use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

const MAX_GITHUB_RESPONSE_BYTES: usize = 256 * 1_024;
const GITHUB_USER_MAX_ATTEMPTS: usize = 3;
const GITHUB_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(150);
const GITHUB_USER_AGENT: &str = concat!(
    "RunOnMine/",
    env!("CARGO_PKG_VERSION"),
    " OAuth owner verifier"
);

use crate::OAuthError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GitHubIdentity {
    pub id: u64,
    pub login: String,
}

#[async_trait]
pub trait GitHubOwnerVerifier: Send + Sync {
    /// Exchanges a one-time GitHub code and verifies the current GitHub user.
    /// Implementations must not persist or log the code or GitHub token.
    async fn verify_code(
        &self,
        code: SecretString,
        callback_url: &Url,
    ) -> Result<GitHubIdentity, OAuthError>;
}

#[derive(Debug, thiserror::Error)]
#[error("GitHub identity observation failed")]
pub struct GitHubIdentityObservationError;

impl GitHubIdentityObservationError {
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl Default for GitHubIdentityObservationError {
    fn default() -> Self {
        Self::new()
    }
}

pub trait GitHubIdentityObserver: Send + Sync {
    /// Reconciles non-authoritative identity metadata after the immutable ID was
    /// verified. Implementations must not widen or replace the numeric authority.
    fn observe(&self, identity: &GitHubIdentity) -> Result<(), GitHubIdentityObservationError>;
}

pub struct ObservedGitHubOwnerVerifier {
    verifier: std::sync::Arc<dyn GitHubOwnerVerifier>,
    observer: std::sync::Arc<dyn GitHubIdentityObserver>,
}

impl std::fmt::Debug for ObservedGitHubOwnerVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObservedGitHubOwnerVerifier")
            .field("verifier", &"dyn GitHubOwnerVerifier")
            .field("observer", &"dyn GitHubIdentityObserver")
            .finish()
    }
}

impl ObservedGitHubOwnerVerifier {
    #[must_use]
    pub fn new(
        verifier: std::sync::Arc<dyn GitHubOwnerVerifier>,
        observer: std::sync::Arc<dyn GitHubIdentityObserver>,
    ) -> Self {
        Self { verifier, observer }
    }
}

#[async_trait]
impl GitHubOwnerVerifier for ObservedGitHubOwnerVerifier {
    async fn verify_code(
        &self,
        code: SecretString,
        callback_url: &Url,
    ) -> Result<GitHubIdentity, OAuthError> {
        let identity = self.verifier.verify_code(code, callback_url).await?;
        self.observer
            .observe(&identity)
            .map_err(|_| OAuthError::server())?;
        Ok(identity)
    }
}

pub struct GitHubApiOwnerVerifier {
    client: reqwest::Client,
    client_id: String,
    client_secret: SecretString,
    owner_id: u64,
}

impl std::fmt::Debug for GitHubApiOwnerVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubApiOwnerVerifier")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("owner_id", &self.owner_id)
            .finish_non_exhaustive()
    }
}

impl GitHubApiOwnerVerifier {
    pub fn new(
        client_id: String,
        client_secret: SecretString,
        owner_id: u64,
    ) -> Result<Self, OAuthError> {
        if client_id.trim().is_empty() || client_secret.expose_secret().is_empty() || owner_id == 0
        {
            return Err(OAuthError::configuration());
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent(GITHUB_USER_AGENT)
            .build()
            .map_err(|_| OAuthError::configuration())?;
        Ok(Self {
            client,
            client_id,
            client_secret,
            owner_id,
        })
    }
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUserResponse {
    id: u64,
    login: String,
}

#[async_trait]
impl GitHubOwnerVerifier for GitHubApiOwnerVerifier {
    async fn verify_code(
        &self,
        code: SecretString,
        callback_url: &Url,
    ) -> Result<GitHubIdentity, OAuthError> {
        let token_response = self
            .client
            .post("https://github.com/login/oauth/access_token")
            .header(reqwest::header::ACCEPT, "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.expose_secret()),
                ("code", code.expose_secret()),
                ("redirect_uri", callback_url.as_str()),
            ])
            .send()
            .await
            .map_err(|_| OAuthError::temporarily_unavailable())?;
        if !token_response.status().is_success() {
            return Err(if is_retryable_github_status(token_response.status()) {
                OAuthError::temporarily_unavailable()
            } else {
                OAuthError::access_denied()
            });
        }
        let token_payload: GitHubTokenResponse = bounded_json(token_response).await?;
        if token_payload.error.is_some() {
            return Err(OAuthError::access_denied());
        }
        let token = token_payload
            .access_token
            .filter(|value| !value.is_empty())
            .map(SecretString::from)
            .ok_or_else(OAuthError::access_denied)?;

        let user_response = send_github_user_request(&self.client, &token).await?;
        let user: GitHubUserResponse = bounded_json(user_response).await?;
        verify_owner_identity(self.owner_id, user)
    }
}

async fn send_github_user_request(
    client: &reqwest::Client,
    token: &SecretString,
) -> Result<reqwest::Response, OAuthError> {
    for attempt in 0..GITHUB_USER_MAX_ATTEMPTS {
        let response = client
            .get("https://api.github.com/user")
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(token.expose_secret())
            .send()
            .await;
        match response {
            Ok(response) if response.status().is_success() => return Ok(response),
            Ok(response) if is_retryable_github_status(response.status()) => {
                if attempt + 1 == GITHUB_USER_MAX_ATTEMPTS {
                    return Err(OAuthError::temporarily_unavailable());
                }
            }
            Ok(_) => return Err(OAuthError::access_denied()),
            Err(_) if attempt + 1 == GITHUB_USER_MAX_ATTEMPTS => {
                return Err(OAuthError::temporarily_unavailable());
            }
            Err(_) => {}
        }
        tokio::time::sleep(GITHUB_RETRY_DELAY).await;
    }
    Err(OAuthError::temporarily_unavailable())
}

fn is_retryable_github_status(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error()
}

fn verify_owner_identity(
    expected_owner_id: u64,
    user: GitHubUserResponse,
) -> Result<GitHubIdentity, OAuthError> {
    if expected_owner_id == 0
        || user.id != expected_owner_id
        || user.login.is_empty()
        || user.login.len() > 39
        || user.login.starts_with('-')
        || user.login.ends_with('-')
        || !user
            .login
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err(OAuthError::access_denied());
    }
    Ok(GitHubIdentity {
        id: user.id,
        login: user.login,
    })
}

async fn bounded_json<T: serde::de::DeserializeOwned>(
    response: reqwest::Response,
) -> Result<T, OAuthError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_GITHUB_RESPONSE_BYTES as u64)
    {
        return Err(OAuthError::access_denied());
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| OAuthError::temporarily_unavailable())?;
    if bytes.len() > MAX_GITHUB_RESPONSE_BYTES {
        return Err(OAuthError::access_denied());
    }
    serde_json::from_slice(&bytes).map_err(|_| OAuthError::access_denied())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_numeric_id_authorizes_a_safe_login_rename() -> Result<(), OAuthError> {
        let identity = verify_owner_identity(
            42,
            GitHubUserResponse {
                id: 42,
                login: "renamed-owner".to_owned(),
            },
        )?;
        assert_eq!(identity.id, 42);
        assert_eq!(identity.login, "renamed-owner");
        Ok(())
    }

    #[test]
    fn matching_login_cannot_override_a_different_numeric_id() {
        assert!(
            verify_owner_identity(
                42,
                GitHubUserResponse {
                    id: 7,
                    login: "owner".to_owned(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn unsafe_provider_login_is_rejected_even_for_the_expected_id() {
        assert!(
            verify_owner_identity(
                42,
                GitHubUserResponse {
                    id: 42,
                    login: "owner\nspoof".to_owned(),
                },
            )
            .is_err()
        );
    }

    #[derive(Debug)]
    struct StaticVerifier(GitHubIdentity);

    #[async_trait]
    impl GitHubOwnerVerifier for StaticVerifier {
        async fn verify_code(
            &self,
            _code: SecretString,
            _callback_url: &Url,
        ) -> Result<GitHubIdentity, OAuthError> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug)]
    struct RecordingObserver {
        observed: std::sync::Mutex<Vec<GitHubIdentity>>,
        fail: bool,
    }

    impl GitHubIdentityObserver for RecordingObserver {
        fn observe(&self, identity: &GitHubIdentity) -> Result<(), GitHubIdentityObservationError> {
            self.observed
                .lock()
                .map_err(|_| GitHubIdentityObservationError::new())?
                .push(identity.clone());
            if self.fail {
                return Err(GitHubIdentityObservationError::new());
            }
            Ok(())
        }
    }

    #[tokio::test]
    async fn observed_verifier_reconciles_only_after_identity_verification()
    -> Result<(), OAuthError> {
        let observer = std::sync::Arc::new(RecordingObserver {
            observed: std::sync::Mutex::new(Vec::new()),
            fail: false,
        });
        let verifier = ObservedGitHubOwnerVerifier::new(
            std::sync::Arc::new(StaticVerifier(GitHubIdentity {
                id: 42,
                login: "renamed-owner".to_owned(),
            })),
            observer.clone(),
        );
        let identity = verifier
            .verify_code(
                SecretString::from("one-time-code".to_owned()),
                &Url::parse("https://mine.example/oauth/github/callback")
                    .map_err(|_| OAuthError::configuration())?,
            )
            .await?;
        assert_eq!(identity.id, 42);
        let identities = observer.observed.lock().map_err(|_| OAuthError::server())?;
        assert_eq!(identities.as_slice(), &[identity]);
        Ok(())
    }

    #[tokio::test]
    async fn observer_failure_fails_closed_after_numeric_identity_verification()
    -> Result<(), OAuthError> {
        let verifier = ObservedGitHubOwnerVerifier::new(
            std::sync::Arc::new(StaticVerifier(GitHubIdentity {
                id: 42,
                login: "renamed-owner".to_owned(),
            })),
            std::sync::Arc::new(RecordingObserver {
                observed: std::sync::Mutex::new(Vec::new()),
                fail: true,
            }),
        );
        let result = verifier
            .verify_code(
                SecretString::from("one-time-code".to_owned()),
                &Url::parse("https://mine.example/oauth/github/callback")
                    .map_err(|_| OAuthError::configuration())?,
            )
            .await;
        let Err(error) = result else {
            return Err(OAuthError::server());
        };
        assert_eq!(error.code, crate::OAuthErrorCode::ServerError);
        Ok(())
    }

    #[test]
    fn github_retry_statuses_are_bounded_to_rate_limits_and_server_errors() {
        assert!(is_retryable_github_status(
            reqwest::StatusCode::TOO_MANY_REQUESTS
        ));
        assert!(is_retryable_github_status(reqwest::StatusCode::BAD_GATEWAY));
        assert!(is_retryable_github_status(
            reqwest::StatusCode::SERVICE_UNAVAILABLE
        ));
        assert!(!is_retryable_github_status(
            reqwest::StatusCode::UNAUTHORIZED
        ));
        assert!(!is_retryable_github_status(reqwest::StatusCode::FORBIDDEN));
        assert!(!is_retryable_github_status(reqwest::StatusCode::NOT_FOUND));
    }

    #[test]
    fn github_user_agent_tracks_the_package_version() {
        assert_eq!(
            GITHUB_USER_AGENT,
            format!(
                "RunOnMine/{} OAuth owner verifier",
                env!("CARGO_PKG_VERSION")
            )
        );
        assert!(!GITHUB_USER_AGENT.contains("RunOnMine/0.1 "));
    }
}
