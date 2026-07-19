use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use url::Url;

const MAX_GITHUB_RESPONSE_BYTES: usize = 256 * 1_024;

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

pub struct GitHubApiOwnerVerifier {
    client: reqwest::Client,
    client_id: String,
    client_secret: SecretString,
    owner_login: String,
    owner_id: Option<u64>,
}

impl std::fmt::Debug for GitHubApiOwnerVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GitHubApiOwnerVerifier")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[REDACTED]")
            .field("owner_login", &self.owner_login)
            .field("owner_id", &self.owner_id)
            .finish_non_exhaustive()
    }
}

impl GitHubApiOwnerVerifier {
    pub fn new(
        client_id: String,
        client_secret: SecretString,
        owner_login: &str,
        owner_id: Option<u64>,
    ) -> Result<Self, OAuthError> {
        let owner_login = owner_login.trim().to_owned();
        if client_id.trim().is_empty()
            || client_secret.expose_secret().is_empty()
            || owner_login.is_empty()
            || owner_login.len() > 39
        {
            return Err(OAuthError::configuration());
        }
        let client = reqwest::Client::builder()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("RunOnMine/0.1 OAuth owner verifier")
            .build()
            .map_err(|_| OAuthError::configuration())?;
        Ok(Self {
            client,
            client_id,
            client_secret,
            owner_login,
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
            return Err(OAuthError::access_denied());
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

        let user_response = self
            .client
            .get("https://api.github.com/user")
            .header(reqwest::header::ACCEPT, "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(token.expose_secret())
            .send()
            .await
            .map_err(|_| OAuthError::temporarily_unavailable())?;
        if !user_response.status().is_success() {
            return Err(OAuthError::access_denied());
        }
        let user: GitHubUserResponse = bounded_json(user_response).await?;
        let login_matches = user.login.eq_ignore_ascii_case(&self.owner_login);
        let id_matches = self.owner_id.is_none_or(|owner_id| owner_id == user.id);
        if !login_matches || !id_matches {
            return Err(OAuthError::access_denied());
        }
        Ok(GitHubIdentity {
            id: user.id,
            login: user.login,
        })
    }
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
