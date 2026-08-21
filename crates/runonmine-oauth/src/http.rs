use std::fmt::Write as _;

use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Form, Query, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{Next, from_fn};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use html_escape::{encode_double_quoted_attribute, encode_text};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::diagnostics;
use crate::model::{ConsentChallenge, ConsentSubmission};
use crate::{
    ConsentDecision, DynamicClientRequest, GitHubCallback, OAuthError, OAuthService,
    RevocationRequest, TokenRequest,
};

/// Builds the OAuth endpoints. Mount this router at the public issuer path and
/// keep the underlying listener on loopback.
pub fn oauth_router(service: Arc<OAuthService>) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-protected-resource/mcp",
            get(protected_resource_metadata),
        )
        .route("/oauth/register", post(register_client))
        .route("/oauth/authorize", get(authorize))
        .route("/oauth/github/callback", get(github_callback))
        .route("/oauth/consent", post(consent))
        .route("/oauth/token", post(token))
        .route("/oauth/revoke", post(revoke))
        .layer(from_fn(oauth_request_diagnostics))
        .layer(DefaultBodyLimit::max(16 * 1_024))
        .with_state(service)
}

async fn oauth_request_diagnostics(request: Request, next: Next) -> Response {
    diagnostics::scope_request(next.run(request)).await
}

async fn authorization_server_metadata(
    State(service): State<Arc<OAuthService>>,
) -> impl IntoResponse {
    Json(service.authorization_server_metadata())
}

async fn protected_resource_metadata(
    State(service): State<Arc<OAuthService>>,
) -> impl IntoResponse {
    Json(service.protected_resource_metadata())
}

async fn register_client(
    State(service): State<Arc<OAuthService>>,
    headers: HeaderMap,
    Json(request): Json<DynamicClientRequest>,
) -> Result<Response, OAuthError> {
    let token = registration_bearer_token(&headers)?;
    let source = registration_source(&headers);
    let response = service.register_client(request, token, &source)?;
    let mut response = (StatusCode::CREATED, Json(response)).into_response();
    no_store_headers(response.headers_mut());
    Ok(response)
}

fn registration_bearer_token(headers: &HeaderMap) -> Result<&str, OAuthError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or_else(OAuthError::invalid_client)?
        .to_str()
        .map_err(|_| OAuthError::invalid_client())?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or_else(OAuthError::invalid_client)?;
    if token.is_empty() || token.contains(char::is_whitespace) || token.len() > 1_024 {
        return Err(OAuthError::invalid_client());
    }
    Ok(token)
}

fn registration_source(headers: &HeaderMap) -> String {
    headers
        .get("cf-connecting-ip")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<IpAddr>().ok())
        .map_or_else(
            || "local".to_owned(),
            |address| format!("cloudflare:{address}"),
        )
}

async fn authorize(
    State(service): State<Arc<OAuthService>>,
    Query(request): Query<crate::AuthorizationRequest>,
) -> Result<Response, OAuthError> {
    let authorization = service.begin_authorization(request)?;
    Ok(no_store_redirect(&authorization.redirect))
}

#[derive(Debug, Deserialize)]
struct GitHubCallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

async fn github_callback(
    State(service): State<Arc<OAuthService>>,
    Query(query): Query<GitHubCallbackQuery>,
) -> Result<Response, OAuthError> {
    if query.error.is_some() {
        return Err(OAuthError::access_denied());
    }
    let challenge = service
        .complete_github_callback(GitHubCallback {
            code: query.code.ok_or_else(OAuthError::invalid_request)?,
            state: query.state.ok_or_else(OAuthError::invalid_request)?,
        })
        .await?;
    Ok(consent_page(&service, &challenge))
}

async fn consent(
    State(service): State<Arc<OAuthService>>,
    Form(submission): Form<ConsentSubmission>,
) -> Result<Response, OAuthError> {
    let decision = match submission.decision.as_str() {
        "allow" => ConsentDecision::Allow,
        "deny" => ConsentDecision::Deny,
        _ => return Err(OAuthError::invalid_request()),
    };
    let result = service.submit_consent(submission.consent_id, &submission.csrf, decision)?;
    Ok(no_store_redirect(&result.redirect))
}

#[derive(Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: u64,
    refresh_token: String,
    scope: String,
}

#[derive(Deserialize)]
struct TokenFormRequest {
    grant_type: String,
    #[serde(default)]
    client_id: Option<String>,
    #[serde(default)]
    client_secret: Option<String>,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    redirect_uri: Option<url::Url>,
    #[serde(default)]
    code_verifier: Option<String>,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    scope: Option<String>,
}

async fn token(
    State(service): State<Arc<OAuthService>>,
    headers: HeaderMap,
    Form(request): Form<TokenFormRequest>,
) -> Result<Response, OAuthError> {
    let (client_id, client_secret) =
        token_client_credentials(&headers, request.client_id, request.client_secret)?;
    let request = TokenRequest {
        grant_type: request.grant_type,
        client_id,
        code: request.code,
        redirect_uri: request.redirect_uri,
        code_verifier: request.code_verifier,
        refresh_token: request.refresh_token,
        scope: request.scope,
    };
    let issued = service.issue_token(&request, client_secret.as_deref())?;
    let body = TokenResponse {
        access_token: issued.access_token.expose_secret().to_owned(),
        token_type: issued.token_type,
        expires_in: issued.expires_in,
        refresh_token: issued.refresh_token.expose_secret().to_owned(),
        scope: issued.scope.to_space_delimited(),
    };
    let mut response = Json(body).into_response();
    no_store_headers(response.headers_mut());
    Ok(response)
}

fn token_client_credentials(
    headers: &HeaderMap,
    form_client_id: Option<String>,
    form_client_secret: Option<String>,
) -> Result<(String, Option<String>), OAuthError> {
    let basic = basic_client_credentials(headers)?;
    if let Some((client_id, secret)) = basic {
        if form_client_id
            .as_deref()
            .is_some_and(|value| value != client_id)
            || form_client_secret.is_some()
        {
            return Err(OAuthError::invalid_client());
        }
        Ok((client_id, Some(secret)))
    } else {
        let client_id = form_client_id.ok_or_else(OAuthError::invalid_client)?;
        Ok((client_id, form_client_secret))
    }
}

fn basic_client_credentials(headers: &HeaderMap) -> Result<Option<(String, String)>, OAuthError> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| OAuthError::invalid_client())?;
    let encoded = value
        .strip_prefix("Basic ")
        .ok_or_else(OAuthError::invalid_client)?;
    if encoded.is_empty() || encoded.len() > 4_096 {
        return Err(OAuthError::invalid_client());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|_| OAuthError::invalid_client())?;
    let decoded = String::from_utf8(decoded).map_err(|_| OAuthError::invalid_client())?;
    let (client_id, secret) = decoded
        .split_once(':')
        .ok_or_else(OAuthError::invalid_client)?;
    if client_id.is_empty()
        || client_id.len() > 256
        || secret.len() < 32
        || secret.len() > 1_024
        || client_id.chars().any(char::is_control)
        || secret.contains(char::is_whitespace)
    {
        return Err(OAuthError::invalid_client());
    }
    Ok(Some((client_id.to_owned(), secret.to_owned())))
}

async fn revoke(
    State(service): State<Arc<OAuthService>>,
    Form(request): Form<RevocationRequest>,
) -> Result<Response, OAuthError> {
    service.revoke(&request)?;
    let mut response = StatusCode::OK.into_response();
    no_store_headers(response.headers_mut());
    Ok(response)
}

fn consent_page(service: &OAuthService, challenge: &ConsentChallenge) -> Response {
    let client_identity = consent_client_identity(challenge);
    let scopes = consent_scope_list(&challenge.scopes);
    let consent_endpoint = service.consent_endpoint();
    let action = encode_double_quoted_attribute(consent_endpoint.as_str());
    let consent_id_value = challenge.id.to_string();
    let consent_id = encode_double_quoted_attribute(&consent_id_value);
    let csrf = encode_double_quoted_attribute(challenge.csrf.expose_secret());
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>RunOnMine authorization</title></head><body><main><h1>Allow AI access to this machine?</h1>{client_identity}<h2>Requested capabilities</h2>{scopes}<form method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"consent_id\" value=\"{consent_id}\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><button type=\"submit\" name=\"decision\" value=\"allow\">Allow</button><button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></main></body></html>"
    );
    let mut response = Html(body).into_response();
    no_store_headers(response.headers_mut());
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        ),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn consent_client_identity(challenge: &ConsentChallenge) -> String {
    let claimed_name = encode_text(&challenge.claimed_client_name);
    let fingerprint = encode_text(&challenge.client_id_fingerprint);
    let registered_at = challenge
        .registered_at
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let registered_at_text = encode_text(&registered_at);
    let registered_at_attribute = encode_double_quoted_attribute(&registered_at);
    let requested_origin = encode_text(&challenge.requested_redirect_origin);
    let registered_origins = consent_redirect_origins(
        &challenge.registered_redirect_origins,
        &challenge.requested_redirect_origin,
    );
    format!(
        "<aside role=\"alert\"><strong>Unverified OAuth client</strong><p>The client supplied the name below. RunOnMine has not verified its name, publisher, or identity.</p></aside><dl><dt>Claimed name (unverified)</dt><dd>{claimed_name}</dd><dt>Client ID fingerprint</dt><dd><code>{fingerprint}</code></dd><dt>Registered</dt><dd><time datetime=\"{registered_at_attribute}\">{registered_at_text}</time></dd><dt>Redirect origin for this request</dt><dd><code>{requested_origin}</code></dd><dt>All registered redirect origins</dt><dd>{registered_origins}</dd></dl>"
    )
}

fn consent_redirect_origins(origins: &[String], requested_origin: &str) -> String {
    let mut html = String::from("<ul>");
    for origin in origins {
        let is_requested = origin == requested_origin;
        let origin = encode_text(origin);
        if is_requested {
            let _ignored = write!(html, "<li><code>{origin}</code> — current request</li>");
        } else {
            let _ignored = write!(html, "<li><code>{origin}</code></li>");
        }
    }
    html.push_str("</ul>");
    html
}

fn consent_scope_list(scopes: &crate::ScopeSet) -> String {
    let mut html = String::from("<ul>");
    for scope in scopes.iter() {
        let _ignored = write!(
            html,
            "<li><code>{}</code> — {}</li>",
            encode_text(scope.as_str()),
            encode_text(scope.consent_text())
        );
    }
    html.push_str("</ul>");
    html
}

fn no_store_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

fn no_store_redirect(target: &url::Url) -> Response {
    let mut response = Redirect::to(target.as_str()).into_response();
    no_store_headers(response.headers_mut());
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn consent_identity_warns_and_renders_stable_client_details_safely() {
        let challenge = ConsentChallenge {
            id: uuid::Uuid::nil(),
            csrf: secrecy::SecretString::from("csrf-token".to_owned()),
            claimed_client_name: "RunOnMine Official <script>alert(1)</script>".to_owned(),
            client_id_fingerprint: "sha256:abc&def".to_owned(),
            registered_at: chrono::DateTime::from_timestamp(1_700_000_000, 0)
                .unwrap_or_else(chrono::Utc::now),
            requested_redirect_origin: "https://client.example".to_owned(),
            registered_redirect_origins: vec![
                "http://127.0.0.1:8787".to_owned(),
                "https://client.example".to_owned(),
            ],
            scopes: crate::ScopeSet::machine_read(),
        };
        let html = consent_client_identity(&challenge);
        assert!(html.contains("Unverified OAuth client"));
        assert!(html.contains("has not verified its name, publisher, or identity"));
        assert!(html.contains("Claimed name (unverified)"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("sha256:abc&amp;def"));
        assert!(html.contains("2023-11-14T22:13:20Z"));
        assert!(html.contains("https://client.example</code> — current request"));
        assert!(html.contains("http://127.0.0.1:8787"));
    }

    #[test]
    fn consent_scope_list_distinguishes_shell_from_platform_automation() {
        let scopes = crate::ScopeSet::parse("shell:exec platform:exec").unwrap_or_default();
        let html = consent_scope_list(&scopes);
        assert!(html.contains("shell:exec"));
        assert!(html.contains("Run shell commands as the signed-in user"));
        assert!(html.contains("platform:exec"));
        assert!(html.contains("AppleScript, PowerShell, or D-Bus"));
    }

    #[test]
    fn registration_requires_exact_bearer_syntax() -> Result<(), Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer initial-token"),
        );
        assert_eq!(registration_bearer_token(&headers)?, "initial-token");
        for value in [
            "bearer token",
            "Bearer ",
            "Bearer two tokens",
            "Basic token",
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value)?);
            assert!(registration_bearer_token(&headers).is_err());
        }
        assert!(registration_bearer_token(&HeaderMap::new()).is_err());
        Ok(())
    }

    #[test]
    fn token_client_credentials_support_basic_and_post_without_mixing_methods()
    -> Result<(), Box<dyn std::error::Error>> {
        let client_id = "romc_chatgpt";
        let secret = "confidential-client-secret-0123456789abcdef";
        let encoded =
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {encoded}"))?,
        );
        assert_eq!(
            token_client_credentials(&headers, None, None)?,
            (client_id.to_owned(), Some(secret.to_owned()))
        );
        assert_eq!(
            token_client_credentials(
                &HeaderMap::new(),
                Some(client_id.to_owned()),
                Some(secret.to_owned())
            )?,
            (client_id.to_owned(), Some(secret.to_owned()))
        );
        assert!(
            token_client_credentials(&headers, Some("different-client".to_owned()), None).is_err()
        );
        assert!(
            token_client_credentials(
                &headers,
                Some(client_id.to_owned()),
                Some(secret.to_owned())
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn token_client_credentials_reject_non_basic_authorization_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer not-valid-for-token-client-auth"),
        );
        assert!(token_client_credentials(&headers, None, None).is_err());
    }

    #[test]
    fn oauth_router_and_response_helpers_apply_security_headers()
    -> Result<(), Box<dyn std::error::Error>> {
        let redirect = Url::parse("https://client.example/callback?code=value")?;
        let response = no_store_redirect(&redirect);
        assert!(response.status().is_redirection());
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(response.headers()[header::LOCATION], redirect.as_str());

        let mut headers = HeaderMap::new();
        no_store_headers(&mut headers);
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::PRAGMA], "no-cache");

        let response = TokenResponse {
            access_token: "access".to_owned(),
            token_type: "Bearer",
            expires_in: 900,
            refresh_token: "refresh".to_owned(),
            scope: "machine:read".to_owned(),
        };
        let value = serde_json::to_value(response)?;
        assert_eq!(value["token_type"], "Bearer");
        assert_eq!(value["expires_in"], 900);
        Ok(())
    }

    #[test]
    fn consent_page_escapes_every_dynamic_field_and_sets_browser_guards()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = Arc::new(crate::SqliteOAuthStore::in_memory()?);
        let verifier = Arc::new(TestVerifier);
        let service = OAuthService::new(
            crate::OAuthServiceConfig {
                connector_id: "oauth-test".to_owned(),
                issuer: Url::parse("https://mine.example/")?,
                protected_resource: Url::parse("https://mine.example/mcp")?,
                github_client_id: "github-client".to_owned(),
                github_callback_url: Url::parse("https://mine.example/oauth/github/callback")?,
            },
            store,
            crate::TokenHasher::new([7_u8; 32])?,
            &secrecy::SecretString::from("registration-access-token-000000000000".to_owned()),
            verifier,
        )?;
        let challenge = ConsentChallenge {
            id: uuid::Uuid::nil(),
            csrf: secrecy::SecretString::from("csrf<&\"".to_owned()),
            claimed_client_name: "<client>".to_owned(),
            client_id_fingerprint: "finger&print".to_owned(),
            registered_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).ok_or("timestamp")?,
            requested_redirect_origin: "https://client.example".to_owned(),
            registered_redirect_origins: vec!["https://client.example".to_owned()],
            scopes: crate::ScopeSet::machine_read(),
        };
        let response = consent_page(&service, &challenge);
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()[header::PRAGMA], "no-cache");
        assert_eq!(response.headers()[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            response.headers()[header::X_CONTENT_TYPE_OPTIONS],
            "nosniff"
        );
        assert!(
            response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()?
                .contains("frame-ancestors 'none'")
        );
        Ok(())
    }

    #[derive(Debug)]
    struct TestVerifier;

    #[async_trait::async_trait]
    impl crate::GitHubOwnerVerifier for TestVerifier {
        async fn verify_code(
            &self,
            _code: secrecy::SecretString,
            _callback_url: &Url,
        ) -> Result<crate::GitHubIdentity, OAuthError> {
            Ok(crate::GitHubIdentity {
                id: 42,
                login: "owner".to_owned(),
            })
        }
    }

    #[test]
    fn callback_query_and_consent_origin_lists_cover_optional_and_current_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let query: GitHubCallbackQuery = serde_json::from_value(serde_json::json!({
            "code": "code", "state": "state", "error": null
        }))?;
        assert_eq!(query.code.as_deref(), Some("code"));
        assert_eq!(query.state.as_deref(), Some("state"));
        assert!(query.error.is_none());
        let denied: GitHubCallbackQuery =
            serde_json::from_value(serde_json::json!({"error":"access_denied"}))?;
        assert_eq!(denied.error.as_deref(), Some("access_denied"));

        let html = consent_redirect_origins(
            &[
                "https://one.example".to_owned(),
                "https://two.example/?x=<tag>".to_owned(),
            ],
            "https://one.example",
        );
        assert!(html.contains("current request"));
        assert!(html.contains("&lt;tag&gt;"));
        assert!(html.starts_with("<ul>"));
        assert!(html.ends_with("</ul>"));
        Ok(())
    }

    #[test]
    fn registration_source_uses_valid_cloudflare_address_only() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.8"));
        assert_eq!(registration_source(&headers), "cloudflare:203.0.113.8");
        headers.insert("cf-connecting-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(registration_source(&headers), "local");
        assert_eq!(registration_source(&HeaderMap::new()), "local");
    }
}
