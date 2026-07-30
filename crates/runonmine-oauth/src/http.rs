use std::net::IpAddr;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use html_escape::encode_text;
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

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
        .layer(DefaultBodyLimit::max(16 * 1_024))
        .with_state(service)
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

async fn token(
    State(service): State<Arc<OAuthService>>,
    Form(request): Form<TokenRequest>,
) -> Result<Response, OAuthError> {
    let issued = service.issue_token(&request)?;
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
    let client_name = encode_text(&challenge.client_name);
    let scope_text = challenge.scopes.to_space_delimited();
    let scopes = encode_text(&scope_text);
    let consent_endpoint = service.consent_endpoint();
    let action = encode_text(consent_endpoint.as_str());
    let body = format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>RunOnMine authorization</title></head><body><main><h1>Allow AI access to this machine?</h1><p><strong>{client_name}</strong> requests these capabilities:</p><p>{scopes}</p><form method=\"post\" action=\"{action}\"><input type=\"hidden\" name=\"consent_id\" value=\"{}\"><input type=\"hidden\" name=\"csrf\" value=\"{}\"><button type=\"submit\" name=\"decision\" value=\"allow\">Allow</button><button type=\"submit\" name=\"decision\" value=\"deny\">Deny</button></form></main></body></html>",
        challenge.id,
        challenge.csrf.expose_secret(),
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
    fn registration_source_uses_valid_cloudflare_address_only() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-connecting-ip", HeaderValue::from_static("203.0.113.8"));
        assert_eq!(registration_source(&headers), "cloudflare:203.0.113.8");
        headers.insert("cf-connecting-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(registration_source(&headers), "local");
        assert_eq!(registration_source(&HeaderMap::new()), "local");
    }
}
