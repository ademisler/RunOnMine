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
            "/.well-known/oauth-authorization-server/mcp",
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
        .route("/oauth/consent.css", get(consent_stylesheet))
        .route("/oauth/logo.svg", get(consent_logo))
        .route("/oauth/assets/consent-v2.css", get(consent_stylesheet))
        .route("/oauth/assets/runonmine-logo-v1.svg", get(consent_logo))
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

const CONSENT_CSS: &str = r#"
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#090b0f;color:#f7f8fa}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 50% -15%,#20283a 0,#0d1119 34%,#090b0f 68%);color:#f7f8fa}
button,input{font:inherit}.shell{min-height:100vh;display:grid;place-items:center;padding:40px 20px}.card{width:min(760px,100%);background:rgba(17,20,27,.96);border:1px solid #2a303c;border-radius:24px;box-shadow:0 28px 80px rgba(0,0,0,.48);overflow:hidden}
.brand{display:flex;align-items:center;gap:12px;padding:22px 28px;border-bottom:1px solid #272c36}.brand-logo{display:block;width:36px;height:36px;border-radius:11px;box-shadow:0 8px 24px rgba(52,211,153,.16)}.brand-copy{display:grid;gap:2px}.brand-copy strong{font-size:14px;letter-spacing:.01em}.brand-copy span{font-size:12px;color:#8e98aa}
.content{padding:30px 30px 28px}.eyebrow{display:inline-flex;align-items:center;gap:8px;margin-bottom:12px;color:#aeb7c7;font-size:12px;font-weight:700;letter-spacing:.08em;text-transform:uppercase}.eyebrow::before{content:"";width:7px;height:7px;border-radius:50%;background:#5cdd9a;box-shadow:0 0 0 4px rgba(92,221,154,.1)}h1{margin:0;font-size:clamp(28px,4vw,38px);line-height:1.12;letter-spacing:-.035em}.subtitle{margin:13px 0 26px;color:#a9b1c0;font-size:15px;line-height:1.6}
.client-card{border:1px solid #303744;border-radius:18px;background:#151922;overflow:hidden;margin-bottom:26px}.client-main{display:flex;align-items:center;gap:14px;padding:17px 18px}.client-avatar{display:grid;place-items:center;flex:0 0 auto;width:44px;height:44px;border-radius:13px;background:#232936;color:#dbe3f2;font-weight:800}.client-copy{min-width:0;flex:1}.client-name{font-size:16px;font-weight:750;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.client-meta{margin-top:3px;color:#8f99aa;font-size:12px}.trust-badge{flex:0 0 auto;padding:6px 9px;border-radius:999px;background:#2a2417;color:#f2c66d;border:1px solid #4a3c1f;font-size:11px;font-weight:700}.details{border-top:1px solid #2a303a}.details summary{cursor:pointer;padding:13px 18px;color:#aeb7c7;font-size:13px;font-weight:650;list-style:none}.details summary::-webkit-details-marker{display:none}.details summary::after{content:"+";float:right;color:#737f92;font-size:18px;line-height:14px}.details[open] summary::after{content:"–"}.detail-body{padding:2px 18px 18px}.detail-grid{display:grid;grid-template-columns:160px 1fr;gap:10px 16px;margin:0}.detail-grid dt{color:#7f899a;font-size:12px}.detail-grid dd{margin:0;color:#cfd6e2;font-size:12px;min-width:0;overflow-wrap:anywhere}.detail-grid code{font-family:"SFMono-Regular",Consolas,monospace;font-size:11px;color:#dfe5ee}.origin-list{margin:0;padding-left:18px}.origin-list li+li{margin-top:4px}.security-note{margin:16px 0 0;padding:12px 13px;border-radius:12px;background:#11151c;color:#929cac;font-size:12px;line-height:1.5}
.section-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;margin:0 0 12px}.section-head h2{margin:0;font-size:16px;letter-spacing:-.01em}.section-head span{color:#7f8999;font-size:12px}.scope-grid{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:10px}.scope-item{display:flex;gap:11px;padding:13px 14px;border-radius:14px;background:#12161e;border:1px solid #272d37}.scope-icon{flex:0 0 auto;width:24px;height:24px;border-radius:8px;background:#202634;display:grid;place-items:center;color:#8ca8ff;font-size:12px;font-weight:800}.scope-copy{min-width:0}.scope-copy code{font-family:"SFMono-Regular",Consolas,monospace;color:#e7eaf0;font-size:12px;font-weight:700}.scope-copy p{margin:5px 0 0;color:#8994a6;font-size:11px;line-height:1.45}
.actions{display:flex;gap:10px;margin-top:26px}.button{appearance:none;border:0;border-radius:13px;padding:13px 18px;font-size:14px;font-weight:750;cursor:pointer;transition:transform .12s ease,background .12s ease,opacity .12s ease}.button:active{transform:translateY(1px)}.button:disabled{cursor:wait;opacity:.62}.button-secondary{margin-left:auto;background:#20252f;color:#d6dce6;border:1px solid #303744}.button-secondary:hover{background:#262c37}.button-primary{min-width:145px;background:#f1f4f8;color:#0b0d11}.button-primary:hover{background:#fff}.footnote{margin:15px 0 0;text-align:right;color:#737e90;font-size:11px;line-height:1.5}
@media(max-width:640px){.shell{padding:0}.card{min-height:100vh;border:0;border-radius:0}.content{padding:26px 20px}.brand{padding:18px 20px}.scope-grid{grid-template-columns:1fr}.detail-grid{grid-template-columns:1fr;gap:4px}.detail-grid dd{margin-bottom:8px}.actions{flex-direction:column-reverse}.button,.button-primary{width:100%}.button-secondary{margin-left:0}.footnote{text-align:center}}
"#;

const CONSENT_LOGO: &str = include_str!("../../../packaging/assets/runonmine.svg");

async fn consent_stylesheet() -> Response {
    let mut response = CONSENT_CSS.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    no_store_headers(response.headers_mut());
    response
}

async fn consent_logo() -> Response {
    let mut response = CONSENT_LOGO.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("image/svg+xml; charset=utf-8"),
    );
    no_store_headers(response.headers_mut());
    response
}

fn consent_page(service: &OAuthService, challenge: &ConsentChallenge) -> Response {
    let client_identity = consent_client_identity(challenge);
    let scopes = consent_scope_list(&challenge.scopes);
    let client_name = encode_text(&challenge.claimed_client_name);
    let consent_endpoint = service.consent_endpoint();
    let action = encode_double_quoted_attribute(consent_endpoint.as_str());
    let consent_id_value = challenge.id.to_string();
    let consent_id = encode_double_quoted_attribute(&consent_id_value);
    let csrf = encode_double_quoted_attribute(challenge.csrf.expose_secret());
    let body = format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<title>RunOnMine authorization</title>
<link rel="stylesheet" href="/oauth/assets/consent-v2.css">
</head>
<body>
<div class="shell">
<main class="card">
<header class="brand"><img class="brand-logo" src="/oauth/assets/runonmine-logo-v1.svg" alt="RunOnMine"><div class="brand-copy"><strong>RunOnMine</strong><span>Secure authorization</span></div></header>
<div class="content">
<div class="eyebrow">Connection request</div>
<h1>Allow {client_name} to access this computer?</h1>
<p class="subtitle">Review exactly what this connection can do. Access is limited to the capabilities shown below and remains subject to RunOnMine policy.</p>
{client_identity}
<section aria-labelledby="capabilities-heading">
<div class="section-head"><h2 id="capabilities-heading">Requested capabilities</h2><span>Review before continuing</span></div>
{scopes}
</section>
<form class="actions" method="post" action="{action}">
<input type="hidden" name="consent_id" value="{consent_id}">
<input type="hidden" name="csrf" value="{csrf}">
<button class="button button-secondary" type="submit" name="decision" value="deny">Cancel</button>
<button class="button button-primary" type="submit" name="decision" value="allow">Allow access</button>
</form>
<p class="footnote">Only approve if you started this connection yourself.</p>
</div>
</main>
</div>
</body>
</html>"#
    );
    let mut response = Html(body).into_response();
    no_store_headers(response.headers_mut());
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        consent_content_security_policy(challenge),
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

fn consent_content_security_policy(challenge: &ConsentChallenge) -> HeaderValue {
    let value = format!(
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self' {}; frame-ancestors 'none'; base-uri 'none'",
        challenge.requested_redirect_origin
    );
    HeaderValue::from_str(&value).unwrap_or_else(|_| {
        HeaderValue::from_static(
            "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
    })
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
        r#"<section class="client-card" aria-label="OAuth client details">
<div class="client-main"><div class="client-avatar">AI</div><div class="client-copy"><div class="client-name">{claimed_name}</div><div class="client-meta">OAuth client requesting access through RunOnMine</div></div><span class="trust-badge">Publisher unverified</span></div>
<details class="details"><summary>Connection details</summary><div class="detail-body"><dl class="detail-grid">
<dt>Client fingerprint</dt><dd><code>{fingerprint}</code></dd>
<dt>Registered</dt><dd><time datetime="{registered_at_attribute}">{registered_at_text}</time></dd>
<dt>Current redirect</dt><dd><code>{requested_origin}</code></dd>
<dt>Allowed redirects</dt><dd>{registered_origins}</dd>
</dl><p class="security-note">RunOnMine validates the registered callback and OAuth credentials, but does not independently verify the client's publisher identity.</p></div></details>
</section>"#
    )
}

fn consent_redirect_origins(origins: &[String], requested_origin: &str) -> String {
    let mut html = String::from("<ul class=\"origin-list\">");
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
    let mut html = String::from("<ul class=\"scope-grid\">");
    for scope in scopes.iter() {
        let _ignored = write!(
            html,
            "<li class=\"scope-item\"><span class=\"scope-icon\">✓</span><div class=\"scope-copy\"><code>{}</code><p>{}</p></div></li>",
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
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt as _;
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
        assert!(html.contains("Publisher unverified"));
        assert!(html.contains("does not independently verify the client's publisher identity"));
        assert!(html.contains("OAuth client requesting access through RunOnMine"));
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(html.contains("sha256:abc&amp;def"));
        assert!(html.contains("2023-11-14T22:13:20Z"));
        assert!(html.contains("https://client.example</code> — current request"));
        assert!(html.contains("http://127.0.0.1:8787"));
    }

    #[test]
    fn consent_assets_use_product_logo_without_client_side_submit_code() {
        assert!(CONSENT_CSS.contains(".card"));
        assert!(CONSENT_CSS.contains(".scope-grid"));
        assert!(CONSENT_CSS.contains(".brand-logo"));
        assert!(!CONSENT_CSS.contains("http://"));
        assert!(!CONSENT_CSS.contains("https://"));
        assert!(CONSENT_LOGO.contains("RunOnMine application icon"));
        assert!(CONSENT_LOGO.contains("#34d399"));
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

    #[tokio::test]
    async fn oauth_router_serves_s256_on_mcp_authorization_metadata_alias()
    -> Result<(), Box<dyn std::error::Error>> {
        let service = OAuthService::new(
            crate::OAuthServiceConfig {
                connector_id: "oauth-metadata-test".to_owned(),
                issuer: Url::parse("https://mine.example/")?,
                protected_resource: Url::parse("https://mine.example/mcp")?,
                github_client_id: "github-client".to_owned(),
                github_callback_url: Url::parse("https://mine.example/oauth/github/callback")?,
            },
            Arc::new(crate::SqliteOAuthStore::in_memory()?),
            crate::TokenHasher::new([7_u8; 32])?,
            &secrecy::SecretString::from("registration-access-token-000000000000".to_owned()),
            Arc::new(TestVerifier),
        )?;
        let response = oauth_router(Arc::new(service))
            .oneshot(
                Request::builder()
                    .uri("/.well-known/oauth-authorization-server/mcp")
                    .body(Body::empty())?,
            )
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await?;
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            value["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        assert_eq!(value["issuer"], "https://mine.example/");
        Ok(())
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
        let csp = response.headers()[header::CONTENT_SECURITY_POLICY].to_str()?;
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("style-src 'self'"));
        assert!(csp.contains("img-src 'self'"));
        assert!(csp.contains("form-action 'self' https://client.example"));
        assert!(!csp.contains("script-src"));
        assert!(!csp.contains("'unsafe-inline'"));
        Ok(())
    }

    #[tokio::test]
    async fn native_consent_post_redirects_and_replays_the_same_location()
    -> Result<(), Box<dyn std::error::Error>> {
        use base64::Engine as _;
        use secrecy::ExposeSecret as _;
        use sha2::{Digest as _, Sha256};

        let store = Arc::new(crate::SqliteOAuthStore::in_memory_scoped(
            "oauth-native-form-test",
        )?);
        let service = Arc::new(OAuthService::new(
            crate::OAuthServiceConfig {
                connector_id: "oauth-native-form-test".to_owned(),
                issuer: Url::parse("https://mine.example/")?,
                protected_resource: Url::parse("https://mine.example/mcp")?,
                github_client_id: "github-client".to_owned(),
                github_callback_url: Url::parse("https://mine.example/oauth/github/callback")?,
            },
            store,
            crate::TokenHasher::new([7_u8; 32])?,
            &secrecy::SecretString::from("registration-access-token-000000000000".to_owned()),
            Arc::new(TestVerifier),
        )?);
        let registered = service
            .register_client(
                DynamicClientRequest {
                    redirect_uris: vec![Url::parse("https://client.example/callback")?],
                    client_name: Some("ChatGPT".to_owned()),
                    token_endpoint_auth_method: Some("none".to_owned()),
                    grant_types: Some(vec![
                        "authorization_code".to_owned(),
                        "refresh_token".to_owned(),
                    ]),
                    response_types: Some(vec!["code".to_owned()]),
                    scope: Some("machine:read".to_owned()),
                },
                "registration-access-token-000000000000",
                "native-form-test",
            )
            .map_err(|error| std::io::Error::other(format!("register client: {error:?}")))?;
        let verifier = "a".repeat(64);
        let code_challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let authorization = service
            .begin_authorization(crate::AuthorizationRequest {
                response_type: "code".to_owned(),
                client_id: registered.client_id,
                redirect_uri: Url::parse("https://client.example/callback")?,
                scope: "machine:read".to_owned(),
                state: "client-state-native-form-123456789".to_owned(),
                code_challenge,
                code_challenge_method: "S256".to_owned(),
                resource: Some(Url::parse("https://mine.example/mcp")?),
            })
            .map_err(|error| std::io::Error::other(format!("begin authorization: {error:?}")))?;
        let challenge = service
            .complete_github_callback(GitHubCallback {
                code: "github-code".to_owned(),
                state: authorization.provider_state.expose_secret().to_owned(),
            })
            .await
            .map_err(|error| {
                std::io::Error::other(format!("complete github callback: {error:?}"))
            })?;
        let form = format!(
            "consent_id={}&csrf={}&decision=allow",
            challenge.id,
            challenge.csrf.expose_secret()
        );
        let router = oauth_router(service);
        let mut locations = Vec::new();
        for _ in 0..2 {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/oauth/consent")
                        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                        .body(Body::from(form.clone()))?,
                )
                .await?;
            assert_eq!(response.status(), StatusCode::SEE_OTHER);
            locations.push(
                response
                    .headers()
                    .get(header::LOCATION)
                    .ok_or("missing consent redirect")?
                    .to_str()?
                    .to_owned(),
            );
        }
        assert_eq!(locations[0], locations[1]);
        assert!(locations[0].starts_with("https://client.example/callback?code="));
        assert!(locations[0].contains("state=client-state-native-form-123456789"));
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
        assert!(html.starts_with("<ul class=\"origin-list\">"));
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
