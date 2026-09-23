use serde::Serialize;
use url::Url;

use crate::Scope;

/// RFC 8414 metadata for the embedded authorization server.
#[derive(Clone, Debug, Serialize)]
pub struct AuthorizationServerMetadata {
    pub issuer: Url,
    pub authorization_endpoint: Url,
    pub token_endpoint: Url,
    pub registration_endpoint: Url,
    pub revocation_endpoint: Url,
    pub scopes_supported: Vec<&'static str>,
    pub response_types_supported: Vec<&'static str>,
    pub response_modes_supported: Vec<&'static str>,
    pub grant_types_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub code_challenge_methods_supported: Vec<&'static str>,
    pub authorization_response_iss_parameter_supported: bool,
    pub protected_resources: Vec<Url>,
}

impl AuthorizationServerMetadata {
    #[must_use]
    pub fn new(issuer: &Url, resource: &Url) -> Self {
        Self {
            issuer: issuer.clone(),
            authorization_endpoint: endpoint(issuer, "oauth/authorize"),
            token_endpoint: endpoint(issuer, "oauth/token"),
            registration_endpoint: endpoint(issuer, "oauth/register"),
            revocation_endpoint: endpoint(issuer, "oauth/revoke"),
            scopes_supported: Scope::ALL.into_iter().map(Scope::as_str).collect(),
            response_types_supported: vec!["code"],
            response_modes_supported: vec!["query"],
            grant_types_supported: vec!["authorization_code", "refresh_token"],
            token_endpoint_auth_methods_supported: vec![
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
            code_challenge_methods_supported: vec!["S256"],
            authorization_response_iss_parameter_supported: true,
            protected_resources: vec![resource.clone()],
        }
    }
}

/// RFC 9728 metadata for the `RunOnMine` MCP protected resource.
#[derive(Clone, Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    pub resource: Url,
    pub authorization_servers: Vec<Url>,
    pub scopes_supported: Vec<&'static str>,
    pub bearer_methods_supported: Vec<&'static str>,
}

impl ProtectedResourceMetadata {
    #[must_use]
    pub fn new(issuer: &Url, resource: &Url) -> Self {
        Self {
            resource: resource.clone(),
            authorization_servers: vec![issuer.clone()],
            scopes_supported: Scope::ALL.into_iter().map(Scope::as_str).collect(),
            bearer_methods_supported: vec!["header"],
        }
    }
}

fn endpoint(issuer: &Url, path: &str) -> Url {
    let mut endpoint = issuer.clone();
    let prefix = issuer.path().trim_end_matches('/');
    endpoint.set_path(&format!("{prefix}/{path}"));
    endpoint.set_query(None);
    endpoint.set_fragment(None);
    endpoint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_advertises_only_secure_supported_flows() {
        let issuer = Url::parse("https://mine.example/connector").ok();
        let resource = Url::parse("https://mine.example/connector/mcp").ok();
        assert!(issuer.is_some());
        assert!(resource.is_some());
        let metadata = AuthorizationServerMetadata::new(
            &issuer.unwrap_or_else(|| unreachable!()),
            &resource.unwrap_or_else(|| unreachable!()),
        );
        assert_eq!(
            metadata.authorization_endpoint.as_str(),
            "https://mine.example/connector/oauth/authorize"
        );
        assert_eq!(metadata.code_challenge_methods_supported, ["S256"]);
        assert_eq!(
            metadata.token_endpoint_auth_methods_supported,
            ["client_secret_basic", "client_secret_post", "none"]
        );
    }
}
