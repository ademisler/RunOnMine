//! OAuth 2.1 authorization server building blocks for `RunOnMine`.
//!
//! The crate is deliberately independent from the transport layer used by a
//! Cloudflare tunnel. The public issuer remains HTTPS while the agent itself
//! continues to listen only on loopback.

mod crypto;
mod error;
mod github;
mod http;
mod metadata;
mod model;
mod scope;
mod service;
mod store;

pub use crypto::{HashPurpose, SecretHash, TokenHasher, generate_secret};
pub use error::{OAuthError, OAuthErrorCode, StoreError};
pub use github::{GitHubApiOwnerVerifier, GitHubIdentity, GitHubOwnerVerifier};
pub use http::oauth_router;
pub use metadata::{AuthorizationServerMetadata, ProtectedResourceMetadata};
pub use model::{
    AccessGrant, AuthorizationCodeGrant, AuthorizationRequest, ConsentChallenge, ConsentDecision,
    ConsentResult, DynamicClientRequest, DynamicClientResponse, GitHubAuthorization,
    GitHubCallback, IssuedToken, OAuthSession, PendingAuthorization, PendingConsent,
    RegisteredClient, RegistrationLimits, RegistrationOutcome, RevocationRequest, TokenGrant,
    TokenPairDraft, TokenRequest,
};
pub use scope::{Scope, ScopeSet};
pub use service::{OAuthService, OAuthServiceConfig};
pub use store::{OAuthConnectorCleanup, OAuthStore, SqliteOAuthStore};
