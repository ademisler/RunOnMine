use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// OAuth protocol error codes returned to untrusted clients.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OAuthErrorCode {
    InvalidRequest,
    InvalidClient,
    InvalidGrant,
    InvalidScope,
    UnauthorizedClient,
    UnsupportedGrantType,
    AccessDenied,
    TemporarilyUnavailable,
    ServerError,
}

impl OAuthErrorCode {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::InvalidClient => "invalid_client",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidScope => "invalid_scope",
            Self::UnauthorizedClient => "unauthorized_client",
            Self::UnsupportedGrantType => "unsupported_grant_type",
            Self::AccessDenied => "access_denied",
            Self::TemporarilyUnavailable => "temporarily_unavailable",
            Self::ServerError => "server_error",
        }
    }
}

/// A deliberately low-detail public error. Internal causes are never exposed.
#[derive(Clone, Debug, thiserror::Error)]
#[error("OAuth request failed: {code:?}")]
pub struct OAuthError {
    pub code: OAuthErrorCode,
    description: &'static str,
}

impl OAuthError {
    pub(crate) const fn new(code: OAuthErrorCode, description: &'static str) -> Self {
        Self { code, description }
    }

    pub(crate) const fn invalid_request() -> Self {
        Self::new(OAuthErrorCode::InvalidRequest, "The request is invalid.")
    }

    pub(crate) const fn invalid_client() -> Self {
        Self::new(
            OAuthErrorCode::InvalidClient,
            "Client authentication failed.",
        )
    }

    pub(crate) const fn invalid_grant() -> Self {
        Self::new(
            OAuthErrorCode::InvalidGrant,
            "The grant is invalid or expired.",
        )
    }

    pub(crate) const fn invalid_scope() -> Self {
        Self::new(
            OAuthErrorCode::InvalidScope,
            "The requested scope is invalid.",
        )
    }

    pub(crate) const fn unsupported_grant() -> Self {
        Self::new(
            OAuthErrorCode::UnsupportedGrantType,
            "The grant type is not supported.",
        )
    }

    pub(crate) const fn access_denied() -> Self {
        Self::new(OAuthErrorCode::AccessDenied, "Authorization was denied.")
    }

    pub(crate) const fn temporarily_unavailable() -> Self {
        Self::new(
            OAuthErrorCode::TemporarilyUnavailable,
            "The authorization service is temporarily unavailable.",
        )
    }

    pub(crate) const fn configuration() -> Self {
        Self::new(
            OAuthErrorCode::ServerError,
            "The authorization service is not configured.",
        )
    }

    pub(crate) const fn server() -> Self {
        Self::new(
            OAuthErrorCode::ServerError,
            "The authorization service failed.",
        )
    }

    #[must_use]
    pub const fn description(&self) -> &'static str {
        self.description
    }

    #[must_use]
    pub const fn status(&self) -> StatusCode {
        match self.code {
            OAuthErrorCode::InvalidClient => StatusCode::UNAUTHORIZED,
            OAuthErrorCode::ServerError | OAuthErrorCode::TemporarilyUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: &'static str,
    error_description: &'static str,
}

impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = ErrorBody {
            error: self.code.as_str(),
            error_description: self.description,
        };
        let mut response = (self.status(), Json(body)).into_response();
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// Persistence failures are kept separate so they can be logged locally
/// without accidentally becoming OAuth responses.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("OAuth state was not found")]
    NotFound,
    #[error("OAuth state is invalid or expired")]
    InvalidGrant,
    #[error("refresh token reuse was detected")]
    RefreshReuse,
    #[error("persisted OAuth state is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("OAuth persistence failed")]
    Database(#[source] rusqlite::Error),
    #[error("OAuth persistence I/O failed")]
    Io(#[source] std::io::Error),
}

impl From<rusqlite::Error> for StoreError {
    fn from(value: rusqlite::Error) -> Self {
        Self::Database(value)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_public_error_code_has_stable_wire_name_and_status() {
        let cases = [
            (
                OAuthErrorCode::InvalidRequest,
                "invalid_request",
                StatusCode::BAD_REQUEST,
            ),
            (
                OAuthErrorCode::InvalidClient,
                "invalid_client",
                StatusCode::UNAUTHORIZED,
            ),
            (
                OAuthErrorCode::InvalidGrant,
                "invalid_grant",
                StatusCode::BAD_REQUEST,
            ),
            (
                OAuthErrorCode::InvalidScope,
                "invalid_scope",
                StatusCode::BAD_REQUEST,
            ),
            (
                OAuthErrorCode::UnauthorizedClient,
                "unauthorized_client",
                StatusCode::BAD_REQUEST,
            ),
            (
                OAuthErrorCode::UnsupportedGrantType,
                "unsupported_grant_type",
                StatusCode::BAD_REQUEST,
            ),
            (
                OAuthErrorCode::AccessDenied,
                "access_denied",
                StatusCode::BAD_REQUEST,
            ),
            (
                OAuthErrorCode::TemporarilyUnavailable,
                "temporarily_unavailable",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
            (
                OAuthErrorCode::ServerError,
                "server_error",
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ];
        for (code, wire, status) in cases {
            let error = OAuthError::new(code, "description");
            assert_eq!(code.as_str(), wire);
            assert_eq!(error.description(), "description");
            assert_eq!(error.status(), status);
            assert!(format!("{error}").contains(&format!("{code:?}")));
            let response = error.into_response();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        }
    }

    #[test]
    fn constructor_descriptions_are_deliberately_low_detail() {
        let cases = [
            OAuthError::invalid_request(),
            OAuthError::invalid_client(),
            OAuthError::invalid_grant(),
            OAuthError::invalid_scope(),
            OAuthError::unsupported_grant(),
            OAuthError::access_denied(),
            OAuthError::temporarily_unavailable(),
            OAuthError::configuration(),
            OAuthError::server(),
        ];
        for error in cases {
            assert!(!error.description().is_empty());
            assert!(!error.description().contains("token"));
            assert!(!error.description().contains("database"));
        }
    }

    #[test]
    fn persistence_errors_preserve_local_sources_without_public_detail() {
        let sqlite = rusqlite::Error::InvalidQuery;
        let database = StoreError::from(sqlite);
        assert!(matches!(database, StoreError::Database(_)));
        assert_eq!(database.to_string(), "OAuth persistence failed");

        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "private path");
        let stored = StoreError::from(io);
        assert!(matches!(stored, StoreError::Io(_)));
        assert_eq!(stored.to_string(), "OAuth persistence I/O failed");
        assert_eq!(
            StoreError::NotFound.to_string(),
            "OAuth state was not found"
        );
        assert_eq!(
            StoreError::InvalidGrant.to_string(),
            "OAuth state is invalid or expired"
        );
        assert_eq!(
            StoreError::RefreshReuse.to_string(),
            "refresh token reuse was detected"
        );
        assert!(
            StoreError::Corrupt("fixture")
                .to_string()
                .contains("fixture")
        );
    }
}
