//! Request-scoped, non-secret diagnostics for OAuth internals.

use std::future::Future;

use uuid::Uuid;

use crate::StoreError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OAuthDiagnosticCategory {
    Corrupt,
    Database,
    Io,
}

impl OAuthDiagnosticCategory {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Corrupt => "oauth_store_corrupt",
            Self::Database => "oauth_store_database",
            Self::Io => "oauth_store_io",
        }
    }
}

tokio::task_local! {
    static REQUEST_REFERENCE: Uuid;
}

pub(crate) async fn scope_request<T>(future: impl Future<Output = T>) -> T {
    if REQUEST_REFERENCE.try_with(|_| ()).is_ok() {
        future.await
    } else {
        REQUEST_REFERENCE.scope(Uuid::new_v4(), future).await
    }
}

pub(crate) fn current_request_id() -> Uuid {
    REQUEST_REFERENCE
        .try_with(|request_id| *request_id)
        .unwrap_or_else(|_| Uuid::new_v4())
}

pub(crate) fn log_store_error(
    connector_id: &str,
    operation: &'static str,
    error: &StoreError,
) -> Uuid {
    let incident_id = Uuid::new_v4();
    let request_id = current_request_id();
    let category = store_error_category(error);
    tracing::error!(
        incident_id = %incident_id,
        request_id = %request_id,
        connector_id,
        category = category.as_str(),
        operation,
        "RunOnMine OAuth internal operation failed"
    );
    incident_id
}

const fn store_error_category(error: &StoreError) -> OAuthDiagnosticCategory {
    match error {
        StoreError::Corrupt(_) => OAuthDiagnosticCategory::Corrupt,
        StoreError::Database(_) => OAuthDiagnosticCategory::Database,
        StoreError::Io(_) => OAuthDiagnosticCategory::Io,
        StoreError::NotFound | StoreError::InvalidGrant | StoreError::RefreshReuse => {
            OAuthDiagnosticCategory::Corrupt
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_categories_are_static_and_bounded() {
        for category in [
            OAuthDiagnosticCategory::Corrupt,
            OAuthDiagnosticCategory::Database,
            OAuthDiagnosticCategory::Io,
        ] {
            let value = category.as_str();
            assert!(value.len() <= 32);
            assert!(
                value
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
            );
        }
    }

    #[tokio::test]
    async fn nested_request_scope_preserves_the_outer_reference() {
        let outer = Uuid::new_v4();
        let observed = REQUEST_REFERENCE
            .scope(outer, async {
                scope_request(async { current_request_id() }).await
            })
            .await;
        assert_eq!(observed, outer);
    }
}
