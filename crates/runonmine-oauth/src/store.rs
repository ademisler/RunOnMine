use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use sha2::{Digest as _, Sha256};
use url::Url;
use uuid::Uuid;

use crate::crypto::verify_pkce;
use crate::model::{
    AccessGrant, AuthorizationClaim, AuthorizationCodeGrant, OAuthSession, PendingAuthorization,
    PendingConsent, RegisteredClient, RegistrationLimits, RegistrationOutcome, TokenGrant,
    TokenPairDraft,
};
use crate::{ScopeSet, SecretHash, StoreError};

const OAUTH_SCHEMA_VERSION: i64 = 6;
const TEST_CONNECTOR_ID: &str = "test-connector";
type DbJob = Box<dyn FnOnce(&mut Connection) + Send + 'static>;

enum DbMessage {
    Run(DbJob),
    Shutdown,
}

struct SqliteWorker {
    sender: Option<mpsc::Sender<DbMessage>>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for SqliteWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteWorker")
            .finish_non_exhaustive()
    }
}

impl SqliteWorker {
    fn start(mut connection: Connection) -> Result<Self, StoreError> {
        let (sender, receiver) = mpsc::channel::<DbMessage>();
        let thread = std::thread::Builder::new()
            .name("runonmine-oauth-db".to_owned())
            .spawn(move || {
                while let Ok(message) = receiver.recv() {
                    match message {
                        DbMessage::Run(job) => job(&mut connection),
                        DbMessage::Shutdown => break,
                    }
                }
            })?;
        Ok(Self {
            sender: Some(sender),
            thread: Mutex::new(Some(thread)),
        })
    }

    fn call<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        let (reply, receive) = mpsc::sync_channel(1);
        self.sender
            .as_ref()
            .ok_or_else(|| {
                StoreError::Io(std::io::Error::other(
                    "OAuth database worker is unavailable",
                ))
            })?
            .send(DbMessage::Run(Box::new(move |connection| {
                let _ignored = reply.send(operation(connection));
            })))
            .map_err(|_| {
                StoreError::Io(std::io::Error::other(
                    "OAuth database worker is unavailable",
                ))
            })?;
        receive.recv().map_err(|_| {
            StoreError::Io(std::io::Error::other(
                "OAuth database worker stopped unexpectedly",
            ))
        })?
    }
}

impl Drop for SqliteWorker {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ignored = sender.send(DbMessage::Shutdown);
        }
        if let Ok(mut thread) = self.thread.lock()
            && let Some(thread) = thread.take()
        {
            let _ignored = thread.join();
        }
    }
}

pub trait OAuthStore: Send + Sync {
    fn register_client_limited(
        &self,
        client: &RegisteredClient,
        limits: &RegistrationLimits,
    ) -> Result<RegistrationOutcome, StoreError>;
    fn client(&self, client_id: &str) -> Result<Option<RegisteredClient>, StoreError>;
    fn touch_client(
        &self,
        client_id: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError>;
    fn put_authorization(&self, pending: &PendingAuthorization) -> Result<(), StoreError>;
    fn claim_authorization(
        &self,
        state_hash: &SecretHash,
        provider_code_hash: &SecretHash,
        claim_id: Uuid,
        now: DateTime<Utc>,
        claim_expires_at: DateTime<Utc>,
    ) -> Result<AuthorizationClaim, StoreError>;
    fn release_authorization_claim(
        &self,
        claim: &AuthorizationClaim,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    fn consume_authorization_claim(
        &self,
        claim: &AuthorizationClaim,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    fn complete_authorization_claim(
        &self,
        claim: &AuthorizationClaim,
        consent: &PendingConsent,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError>;
    fn put_consent(&self, pending: &PendingConsent) -> Result<(), StoreError>;
    fn take_consent(
        &self,
        id: Uuid,
        csrf_hash: &SecretHash,
        now: DateTime<Utc>,
    ) -> Result<PendingConsent, StoreError>;
    fn put_authorization_code(&self, code: &AuthorizationCodeGrant) -> Result<(), StoreError>;
    fn exchange_authorization_code(
        &self,
        code_hash: &SecretHash,
        client_id: &str,
        redirect_uri: &Url,
        verifier: &str,
        tokens: &TokenPairDraft,
        now: DateTime<Utc>,
    ) -> Result<TokenGrant, StoreError>;
    fn rotate_refresh_token(
        &self,
        refresh_hash: &SecretHash,
        client_id: &str,
        requested_scopes: Option<&ScopeSet>,
        tokens: &TokenPairDraft,
        now: DateTime<Utc>,
    ) -> Result<TokenGrant, StoreError>;
    fn revoke_token(&self, token_hash: &SecretHash) -> Result<(), StoreError>;
    fn access_grant(
        &self,
        token_hash: &SecretHash,
        now: DateTime<Utc>,
    ) -> Result<Option<AccessGrant>, StoreError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct OAuthConnectorCleanup {
    pub registration_attempts: usize,
    pub clients: usize,
}

impl OAuthConnectorCleanup {
    #[must_use]
    pub const fn total(self) -> usize {
        self.registration_attempts + self.clients
    }
}

pub struct SqliteOAuthStore {
    worker: Arc<SqliteWorker>,
    connector_id: Option<String>,
}

impl std::fmt::Debug for SqliteOAuthStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteOAuthStore")
            .field("connector_id", &self.connector_id)
            .finish_non_exhaustive()
    }
}

impl SqliteOAuthStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        Self::open_with_scope(path, None)
    }

    pub fn open_scoped(path: &Path, connector_id: &str) -> Result<Self, StoreError> {
        validate_connector_id(connector_id)?;
        Self::open_with_scope(path, Some(connector_id.to_owned()))
    }

    fn open_with_scope(path: &Path, connector_id: Option<String>) -> Result<Self, StoreError> {
        if path
            .symlink_metadata()
            .is_ok_and(|metadata| metadata.file_type().is_symlink())
        {
            return Err(StoreError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "refusing to open a symlinked OAuth database",
            )));
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
            restrict_database_directory(parent)?;
        }
        let connection = Connection::open(path)?;
        let store = Self::from_connection(connection, connector_id)?;
        restrict_database_files(path)?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        Self::in_memory_scoped(TEST_CONNECTOR_ID)
    }

    pub fn in_memory_scoped(connector_id: &str) -> Result<Self, StoreError> {
        validate_connector_id(connector_id)?;
        Self::from_connection(Connection::open_in_memory()?, Some(connector_id.to_owned()))
    }

    fn from_connection(
        mut connection: Connection,
        connector_id: Option<String>,
    ) -> Result<Self, StoreError> {
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS schema_versions (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL CHECK (version >= 0)
             );",
        )?;
        let current = connection
            .query_row(
                "SELECT version FROM schema_versions WHERE component = 'oauth'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .unwrap_or(0);
        if current > OAUTH_SCHEMA_VERSION {
            return Err(StoreError::Corrupt(
                "unsupported OAuth database schema version",
            ));
        }
        migrate_oauth_schema(&mut connection, current)?;
        connection.execute(
            "INSERT INTO schema_versions(component, version) VALUES ('oauth', ?1)
             ON CONFLICT(component) DO UPDATE SET version = excluded.version",
            [OAUTH_SCHEMA_VERSION],
        )?;
        cleanup_expired_connection(&mut connection, Utc::now())?;
        Ok(Self {
            worker: Arc::new(SqliteWorker::start(connection)?),
            connector_id,
        })
    }

    fn scoped_connector_id(&self) -> Result<&str, StoreError> {
        self.connector_id.as_deref().ok_or(StoreError::Corrupt(
            "OAuth service store is not connector-scoped",
        ))
    }

    fn namespaced_hash(&self, hash: &SecretHash) -> Result<SecretHash, StoreError> {
        namespace_hash(self.scoped_connector_id()?, hash)
    }

    pub fn registered_clients(&self) -> Result<Vec<RegisteredClient>, StoreError> {
        let connector_id = self.connector_id.clone();
        self.call(move |connection| {
            registered_clients_connection(connection, connector_id.as_deref())
        })
    }

    pub fn revoke_client_tokens(&self, client_id: &str) -> Result<usize, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        self.revoke_client_tokens_for(&connector_id, client_id)
    }

    pub fn revoke_client_tokens_for(
        &self,
        connector_id: &str,
        client_id: &str,
    ) -> Result<usize, StoreError> {
        validate_connector_id(connector_id)?;
        let connector_id = connector_id.to_owned();
        let client_id = client_id.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "UPDATE oauth_tokens
                 SET status = 'revoked'
                 WHERE client_id = ?1
                   AND status = 'active'
                   AND EXISTS (
                     SELECT 1 FROM oauth_clients
                     WHERE oauth_clients.client_id = oauth_tokens.client_id
                       AND oauth_clients.connector_id = ?2
                   )",
                params![client_id, connector_id],
            )?)
        })
    }

    pub fn delete_client(&self, client_id: &str) -> Result<bool, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        self.delete_client_for(&connector_id, client_id)
    }

    pub fn delete_client_for(
        &self,
        connector_id: &str,
        client_id: &str,
    ) -> Result<bool, StoreError> {
        validate_connector_id(connector_id)?;
        let connector_id = connector_id.to_owned();
        let client_id = client_id.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "DELETE FROM oauth_clients WHERE connector_id = ?1 AND client_id = ?2",
                params![connector_id, client_id],
            )? == 1)
        })
    }

    pub fn sessions(&self, client_id: Option<&str>) -> Result<Vec<OAuthSession>, StoreError> {
        self.sessions_for(self.connector_id.as_deref(), client_id)
    }

    pub fn sessions_for(
        &self,
        connector_id: Option<&str>,
        client_id: Option<&str>,
    ) -> Result<Vec<OAuthSession>, StoreError> {
        if let Some(connector_id) = connector_id {
            validate_connector_id(connector_id)?;
        }
        let connector_id = connector_id.map(str::to_owned);
        let client_id = client_id.map(str::to_owned);
        self.call(move |connection| {
            sessions_connection(connection, connector_id.as_deref(), client_id.as_deref())
        })
    }

    pub fn revoke_session(&self, family_id: Uuid) -> Result<usize, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        self.revoke_session_for(&connector_id, family_id)
    }

    pub fn revoke_session_for(
        &self,
        connector_id: &str,
        family_id: Uuid,
    ) -> Result<usize, StoreError> {
        validate_connector_id(connector_id)?;
        let connector_id = connector_id.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "UPDATE oauth_tokens
                 SET status = 'revoked'
                 WHERE family_id = ?1
                   AND status = 'active'
                   AND EXISTS (
                     SELECT 1 FROM oauth_clients
                     WHERE oauth_clients.client_id = oauth_tokens.client_id
                       AND oauth_clients.connector_id = ?2
                   )",
                params![family_id.to_string(), connector_id],
            )?)
        })
    }

    pub fn remove_connector_data(&self) -> Result<OAuthConnectorCleanup, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        self.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let registration_attempts = transaction.execute(
                "DELETE FROM oauth_registration_attempts WHERE connector_id = ?1",
                [&connector_id],
            )?;
            let clients = transaction.execute(
                "DELETE FROM oauth_clients WHERE connector_id = ?1",
                [&connector_id],
            )?;
            transaction.commit()?;
            Ok(OAuthConnectorCleanup {
                registration_attempts,
                clients,
            })
        })
    }

    pub fn emergency_revoke_all(&self) -> Result<usize, StoreError> {
        let connector_id = self.connector_id.clone();
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            for table in ["oauth_authorizations", "oauth_consents", "oauth_codes"] {
                transaction.execute(
                    &format!(
                        "DELETE FROM {table}
                         WHERE client_id IN (
                           SELECT client_id FROM oauth_clients
                           WHERE (?1 IS NULL OR connector_id = ?1)
                         )"
                    ),
                    [connector_id.as_deref()],
                )?;
            }
            let revoked = transaction.execute(
                "UPDATE oauth_tokens
                 SET status = 'revoked'
                 WHERE status = 'active'
                   AND client_id IN (
                     SELECT client_id FROM oauth_clients
                     WHERE (?1 IS NULL OR connector_id = ?1)
                   )",
                [connector_id.as_deref()],
            )?;
            transaction.commit()?;
            Ok(revoked)
        })
    }

    pub fn cleanup_expired(&self, now: DateTime<Utc>) -> Result<usize, StoreError> {
        self.call(move |connection| cleanup_expired_connection(connection, now))
    }

    fn call<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        self.worker.call(operation)
    }

    #[cfg(test)]
    fn test_call<T, F>(&self, operation: F) -> Result<T, StoreError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, StoreError> + Send + 'static,
    {
        self.call(operation)
    }
}

fn migrate_oauth_schema(connection: &mut Connection, current: i64) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    migrate_registration_attempts(&transaction)?;
    migrate_registered_clients(&transaction)?;
    migrate_connector_namespace(&transaction, current)?;
    create_oauth_tables(&transaction)?;
    migrate_authorization_claims(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_connector_namespace(connection: &Connection, current: i64) -> Result<(), StoreError> {
    if current >= 4 || !table_exists(connection, "oauth_clients")? {
        return Ok(());
    }
    if !table_has_column(connection, "oauth_clients", "connector_id")? {
        connection.execute(
            "ALTER TABLE oauth_clients ADD COLUMN connector_id TEXT NOT NULL DEFAULT 'legacy-unbound'",
            [],
        )?;
    }
    // Namespace-free beta credentials cannot be assigned safely to one issuer.
    // Delete them so upgrading requires explicit client registration and consent.
    for table in [
        "oauth_authorizations",
        "oauth_consents",
        "oauth_codes",
        "oauth_tokens",
        "oauth_registration_attempts",
        "oauth_clients",
    ] {
        if table_exists(connection, table)? {
            connection.execute(&format!("DELETE FROM {table}"), [])?;
        }
    }
    Ok(())
}

fn migrate_registration_attempts(connection: &Connection) -> Result<(), StoreError> {
    if table_exists(connection, "oauth_registration_attempts")?
        && (!table_has_column(connection, "oauth_registration_attempts", "source_key")?
            || !table_has_column(connection, "oauth_registration_attempts", "connector_id")?)
    {
        // Historical attempts cannot be assigned safely to one connector.
        // Recreate this short-lived limiter table with an explicit namespace.
        connection.execute("DROP TABLE oauth_registration_attempts", [])?;
    }
    Ok(())
}

fn migrate_authorization_claims(connection: &Connection) -> Result<(), StoreError> {
    if !table_exists(connection, "oauth_authorizations")? {
        return Ok(());
    }
    for (column, definition) in [
        ("provider_code_hash", "BLOB"),
        ("claim_id", "TEXT"),
        ("claim_expires_at", "INTEGER"),
    ] {
        if !table_has_column(connection, "oauth_authorizations", column)? {
            connection.execute(
                &format!("ALTER TABLE oauth_authorizations ADD COLUMN {column} {definition}"),
                [],
            )?;
        }
    }
    Ok(())
}

fn migrate_registered_clients(connection: &Connection) -> Result<(), StoreError> {
    if !table_exists(connection, "oauth_clients")? {
        return Ok(());
    }
    if !table_has_column(connection, "oauth_clients", "expires_at")? {
        connection.execute(
            "ALTER TABLE oauth_clients ADD COLUMN expires_at INTEGER",
            [],
        )?;
    }
    if !table_has_column(connection, "oauth_clients", "last_used_at")? {
        connection.execute(
            "ALTER TABLE oauth_clients ADD COLUMN last_used_at INTEGER",
            [],
        )?;
    }
    if !table_has_column(connection, "oauth_clients", "registration_source_hash")? {
        connection.execute(
            "ALTER TABLE oauth_clients ADD COLUMN registration_source_hash TEXT",
            [],
        )?;
    }
    let migration_expiry = (Utc::now() + chrono::Duration::days(30)).timestamp();
    connection.execute(
        "UPDATE oauth_clients
         SET expires_at = COALESCE(expires_at, ?1),
             registration_source_hash = COALESCE(registration_source_hash, 'legacy')",
        [migration_expiry],
    )?;
    Ok(())
}

fn create_oauth_tables(connection: &Connection) -> Result<(), StoreError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS oauth_registration_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            connector_id TEXT NOT NULL,
            source_key TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS oauth_registration_attempts_time_idx
            ON oauth_registration_attempts(attempted_at);
         CREATE INDEX IF NOT EXISTS oauth_registration_attempts_source_time_idx
            ON oauth_registration_attempts(connector_id, source_key, attempted_at);
         CREATE INDEX IF NOT EXISTS oauth_registration_attempts_connector_time_idx
            ON oauth_registration_attempts(connector_id, attempted_at);
         CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
            connector_id TEXT NOT NULL,
            client_name TEXT NOT NULL,
            redirect_uris TEXT NOT NULL,
            scopes TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            last_used_at INTEGER,
            registration_source_hash TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS oauth_clients_expiry_idx
            ON oauth_clients(expires_at);
         CREATE INDEX IF NOT EXISTS oauth_clients_connector_idx
            ON oauth_clients(connector_id, issued_at);
         CREATE TABLE IF NOT EXISTS oauth_authorizations (
            provider_state_hash BLOB PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
            redirect_uri TEXT NOT NULL,
            client_state TEXT NOT NULL,
            scopes TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            provider_code_hash BLOB,
            claim_id TEXT,
            claim_expires_at INTEGER
         );
         CREATE TABLE IF NOT EXISTS oauth_consents (
            id TEXT PRIMARY KEY,
            csrf_hash BLOB NOT NULL UNIQUE,
            client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
            redirect_uri TEXT NOT NULL,
            client_state TEXT NOT NULL,
            scopes TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            subject TEXT NOT NULL,
            expires_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS oauth_codes (
            code_hash BLOB PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
            redirect_uri TEXT NOT NULL,
            scopes TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            subject TEXT NOT NULL,
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1))
         );
         CREATE TABLE IF NOT EXISTS oauth_tokens (
            token_hash BLOB PRIMARY KEY,
            token_kind TEXT NOT NULL CHECK (token_kind IN ('access', 'refresh')),
            family_id TEXT NOT NULL,
            client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
            subject TEXT NOT NULL,
            scopes TEXT NOT NULL,
            issued_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('active', 'rotated', 'revoked'))
         );
         CREATE INDEX IF NOT EXISTS oauth_tokens_family_idx
            ON oauth_tokens(family_id);
         CREATE INDEX IF NOT EXISTS oauth_tokens_expiry_idx
            ON oauth_tokens(expires_at);",
    )?;
    Ok(())
}

fn table_exists(connection: &Connection, table: &str) -> Result<bool, StoreError> {
    Ok(connection
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

fn table_has_column(
    connection: &Connection,
    table: &str,
    column: &str,
) -> Result<bool, StoreError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table})"))?;
    let columns = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(columns.iter().any(|candidate| candidate == column))
}

fn validate_connector_id(connector_id: &str) -> Result<(), StoreError> {
    if connector_id.trim().is_empty()
        || connector_id.len() > 128
        || connector_id.chars().any(char::is_control)
    {
        return Err(StoreError::Corrupt("invalid OAuth connector namespace"));
    }
    Ok(())
}

fn namespace_hash(connector_id: &str, hash: &SecretHash) -> Result<SecretHash, StoreError> {
    let mut digest = Sha256::new();
    digest.update(b"runonmine/oauth/store-namespace/v1\0");
    digest.update(connector_id.as_bytes());
    digest.update([0]);
    digest.update(hash.as_bytes());
    SecretHash::from_slice(&digest.finalize())
        .map_err(|_| StoreError::Corrupt("failed to namespace OAuth hash"))
}

fn namespace_token_pair(
    connector_id: &str,
    tokens: &TokenPairDraft,
) -> Result<TokenPairDraft, StoreError> {
    Ok(TokenPairDraft {
        access_hash: namespace_hash(connector_id, &tokens.access_hash)?,
        refresh_hash: namespace_hash(connector_id, &tokens.refresh_hash)?,
        access_expires_at: tokens.access_expires_at,
        refresh_expires_at: tokens.refresh_expires_at,
    })
}

fn prune_expired_clients(
    connection: &Connection,
    connector_id: Option<&str>,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    Ok(connection.execute(
        "DELETE FROM oauth_clients
         WHERE (?1 IS NULL OR connector_id = ?1)
           AND expires_at <= ?2
           AND NOT EXISTS (
             SELECT 1 FROM oauth_tokens
             WHERE oauth_tokens.client_id = oauth_clients.client_id
               AND oauth_tokens.status = 'active'
               AND oauth_tokens.expires_at > ?2
           )",
        params![connector_id, now.timestamp()],
    )?)
}

fn validate_registration_limits(limits: &RegistrationLimits) -> Result<(), StoreError> {
    if limits.window_seconds <= 0
        || limits.per_source_limit == 0
        || limits.global_limit == 0
        || limits.max_clients == 0
        || limits.per_source_limit > limits.global_limit
    {
        return Err(StoreError::Corrupt(
            "invalid OAuth registration limiter settings",
        ));
    }
    Ok(())
}

fn limit_as_i64(value: usize) -> Result<i64, StoreError> {
    i64::try_from(value).map_err(|_| StoreError::Corrupt("invalid OAuth registration limit"))
}

impl OAuthStore for SqliteOAuthStore {
    fn register_client_limited(
        &self,
        client: &RegisteredClient,
        limits: &RegistrationLimits,
    ) -> Result<RegistrationOutcome, StoreError> {
        validate_registration_limits(limits)?;
        let connector_id = self.scoped_connector_id()?.to_owned();
        if client.connector_id != connector_id {
            return Err(StoreError::Corrupt(
                "OAuth client does not belong to this connector namespace",
            ));
        }
        let client = client.clone();
        let limits = limits.clone();
        self.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let cutoff = limits.now.timestamp().saturating_sub(limits.window_seconds);
            transaction.execute(
                "DELETE FROM oauth_registration_attempts WHERE attempted_at <= ?1",
                [cutoff],
            )?;
            let source_key = client.registration_source_hash.clone();
            let global_count = transaction.query_row(
                "SELECT COUNT(*) FROM oauth_registration_attempts WHERE connector_id = ?1",
                [&connector_id],
                |row| row.get::<_, i64>(0),
            )?;
            let source_count = transaction.query_row(
                "SELECT COUNT(*) FROM oauth_registration_attempts
                 WHERE connector_id = ?1 AND source_key = ?2",
                params![connector_id, source_key],
                |row| row.get::<_, i64>(0),
            )?;
            if global_count >= limit_as_i64(limits.global_limit)?
                || source_count >= limit_as_i64(limits.per_source_limit)?
            {
                transaction.commit()?;
                return Ok(RegistrationOutcome::RateLimited);
            }
            prune_expired_clients(&transaction, Some(&connector_id), limits.now)?;
            let client_count = transaction.query_row(
                "SELECT COUNT(*) FROM oauth_clients WHERE connector_id = ?1",
                [&connector_id],
                |row| row.get::<_, i64>(0),
            )?;
            if client_count >= limit_as_i64(limits.max_clients)? {
                transaction.commit()?;
                return Ok(RegistrationOutcome::CapacityReached);
            }
            let redirects = serde_json::to_string(&client.redirect_uris)
                .map_err(|_| StoreError::Corrupt("client redirect URI serialization failed"))?;
            transaction.execute(
                "INSERT INTO oauth_registration_attempts (connector_id, source_key, attempted_at)
                 VALUES (?1, ?2, ?3)",
                params![connector_id, source_key, limits.now.timestamp()],
            )?;
            transaction.execute(
                "INSERT INTO oauth_clients (
                    client_id, connector_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    client.client_id,
                    connector_id,
                    client.client_name,
                    redirects,
                    client.scopes.to_space_delimited(),
                    client.issued_at.timestamp(),
                    client.expires_at.timestamp(),
                    client.last_used_at.map(|value| value.timestamp()),
                    client.registration_source_hash,
                ],
            )?;
            transaction.commit()?;
            Ok(RegistrationOutcome::Registered)
        })
    }

    fn client(&self, client_id: &str) -> Result<Option<RegisteredClient>, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let client_id = client_id.to_owned();
        self.call(move |connection| client_connection(connection, &connector_id, &client_id))
    }

    fn touch_client(
        &self,
        client_id: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let client_id = client_id.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "UPDATE oauth_clients
                 SET last_used_at = ?1,
                     expires_at = CASE WHEN expires_at < ?2 THEN ?2 ELSE expires_at END
                 WHERE connector_id = ?3 AND client_id = ?4 AND expires_at > ?1",
                params![
                    now.timestamp(),
                    expires_at.timestamp(),
                    connector_id,
                    client_id
                ],
            )? == 1)
        })
    }

    fn put_authorization(&self, pending: &PendingAuthorization) -> Result<(), StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let mut pending = pending.clone();
        pending.provider_state_hash = namespace_hash(&connector_id, &pending.provider_state_hash)?;
        self.call(move |connection| {
            connection.execute(
                "INSERT INTO oauth_authorizations (provider_state_hash, client_id, redirect_uri, client_state, scopes, code_challenge, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![pending.provider_state_hash.as_bytes().as_slice(), pending.client_id, pending.redirect_uri.as_str(), pending.client_state, pending.scopes.to_space_delimited(), pending.code_challenge, pending.expires_at.timestamp()],
            )?;
            Ok(())
        })
    }

    fn claim_authorization(
        &self,
        state_hash: &SecretHash,
        provider_code_hash: &SecretHash,
        claim_id: Uuid,
        now: DateTime<Utc>,
        claim_expires_at: DateTime<Utc>,
    ) -> Result<AuthorizationClaim, StoreError> {
        if claim_expires_at <= now {
            return Err(StoreError::InvalidGrant);
        }
        let original_state_hash = *state_hash;
        let original_code_hash = *provider_code_hash;
        let state_hash = self.namespaced_hash(state_hash)?;
        let provider_code_hash = self.namespaced_hash(provider_code_hash)?;
        self.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            transaction.execute(
                "DELETE FROM oauth_authorizations WHERE expires_at <= ?1",
                [now.timestamp()],
            )?;
            let row = transaction
                .query_row(
                    "SELECT client_id, redirect_uri, client_state, scopes, code_challenge,
                            expires_at, provider_code_hash, claim_id, claim_expires_at
                     FROM oauth_authorizations WHERE provider_state_hash = ?1",
                    [state_hash.as_bytes().as_slice()],
                    map_authorization_claim_row,
                )
                .optional()?
                .ok_or(StoreError::NotFound)?;
            let (pending, stored_code_hash, active_claim_id, active_claim_expires_at) = row;
            if let Some(stored_code_hash) = stored_code_hash {
                let stored_code_hash = SecretHash::from_slice(&stored_code_hash)?;
                if !stored_code_hash.constant_time_eq(&provider_code_hash) {
                    return Err(StoreError::InvalidGrant);
                }
            }
            if active_claim_id.is_some()
                && active_claim_expires_at.is_some_and(|expires_at| expires_at > now.timestamp())
            {
                return Err(StoreError::InvalidGrant);
            }
            let effective_claim_expiry = claim_expires_at.min(pending.expires_at);
            let changed = transaction.execute(
                "UPDATE oauth_authorizations
                 SET provider_code_hash = ?1, claim_id = ?2, claim_expires_at = ?3
                 WHERE provider_state_hash = ?4 AND expires_at > ?5",
                params![
                    provider_code_hash.as_bytes().as_slice(),
                    claim_id.to_string(),
                    effective_claim_expiry.timestamp(),
                    state_hash.as_bytes().as_slice(),
                    now.timestamp(),
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::InvalidGrant);
            }
            transaction.commit()?;
            Ok(AuthorizationClaim {
                claim_id,
                provider_code_hash: original_code_hash,
                pending: PendingAuthorization {
                    provider_state_hash: original_state_hash,
                    ..pending
                },
                claim_expires_at: effective_claim_expiry,
            })
        })
    }

    fn release_authorization_claim(
        &self,
        claim: &AuthorizationClaim,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let state_hash = self.namespaced_hash(&claim.pending.provider_state_hash)?;
        let provider_code_hash = self.namespaced_hash(&claim.provider_code_hash)?;
        let claim_id = claim.claim_id.to_string();
        self.call(move |connection| {
            let changed = connection.execute(
                "UPDATE oauth_authorizations
                 SET claim_id = NULL, claim_expires_at = NULL
                 WHERE provider_state_hash = ?1 AND provider_code_hash = ?2
                   AND claim_id = ?3 AND expires_at > ?4",
                params![
                    state_hash.as_bytes().as_slice(),
                    provider_code_hash.as_bytes().as_slice(),
                    claim_id,
                    now.timestamp(),
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::InvalidGrant);
            }
            Ok(())
        })
    }

    fn consume_authorization_claim(
        &self,
        claim: &AuthorizationClaim,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        let state_hash = self.namespaced_hash(&claim.pending.provider_state_hash)?;
        let provider_code_hash = self.namespaced_hash(&claim.provider_code_hash)?;
        let claim_id = claim.claim_id.to_string();
        self.call(move |connection| {
            let changed = connection.execute(
                "DELETE FROM oauth_authorizations
                 WHERE provider_state_hash = ?1 AND provider_code_hash = ?2
                   AND claim_id = ?3 AND expires_at > ?4",
                params![
                    state_hash.as_bytes().as_slice(),
                    provider_code_hash.as_bytes().as_slice(),
                    claim_id,
                    now.timestamp(),
                ],
            )?;
            if changed != 1 {
                return Err(StoreError::InvalidGrant);
            }
            Ok(())
        })
    }

    fn complete_authorization_claim(
        &self,
        claim: &AuthorizationClaim,
        consent: &PendingConsent,
        now: DateTime<Utc>,
    ) -> Result<(), StoreError> {
        if consent.client_id != claim.pending.client_id
            || consent.redirect_uri != claim.pending.redirect_uri
            || consent.client_state != claim.pending.client_state
            || consent.scopes != claim.pending.scopes
            || consent.code_challenge != claim.pending.code_challenge
        {
            return Err(StoreError::Corrupt(
                "authorization claim and consent do not match",
            ));
        }
        let state_hash = self.namespaced_hash(&claim.pending.provider_state_hash)?;
        let provider_code_hash = self.namespaced_hash(&claim.provider_code_hash)?;
        let claim_id = claim.claim_id.to_string();
        let mut consent = consent.clone();
        let connector_id = self.scoped_connector_id()?.to_owned();
        consent.csrf_hash = namespace_hash(&connector_id, &consent.csrf_hash)?;
        self.call(move |connection| {
            let transaction =
                connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let claim_exists = transaction
                .query_row(
                    "SELECT 1 FROM oauth_authorizations
                     WHERE provider_state_hash = ?1 AND provider_code_hash = ?2
                       AND claim_id = ?3 AND claim_expires_at > ?4 AND expires_at > ?4",
                    params![
                        state_hash.as_bytes().as_slice(),
                        provider_code_hash.as_bytes().as_slice(),
                        claim_id,
                        now.timestamp(),
                    ],
                    |_| Ok(()),
                )
                .optional()?
                .is_some();
            if !claim_exists {
                return Err(StoreError::InvalidGrant);
            }
            transaction.execute(
                "INSERT INTO oauth_consents
                 (id, csrf_hash, client_id, redirect_uri, client_state, scopes,
                  code_challenge, subject, expires_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![
                    consent.id.to_string(),
                    consent.csrf_hash.as_bytes().as_slice(),
                    consent.client_id,
                    consent.redirect_uri.as_str(),
                    consent.client_state,
                    consent.scopes.to_space_delimited(),
                    consent.code_challenge,
                    consent.subject,
                    consent.expires_at.timestamp(),
                ],
            )?;
            let removed = transaction.execute(
                "DELETE FROM oauth_authorizations
                 WHERE provider_state_hash = ?1 AND provider_code_hash = ?2
                   AND claim_id = ?3",
                params![
                    state_hash.as_bytes().as_slice(),
                    provider_code_hash.as_bytes().as_slice(),
                    claim_id,
                ],
            )?;
            if removed != 1 {
                return Err(StoreError::InvalidGrant);
            }
            transaction.commit()?;
            Ok(())
        })
    }

    fn put_consent(&self, pending: &PendingConsent) -> Result<(), StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let mut pending = pending.clone();
        pending.csrf_hash = namespace_hash(&connector_id, &pending.csrf_hash)?;
        self.call(move |connection| {
            connection.execute(
                "INSERT INTO oauth_consents (id, csrf_hash, client_id, redirect_uri, client_state, scopes, code_challenge, subject, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                params![pending.id.to_string(), pending.csrf_hash.as_bytes().as_slice(), pending.client_id, pending.redirect_uri.as_str(), pending.client_state, pending.scopes.to_space_delimited(), pending.code_challenge, pending.subject, pending.expires_at.timestamp()],
            )?;
            Ok(())
        })
    }

    fn take_consent(
        &self,
        id: Uuid,
        csrf_hash: &SecretHash,
        now: DateTime<Utc>,
    ) -> Result<PendingConsent, StoreError> {
        let original_hash = *csrf_hash;
        let csrf_hash = self.namespaced_hash(csrf_hash)?;
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM oauth_consents WHERE expires_at <= ?1", [now.timestamp()])?;
            let consent = transaction.query_row(
                "SELECT client_id, redirect_uri, client_state, scopes, code_challenge, subject, expires_at FROM oauth_consents WHERE id = ?1 AND csrf_hash = ?2",
                params![id.to_string(), csrf_hash.as_bytes().as_slice()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, i64>(6)?)),
            ).optional()?.ok_or(StoreError::NotFound)?;
            transaction.execute("DELETE FROM oauth_consents WHERE id = ?1 AND csrf_hash = ?2", params![id.to_string(), csrf_hash.as_bytes().as_slice()])?;
            transaction.commit()?;
            Ok(PendingConsent { id, csrf_hash: original_hash, client_id: consent.0, redirect_uri: parse_url(&consent.1)?, client_state: consent.2, scopes: parse_scopes(&consent.3)?, code_challenge: consent.4, subject: consent.5, expires_at: from_timestamp(consent.6)? })
        })
    }

    fn put_authorization_code(&self, code: &AuthorizationCodeGrant) -> Result<(), StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let mut code = code.clone();
        code.code_hash = namespace_hash(&connector_id, &code.code_hash)?;
        self.call(move |connection| {
            connection.execute(
                "INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, scopes, code_challenge, subject, expires_at, used) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                params![code.code_hash.as_bytes().as_slice(), code.client_id, code.redirect_uri.as_str(), code.scopes.to_space_delimited(), code.code_challenge, code.subject, code.expires_at.timestamp()],
            )?;
            Ok(())
        })
    }

    fn exchange_authorization_code(
        &self,
        code_hash: &SecretHash,
        client_id: &str,
        redirect_uri: &Url,
        verifier: &str,
        tokens: &TokenPairDraft,
        now: DateTime<Utc>,
    ) -> Result<TokenGrant, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let code_hash = namespace_hash(&connector_id, code_hash)?;
        let client_id = client_id.to_owned();
        let redirect_uri = redirect_uri.clone();
        let verifier = verifier.to_owned();
        let tokens = namespace_token_pair(&connector_id, tokens)?;
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            let row = transaction.query_row(
                "SELECT client_id, redirect_uri, scopes, code_challenge, subject, expires_at, used FROM oauth_codes WHERE code_hash = ?1",
                [code_hash.as_bytes().as_slice()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, bool>(6)?)),
            ).optional()?.ok_or(StoreError::InvalidGrant)?;
            if row.6 || row.5 <= now.timestamp() || row.0 != client_id || row.1 != redirect_uri.as_str() || !verify_pkce(&verifier, &row.3) { return Err(StoreError::InvalidGrant); }
            if transaction.execute("UPDATE oauth_codes SET used = 1 WHERE code_hash = ?1 AND used = 0", [code_hash.as_bytes().as_slice()])? != 1 { return Err(StoreError::InvalidGrant); }
            let scopes = parse_scopes(&row.2)?;
            insert_token_pair(&transaction, Uuid::new_v4(), &client_id, &row.4, &scopes, &tokens, now)?;
            transaction.commit()?;
            Ok(TokenGrant { scopes })
        })
    }

    fn rotate_refresh_token(
        &self,
        refresh_hash: &SecretHash,
        client_id: &str,
        requested_scopes: Option<&ScopeSet>,
        tokens: &TokenPairDraft,
        now: DateTime<Utc>,
    ) -> Result<TokenGrant, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let refresh_hash = namespace_hash(&connector_id, refresh_hash)?;
        let client_id = client_id.to_owned();
        let requested_scopes = requested_scopes.cloned();
        let tokens = namespace_token_pair(&connector_id, tokens)?;
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            let row = transaction.query_row(
                "SELECT token_kind, family_id, client_id, subject, scopes, expires_at, status FROM oauth_tokens WHERE token_hash = ?1",
                [refresh_hash.as_bytes().as_slice()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, String>(6)?)),
            ).optional()?.ok_or(StoreError::InvalidGrant)?;
            if row.0 != "refresh" || row.2 != client_id || row.5 <= now.timestamp() { return Err(StoreError::InvalidGrant); }
            if row.6 != "active" {
                transaction.execute(
                    "UPDATE oauth_tokens SET status = 'revoked'
                     WHERE family_id = ?1
                       AND client_id IN (SELECT client_id FROM oauth_clients WHERE connector_id = ?2)",
                    params![row.1, connector_id],
                )?;
                transaction.commit()?;
                return Err(StoreError::RefreshReuse);
            }
            let original_scopes = parse_scopes(&row.4)?;
            let scopes = requested_scopes.as_ref().unwrap_or(&original_scopes);
            if !scopes.is_subset(&original_scopes) { return Err(StoreError::InvalidGrant); }
            if transaction.execute("UPDATE oauth_tokens SET status = 'rotated' WHERE token_hash = ?1 AND status = 'active'", [refresh_hash.as_bytes().as_slice()])? != 1 { return Err(StoreError::RefreshReuse); }
            let family = Uuid::parse_str(&row.1).map_err(|_| StoreError::Corrupt("invalid refresh token family"))?;
            insert_token_pair(&transaction, family, &client_id, &row.3, scopes, &tokens, now)?;
            transaction.commit()?;
            Ok(TokenGrant { scopes: scopes.clone() })
        })
    }

    fn revoke_token(&self, token_hash: &SecretHash) -> Result<(), StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let token_hash = namespace_hash(&connector_id, token_hash)?;
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            let token = transaction
                .query_row(
                    "SELECT token_kind, family_id FROM oauth_tokens WHERE token_hash = ?1",
                    [token_hash.as_bytes().as_slice()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?;
            if let Some((kind, family)) = token {
                if kind == "refresh" {
                    transaction.execute(
                        "UPDATE oauth_tokens SET status = 'revoked'
                         WHERE family_id = ?1
                           AND client_id IN (SELECT client_id FROM oauth_clients WHERE connector_id = ?2)",
                        params![family, connector_id],
                    )?;
                } else {
                    transaction.execute(
                        "UPDATE oauth_tokens SET status = 'revoked' WHERE token_hash = ?1",
                        [token_hash.as_bytes().as_slice()],
                    )?;
                }
            }
            transaction.commit()?;
            Ok(())
        })
    }

    fn access_grant(
        &self,
        token_hash: &SecretHash,
        now: DateTime<Utc>,
    ) -> Result<Option<AccessGrant>, StoreError> {
        let connector_id = self.scoped_connector_id()?.to_owned();
        let token_hash = namespace_hash(&connector_id, token_hash)?;
        self.call(move |connection| {
            let row = connection.query_row(
                "SELECT oauth_tokens.client_id, oauth_tokens.subject, oauth_tokens.scopes, oauth_tokens.expires_at
                 FROM oauth_tokens
                 JOIN oauth_clients ON oauth_clients.client_id = oauth_tokens.client_id
                 WHERE oauth_tokens.token_hash = ?1
                   AND oauth_tokens.token_kind = 'access'
                   AND oauth_tokens.status = 'active'
                   AND oauth_tokens.expires_at > ?2
                   AND oauth_clients.connector_id = ?3",
                params![token_hash.as_bytes().as_slice(), now.timestamp(), connector_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?)),
            ).optional()?;
            row.map(|(client_id, subject, scopes, expires_at)| Ok(AccessGrant { client_id, subject, scopes: parse_scopes(&scopes)?, expires_at: from_timestamp(expires_at)? })).transpose()
        })
    }
}

fn registered_clients_connection(
    connection: &mut Connection,
    connector_id: Option<&str>,
) -> Result<Vec<RegisteredClient>, StoreError> {
    prune_expired_clients(connection, connector_id, Utc::now())?;
    let mut statement = connection.prepare(
        "SELECT connector_id, client_id, client_name, redirect_uris, scopes, issued_at,
                expires_at, last_used_at, registration_source_hash
         FROM oauth_clients
         WHERE (?1 IS NULL OR connector_id = ?1)
         ORDER BY issued_at DESC, connector_id ASC, client_id ASC",
    )?;
    let rows = statement.query_map([connector_id], map_registered_client_row)?;
    rows.map(|row| decode_registered_client(row?)).collect()
}

fn client_connection(
    connection: &mut Connection,
    connector_id: &str,
    client_id: &str,
) -> Result<Option<RegisteredClient>, StoreError> {
    let now = Utc::now();
    prune_expired_clients(connection, Some(connector_id), now)?;
    connection
        .query_row(
            "SELECT connector_id, client_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
             FROM oauth_clients
             WHERE connector_id = ?1 AND client_id = ?2 AND expires_at > ?3",
            params![connector_id, client_id, now.timestamp()],
            map_registered_client_row,
        )
        .optional()?
        .map(decode_registered_client)
        .transpose()
}

type RegisteredClientRow = (
    String,
    String,
    String,
    String,
    String,
    i64,
    i64,
    Option<i64>,
    String,
);

fn map_registered_client_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<RegisteredClientRow> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn decode_registered_client(row: RegisteredClientRow) -> Result<RegisteredClient, StoreError> {
    Ok(RegisteredClient {
        connector_id: row.0,
        client_id: row.1,
        client_name: row.2,
        redirect_uris: serde_json::from_str(&row.3)
            .map_err(|_| StoreError::Corrupt("invalid registered redirect URI"))?,
        scopes: parse_scopes(&row.4)?,
        issued_at: from_timestamp(row.5)?,
        expires_at: from_timestamp(row.6)?,
        last_used_at: row.7.map(from_timestamp).transpose()?,
        registration_source_hash: row.8,
    })
}

fn sessions_connection(
    connection: &mut Connection,
    connector_id: Option<&str>,
    client_id: Option<&str>,
) -> Result<Vec<OAuthSession>, StoreError> {
    let mut statement = connection.prepare(
        "SELECT oauth_clients.connector_id, oauth_tokens.family_id, oauth_tokens.client_id,
                oauth_tokens.subject, oauth_tokens.scopes, MIN(oauth_tokens.issued_at),
                MAX(oauth_tokens.expires_at),
                MAX(CASE WHEN oauth_tokens.status = 'active' AND oauth_tokens.expires_at > ?1 THEN 1 ELSE 0 END)
         FROM oauth_tokens
         JOIN oauth_clients ON oauth_clients.client_id = oauth_tokens.client_id
         WHERE (?2 IS NULL OR oauth_clients.connector_id = ?2)
           AND (?3 IS NULL OR oauth_tokens.client_id = ?3)
         GROUP BY oauth_clients.connector_id, oauth_tokens.family_id, oauth_tokens.client_id,
                  oauth_tokens.subject, oauth_tokens.scopes
         ORDER BY MAX(oauth_tokens.issued_at) DESC, oauth_clients.connector_id, oauth_tokens.family_id ASC",
    )?;
    let rows = statement.query_map(
        params![Utc::now().timestamp(), connector_id, client_id],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, bool>(7)?,
            ))
        },
    )?;
    rows.map(|row| {
        let (connector_id, family_id, client_id, subject, scopes, issued_at, expires_at, active) =
            row?;
        Ok(OAuthSession {
            connector_id,
            family_id: Uuid::parse_str(&family_id)
                .map_err(|_| StoreError::Corrupt("invalid token family"))?,
            client_id,
            subject,
            scopes: parse_scopes(&scopes)?,
            issued_at: from_timestamp(issued_at)?,
            expires_at: from_timestamp(expires_at)?,
            active,
        })
    })
    .collect()
}

fn cleanup_expired_connection(
    connection: &mut Connection,
    now: DateTime<Utc>,
) -> Result<usize, StoreError> {
    let transaction = connection.transaction()?;
    let mut removed = 0;
    for table in [
        "oauth_authorizations",
        "oauth_consents",
        "oauth_codes",
        "oauth_tokens",
    ] {
        removed += transaction.execute(
            &format!("DELETE FROM {table} WHERE expires_at <= ?1"),
            [now.timestamp()],
        )?;
    }
    removed += transaction.execute(
        "DELETE FROM oauth_registration_attempts WHERE attempted_at <= ?1",
        [now.timestamp().saturating_sub(3_600)],
    )?;
    removed += prune_expired_clients(&transaction, None, now)?;
    transaction.commit()?;
    Ok(removed)
}

type AuthorizationClaimRow = (
    PendingAuthorization,
    Option<Vec<u8>>,
    Option<String>,
    Option<i64>,
);

fn map_authorization_claim_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuthorizationClaimRow> {
    Ok((
        map_authorization(row)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
    ))
}

fn map_authorization(row: &rusqlite::Row<'_>) -> rusqlite::Result<PendingAuthorization> {
    let redirect_uri: String = row.get(1)?;
    let scopes: String = row.get(3)?;
    let expires_at: i64 = row.get(5)?;
    Ok(PendingAuthorization {
        provider_state_hash: SecretHash::from_slice(&[0_u8; 32])
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_id: row.get(0)?,
        redirect_uri: Url::parse(&redirect_uri).map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_state: row.get(2)?,
        scopes: ScopeSet::parse(&scopes).map_err(|_| rusqlite::Error::InvalidQuery)?,
        code_challenge: row.get(4)?,
        expires_at: DateTime::from_timestamp(expires_at, 0).ok_or(rusqlite::Error::InvalidQuery)?,
    })
}

fn insert_token_pair(
    transaction: &Transaction<'_>,
    family_id: Uuid,
    client_id: &str,
    subject: &str,
    scopes: &ScopeSet,
    tokens: &TokenPairDraft,
    now: DateTime<Utc>,
) -> Result<(), StoreError> {
    let scope = scopes.to_space_delimited();
    transaction.execute(
        "INSERT INTO oauth_tokens
         (token_hash, token_kind, family_id, client_id, subject, scopes,
          issued_at, expires_at, status)
         VALUES (?1, 'access', ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
        params![
            tokens.access_hash.as_bytes().as_slice(),
            family_id.to_string(),
            client_id,
            subject,
            scope,
            now.timestamp(),
            tokens.access_expires_at.timestamp(),
        ],
    )?;
    transaction.execute(
        "INSERT INTO oauth_tokens
         (token_hash, token_kind, family_id, client_id, subject, scopes,
          issued_at, expires_at, status)
         VALUES (?1, 'refresh', ?2, ?3, ?4, ?5, ?6, ?7, 'active')",
        params![
            tokens.refresh_hash.as_bytes().as_slice(),
            family_id.to_string(),
            client_id,
            subject,
            scope,
            now.timestamp(),
            tokens.refresh_expires_at.timestamp(),
        ],
    )?;
    Ok(())
}

fn parse_scopes(value: &str) -> Result<ScopeSet, StoreError> {
    ScopeSet::parse(value).map_err(|_| StoreError::Corrupt("invalid persisted scope"))
}

fn parse_url(value: &str) -> Result<Url, StoreError> {
    Url::parse(value).map_err(|_| StoreError::Corrupt("invalid persisted URL"))
}

fn from_timestamp(value: i64) -> Result<DateTime<Utc>, StoreError> {
    DateTime::from_timestamp(value, 0).ok_or(StoreError::Corrupt("invalid persisted timestamp"))
}

fn sqlite_sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    std::path::PathBuf::from(value)
}

fn restrict_database_directory(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_database_files(path: &Path) -> Result<(), StoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        for candidate in [
            path.to_path_buf(),
            sqlite_sidecar(path, "-wal"),
            sqlite_sidecar(path, "-shm"),
        ] {
            match std::fs::symlink_metadata(&candidate) {
                Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                    return Err(StoreError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "OAuth SQLite path must be a regular, non-symlink file",
                    )));
                }
                Ok(_) => {
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600))?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(StoreError::Io(error)),
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;

    use super::*;

    fn registered_client(
        client_id: &str,
        source: &str,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> RegisteredClient {
        RegisteredClient {
            connector_id: TEST_CONNECTOR_ID.to_owned(),
            client_id: client_id.to_owned(),
            client_name: format!("Client {client_id}"),
            redirect_uris: vec![
                Url::parse("https://client.example/callback").unwrap_or_else(|_| unreachable!()),
            ],
            scopes: ScopeSet::machine_read(),
            issued_at,
            expires_at,
            last_used_at: None,
            registration_source_hash: source.to_owned(),
        }
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_database_directory_and_files_are_private() -> Result<(), StoreError> {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir()?;
        let state_directory = directory.path().join("state");
        let database = state_directory.join("state.db");
        let _store = SqliteOAuthStore::open(&database)?;
        assert_eq!(
            std::fs::metadata(&state_directory)?.permissions().mode() & 0o777,
            0o700
        );
        for path in [
            database.clone(),
            sqlite_sidecar(&database, "-wal"),
            sqlite_sidecar(&database, "-shm"),
        ] {
            if path.exists() {
                assert_eq!(std::fs::metadata(path)?.permissions().mode() & 0o777, 0o600);
            }
        }
        Ok(())
    }

    #[test]
    fn connector_data_removal_is_scoped_cascading_and_idempotent() -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory_scoped("remove-me")?;
        let now = Utc::now().timestamp();
        store.test_call(move |connection| {
            for connector_id in ["remove-me", "keep-me"] {
                let client_id = format!("client-{connector_id}");
                connection.execute(
                    "INSERT INTO oauth_registration_attempts (
                        connector_id, source_key, attempted_at
                     ) VALUES (?1, ?2, ?3)",
                    params![connector_id, format!("source-{connector_id}"), now],
                )?;
                connection.execute(
                    "INSERT INTO oauth_clients (
                        client_id, connector_id, client_name, redirect_uris, scopes,
                        issued_at, expires_at, last_used_at, registration_source_hash
                     ) VALUES (?1, ?2, 'Client', '[]', 'machine:read', ?3, ?4, NULL, 'source')",
                    params![client_id, connector_id, now, now + 3_600],
                )?;
                connection.execute(
                    "INSERT INTO oauth_tokens (
                        token_hash, token_kind, family_id, client_id, subject,
                        scopes, issued_at, expires_at, status
                     ) VALUES (?1, 'access', ?2, ?3, 'owner', 'machine:read', ?4, ?5, 'active')",
                    params![
                        vec![
                            if connector_id == "remove-me" {
                                1_u8
                            } else {
                                2_u8
                            };
                            32
                        ],
                        Uuid::new_v4().to_string(),
                        format!("client-{connector_id}"),
                        now,
                        now + 3_600,
                    ],
                )?;
            }
            Ok(())
        })?;

        let removed = store.remove_connector_data()?;
        assert_eq!(removed.registration_attempts, 1);
        assert_eq!(removed.clients, 1);
        assert_eq!(removed.total(), 2);
        assert_eq!(store.remove_connector_data()?.total(), 0);
        store.test_call(|connection| {
            let keep_clients: i64 = connection.query_row(
                "SELECT COUNT(*) FROM oauth_clients WHERE connector_id = 'keep-me'",
                [],
                |row| row.get(0),
            )?;
            let remove_tokens: i64 = connection.query_row(
                "SELECT COUNT(*) FROM oauth_tokens WHERE client_id = 'client-remove-me'",
                [],
                |row| row.get(0),
            )?;
            let keep_tokens: i64 = connection.query_row(
                "SELECT COUNT(*) FROM oauth_tokens WHERE client_id = 'client-keep-me'",
                [],
                |row| row.get(0),
            )?;
            assert_eq!(keep_clients, 1);
            assert_eq!(remove_tokens, 0);
            assert_eq!(keep_tokens, 1);
            Ok(())
        })?;
        Ok(())
    }

    #[test]
    fn emergency_revoke_removes_pending_flows_and_revokes_tokens() -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now().timestamp();
        store.test_call(move |connection| {
            connection.execute(
                "INSERT INTO oauth_clients (
                    client_id, connector_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES ('client', 'test-connector', 'Client', '[]', 'machine:read', ?1, ?2, NULL, 'test')",
                params![now, now + 7_200],
            )?;
            connection.execute(
                "INSERT INTO oauth_tokens (token_hash, token_kind, family_id, client_id, subject, scopes, issued_at, expires_at, status) VALUES (?1, 'access', ?2, 'client', 'owner', 'machine:read', ?3, ?4, 'active')",
                params![vec![7_u8; 32], Uuid::new_v4().to_string(), now, now + 3_600],
            )?;
            Ok(())
        })?;

        assert_eq!(store.emergency_revoke_all()?, 1);
        let status: String = store.test_call(|connection| {
            connection
                .query_row("SELECT status FROM oauth_tokens LIMIT 1", [], |row| {
                    row.get(0)
                })
                .map_err(Into::into)
        })?;
        assert_eq!(status, "revoked");
        Ok(())
    }

    #[test]
    fn cleanup_removes_only_expired_records() -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now();
        store.test_call(move |connection| {
            connection.execute(
                "INSERT INTO oauth_clients (
                    client_id, connector_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES ('client', 'test-connector', 'Client', '[]', 'machine:read', ?1, ?2, NULL, 'test')",
                params![now.timestamp(), now.timestamp() + 7_200],
            )?;
            for (hash, expiry) in [(vec![1_u8; 32], -1_i64), (vec![2_u8; 32], 3_600_i64)] {
                connection.execute(
                    "INSERT INTO oauth_tokens (token_hash, token_kind, family_id, client_id, subject, scopes, issued_at, expires_at, status) VALUES (?1, 'access', ?2, 'client', 'owner', 'machine:read', ?3, ?4, 'active')",
                    params![hash, Uuid::new_v4().to_string(), now.timestamp(), now.timestamp() + expiry],
                )?;
            }
            Ok(())
        })?;

        assert_eq!(store.cleanup_expired(now)?, 1);
        let remaining: i64 = store.test_call(|connection| {
            connection
                .query_row("SELECT COUNT(*) FROM oauth_tokens", [], |row| row.get(0))
                .map_err(Into::into)
        })?;
        assert_eq!(remaining, 1);
        Ok(())
    }

    #[test]
    fn owner_can_list_revoke_and_delete_clients_and_sessions() -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now();
        let family = Uuid::new_v4();
        store.test_call(move |connection| {
            connection.execute(
                r#"INSERT INTO oauth_clients (
                    client_id, connector_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES ('client', 'test-connector', 'Client', '["https://client.example/callback"]',
                           'machine:read', ?1, ?2, NULL, 'test')"#,
                params![now.timestamp(), now.timestamp() + 7_200],
            )?;
            for (index, kind) in ["access", "refresh"].into_iter().enumerate() {
                connection.execute(
                    "INSERT INTO oauth_tokens (token_hash, token_kind, family_id, client_id, subject, scopes, issued_at, expires_at, status) VALUES (?1, ?2, ?3, 'client', 'github:42', 'machine:read', ?4, ?5, 'active')",
                    params![vec![u8::try_from(index + 1).unwrap_or(1); 32], kind, family.to_string(), now.timestamp(), (now + chrono::Duration::hours(1)).timestamp()],
                )?;
            }
            Ok(())
        })?;

        let clients = store.registered_clients()?;
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].connector_id, TEST_CONNECTOR_ID);
        assert_eq!(clients[0].client_id, "client");
        let sessions = store.sessions(Some("client"))?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].connector_id, TEST_CONNECTOR_ID);
        assert!(sessions[0].active);
        assert_eq!(store.revoke_session(family)?, 2);
        assert!(!store.sessions(Some("client"))?[0].active);
        assert_eq!(store.revoke_client_tokens("client")?, 0);
        assert!(store.delete_client("client")?);
        assert!(store.registered_clients()?.is_empty());
        Ok(())
    }

    struct NamespaceFixture {
        _directory: tempfile::TempDir,
        connector_a: SqliteOAuthStore,
        connector_b: SqliteOAuthStore,
        admin: SqliteOAuthStore,
        client_a: RegisteredClient,
        client_b: RegisteredClient,
        now: DateTime<Utc>,
        redirect_uri: Url,
    }

    fn namespace_fixture() -> Result<NamespaceFixture, StoreError> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state.db");
        let connector_a = SqliteOAuthStore::open_scoped(&database, "connector-a")?;
        let connector_b = SqliteOAuthStore::open_scoped(&database, "connector-b")?;
        let admin = SqliteOAuthStore::open(&database)?;
        let now = Utc::now();
        let redirect_uri = Url::parse("https://client.example/callback")
            .map_err(|_| StoreError::Corrupt("test redirect URL is invalid"))?;
        let client_a = RegisteredClient {
            connector_id: "connector-a".to_owned(),
            client_id: "rom_connector_a_client".to_owned(),
            client_name: "Connector A client".to_owned(),
            redirect_uris: vec![redirect_uri.clone()],
            scopes: ScopeSet::machine_read(),
            issued_at: now,
            expires_at: now + chrono::Duration::days(1),
            last_used_at: None,
            registration_source_hash: "same-source".to_owned(),
        };
        let client_b = RegisteredClient {
            connector_id: "connector-b".to_owned(),
            client_id: "rom_connector_b_client".to_owned(),
            client_name: "Connector B client".to_owned(),
            ..client_a.clone()
        };
        let limits = RegistrationLimits {
            now,
            window_seconds: 60,
            per_source_limit: 5,
            global_limit: 20,
            max_clients: 256,
        };
        assert_eq!(
            connector_a.register_client_limited(&client_a, &limits)?,
            RegistrationOutcome::Registered
        );
        assert_eq!(
            connector_b.register_client_limited(&client_b, &limits)?,
            RegistrationOutcome::Registered
        );
        Ok(NamespaceFixture {
            _directory: directory,
            connector_a,
            connector_b,
            admin,
            client_a,
            client_b,
            now,
            redirect_uri,
        })
    }

    fn authorization_fixture(
        store: &SqliteOAuthStore,
        state_hash: SecretHash,
        now: DateTime<Utc>,
    ) -> Result<RegisteredClient, StoreError> {
        let client = registered_client(
            "authorization-client",
            "authorization-source",
            now,
            now + chrono::Duration::days(1),
        );
        let limits = RegistrationLimits {
            now,
            window_seconds: 60,
            per_source_limit: 5,
            global_limit: 20,
            max_clients: 256,
        };
        assert_eq!(
            store.register_client_limited(&client, &limits)?,
            RegistrationOutcome::Registered
        );
        store.put_authorization(&PendingAuthorization {
            provider_state_hash: state_hash,
            client_id: client.client_id.clone(),
            redirect_uri: client.redirect_uris[0].clone(),
            client_state: "client-state".to_owned(),
            scopes: ScopeSet::machine_read(),
            code_challenge: "challenge-value".to_owned(),
            expires_at: now + chrono::Duration::minutes(10),
        })?;
        Ok(client)
    }

    #[test]
    fn authorization_claim_release_retry_and_completion_are_replay_safe() -> Result<(), StoreError>
    {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now();
        let state_hash = SecretHash::from_slice(&[21_u8; 32])?;
        let code_hash = SecretHash::from_slice(&[22_u8; 32])?;
        let wrong_code_hash = SecretHash::from_slice(&[23_u8; 32])?;
        let client = authorization_fixture(&store, state_hash, now)?;
        let claim = store.claim_authorization(
            &state_hash,
            &code_hash,
            Uuid::new_v4(),
            now,
            now + chrono::Duration::minutes(2),
        )?;
        assert!(matches!(
            store.claim_authorization(
                &state_hash,
                &code_hash,
                Uuid::new_v4(),
                now,
                now + chrono::Duration::minutes(2),
            ),
            Err(StoreError::InvalidGrant)
        ));
        store.release_authorization_claim(&claim, now)?;
        assert!(matches!(
            store.claim_authorization(
                &state_hash,
                &wrong_code_hash,
                Uuid::new_v4(),
                now,
                now + chrono::Duration::minutes(2),
            ),
            Err(StoreError::InvalidGrant)
        ));
        let retry_claim = store.claim_authorization(
            &state_hash,
            &code_hash,
            Uuid::new_v4(),
            now,
            now + chrono::Duration::minutes(2),
        )?;
        let consent = PendingConsent {
            id: Uuid::new_v4(),
            csrf_hash: SecretHash::from_slice(&[24_u8; 32])?,
            client_id: client.client_id,
            redirect_uri: retry_claim.pending.redirect_uri.clone(),
            client_state: retry_claim.pending.client_state.clone(),
            scopes: retry_claim.pending.scopes.clone(),
            code_challenge: retry_claim.pending.code_challenge.clone(),
            subject: "github:42".to_owned(),
            expires_at: now + chrono::Duration::minutes(5),
        };
        store.complete_authorization_claim(&retry_claim, &consent, now)?;
        assert!(matches!(
            store.claim_authorization(
                &state_hash,
                &code_hash,
                Uuid::new_v4(),
                now,
                now + chrono::Duration::minutes(2),
            ),
            Err(StoreError::NotFound)
        ));
        assert_eq!(
            store
                .take_consent(consent.id, &consent.csrf_hash, now)?
                .subject,
            "github:42"
        );
        Ok(())
    }

    #[test]
    fn stale_authorization_claim_can_be_reclaimed_only_with_the_bound_code()
    -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now();
        let state_hash = SecretHash::from_slice(&[31_u8; 32])?;
        let code_hash = SecretHash::from_slice(&[32_u8; 32])?;
        let wrong_code_hash = SecretHash::from_slice(&[33_u8; 32])?;
        authorization_fixture(&store, state_hash, now)?;
        let _claim = store.claim_authorization(
            &state_hash,
            &code_hash,
            Uuid::new_v4(),
            now,
            now + chrono::Duration::seconds(1),
        )?;
        let later = now + chrono::Duration::seconds(2);
        assert!(matches!(
            store.claim_authorization(
                &state_hash,
                &wrong_code_hash,
                Uuid::new_v4(),
                later,
                later + chrono::Duration::minutes(1),
            ),
            Err(StoreError::InvalidGrant)
        ));
        let reclaimed = store.claim_authorization(
            &state_hash,
            &code_hash,
            Uuid::new_v4(),
            later,
            later + chrono::Duration::minutes(1),
        )?;
        store.consume_authorization_claim(&reclaimed, later)?;
        Ok(())
    }

    #[test]
    fn connector_namespaces_isolate_clients_and_authorizations() -> Result<(), StoreError> {
        let fixture = namespace_fixture()?;
        assert!(
            fixture
                .connector_a
                .client(&fixture.client_a.client_id)?
                .is_some()
        );
        assert!(
            fixture
                .connector_a
                .client(&fixture.client_b.client_id)?
                .is_none()
        );
        assert!(
            fixture
                .connector_b
                .client(&fixture.client_b.client_id)?
                .is_some()
        );
        assert!(
            fixture
                .connector_b
                .client(&fixture.client_a.client_id)?
                .is_none()
        );
        let clients = fixture.admin.registered_clients()?;
        assert_eq!(clients.len(), 2);
        assert_eq!(
            clients
                .iter()
                .map(|client| client.connector_id.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            std::collections::BTreeSet::from(["connector-a", "connector-b"])
        );

        let raw_state = SecretHash::from_slice(&[7_u8; 32])?;
        for (store, client) in [
            (&fixture.connector_a, &fixture.client_a),
            (&fixture.connector_b, &fixture.client_b),
        ] {
            store.put_authorization(&PendingAuthorization {
                provider_state_hash: raw_state,
                client_id: client.client_id.clone(),
                redirect_uri: fixture.redirect_uri.clone(),
                client_state: format!("state-{}", client.connector_id),
                scopes: ScopeSet::machine_read(),
                code_challenge: "challenge-value".to_owned(),
                expires_at: fixture.now + chrono::Duration::minutes(5),
            })?;
        }
        assert_eq!(
            fixture
                .connector_a
                .claim_authorization(
                    &raw_state,
                    &SecretHash::from_slice(&[12_u8; 32])?,
                    Uuid::new_v4(),
                    fixture.now,
                    fixture.now + chrono::Duration::minutes(1),
                )?
                .pending
                .client_id,
            fixture.client_a.client_id
        );
        assert_eq!(
            fixture
                .connector_b
                .claim_authorization(
                    &raw_state,
                    &SecretHash::from_slice(&[12_u8; 32])?,
                    Uuid::new_v4(),
                    fixture.now,
                    fixture.now + chrono::Duration::minutes(1),
                )?
                .pending
                .client_id,
            fixture.client_b.client_id
        );
        Ok(())
    }

    #[test]
    fn connector_namespaces_isolate_consents() -> Result<(), StoreError> {
        let fixture = namespace_fixture()?;
        let raw_csrf = SecretHash::from_slice(&[8_u8; 32])?;
        let consent_a = Uuid::new_v4();
        let consent_b = Uuid::new_v4();
        for (store, client, id) in [
            (&fixture.connector_a, &fixture.client_a, consent_a),
            (&fixture.connector_b, &fixture.client_b, consent_b),
        ] {
            store.put_consent(&PendingConsent {
                id,
                csrf_hash: raw_csrf,
                client_id: client.client_id.clone(),
                redirect_uri: fixture.redirect_uri.clone(),
                client_state: format!("consent-{}", client.connector_id),
                scopes: ScopeSet::machine_read(),
                code_challenge: "challenge-value".to_owned(),
                subject: "github:42".to_owned(),
                expires_at: fixture.now + chrono::Duration::minutes(5),
            })?;
        }
        assert!(matches!(
            fixture
                .connector_b
                .take_consent(consent_a, &raw_csrf, fixture.now),
            Err(StoreError::NotFound)
        ));
        assert_eq!(
            fixture
                .connector_a
                .take_consent(consent_a, &raw_csrf, fixture.now)?
                .client_id,
            fixture.client_a.client_id
        );
        assert_eq!(
            fixture
                .connector_b
                .take_consent(consent_b, &raw_csrf, fixture.now)?
                .client_id,
            fixture.client_b.client_id
        );
        Ok(())
    }

    #[test]
    fn connector_namespaces_isolate_codes_tokens_sessions_and_revocation() -> Result<(), StoreError>
    {
        let fixture = namespace_fixture()?;
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(Sha256::digest(verifier.as_bytes()));
        let raw_code = SecretHash::from_slice(&[9_u8; 32])?;
        for (store, client) in [
            (&fixture.connector_a, &fixture.client_a),
            (&fixture.connector_b, &fixture.client_b),
        ] {
            store.put_authorization_code(&AuthorizationCodeGrant {
                code_hash: raw_code,
                client_id: client.client_id.clone(),
                redirect_uri: fixture.redirect_uri.clone(),
                scopes: ScopeSet::machine_read(),
                code_challenge: challenge.clone(),
                subject: "github:42".to_owned(),
                expires_at: fixture.now + chrono::Duration::minutes(5),
            })?;
        }
        let raw_access = SecretHash::from_slice(&[10_u8; 32])?;
        let tokens = TokenPairDraft {
            access_hash: raw_access,
            refresh_hash: SecretHash::from_slice(&[11_u8; 32])?,
            access_expires_at: fixture.now + chrono::Duration::minutes(15),
            refresh_expires_at: fixture.now + chrono::Duration::days(30),
        };
        for (store, client) in [
            (&fixture.connector_a, &fixture.client_a),
            (&fixture.connector_b, &fixture.client_b),
        ] {
            store.exchange_authorization_code(
                &raw_code,
                &client.client_id,
                &fixture.redirect_uri,
                verifier,
                &tokens,
                fixture.now,
            )?;
            assert_eq!(
                store
                    .access_grant(&raw_access, fixture.now)?
                    .ok_or(StoreError::NotFound)?
                    .client_id,
                client.client_id
            );
        }
        let sessions = fixture.admin.sessions(None)?;
        assert_eq!(sessions.len(), 2);
        let session_b = sessions
            .iter()
            .find(|session| session.connector_id == "connector-b")
            .ok_or(StoreError::NotFound)?;
        assert_eq!(
            fixture
                .admin
                .revoke_session_for("connector-a", session_b.family_id)?,
            0
        );

        fixture.connector_a.revoke_token(&raw_access)?;
        assert!(
            fixture
                .connector_a
                .access_grant(&raw_access, fixture.now)?
                .is_none()
        );
        assert!(
            fixture
                .connector_b
                .access_grant(&raw_access, fixture.now)?
                .is_some()
        );
        assert_eq!(
            fixture
                .admin
                .revoke_client_tokens_for("connector-a", &fixture.client_b.client_id)?,
            0
        );
        assert!(
            fixture
                .connector_b
                .access_grant(&raw_access, fixture.now)?
                .is_some()
        );
        assert!(
            !fixture
                .admin
                .delete_client_for("connector-a", &fixture.client_b.client_id)?
        );
        assert!(
            fixture
                .connector_b
                .client(&fixture.client_b.client_id)?
                .is_some()
        );
        Ok(())
    }

    #[test]
    fn oauth_beta_v1_fixture_migrates_namespace_free_state_fail_closed() -> Result<(), StoreError> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("state").join("state.db");
        std::fs::create_dir_all(database.parent().ok_or_else(|| {
            StoreError::Io(std::io::Error::other("fixture database has no parent"))
        })?)?;
        {
            let connection = Connection::open(&database)?;
            connection.execute_batch(include_str!("../tests/fixtures/oauth_beta_v1.sql"))?;
        }

        let migrated = SqliteOAuthStore::open(&database)?;
        assert!(migrated.registered_clients()?.is_empty());
        assert!(migrated.sessions(None)?.is_empty());
        let (version, registration_table_count, client_count, token_count, connector_column):
            (i64, i64, i64, i64, i64) = migrated.test_call(|connection| {
                let version = connection.query_row(
                    "SELECT version FROM schema_versions WHERE component = 'oauth'",
                    [],
                    |row| row.get(0),
                )?;
                let table_count = connection.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'oauth_registration_attempts'",
                    [],
                    |row| row.get(0),
                )?;
                let client_count = connection.query_row(
                    "SELECT COUNT(*) FROM oauth_clients",
                    [],
                    |row| row.get(0),
                )?;
                let token_count = connection.query_row(
                    "SELECT COUNT(*) FROM oauth_tokens",
                    [],
                    |row| row.get(0),
                )?;
                let connector_column = connection.query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('oauth_clients') WHERE name = 'connector_id'",
                    [],
                    |row| row.get(0),
                )?;
                Ok((
                    version,
                    table_count,
                    client_count,
                    token_count,
                    connector_column,
                ))
            })?;
        assert_eq!(version, OAUTH_SCHEMA_VERSION);
        assert_eq!(registration_table_count, 1);
        assert_eq!(client_count, 0);
        assert_eq!(token_count, 0);
        assert_eq!(connector_column, 1);
        Ok(())
    }

    #[test]
    fn expired_unused_clients_are_pruned_before_capacity_check() -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now();
        let limits = RegistrationLimits {
            now,
            window_seconds: 60,
            per_source_limit: 5,
            global_limit: 20,
            max_clients: 1,
        };
        let first = registered_client("first", "source-a", now, now + chrono::Duration::seconds(1));
        assert_eq!(
            store.register_client_limited(&first, &limits)?,
            RegistrationOutcome::Registered
        );
        let second = registered_client("second", "source-b", now, now + chrono::Duration::days(1));
        assert_eq!(
            store.register_client_limited(&second, &limits)?,
            RegistrationOutcome::CapacityReached
        );

        let later_limits = RegistrationLimits {
            now: now + chrono::Duration::seconds(2),
            ..limits
        };
        assert_eq!(
            store.register_client_limited(&second, &later_limits)?,
            RegistrationOutcome::Registered
        );
        let clients = store.registered_clients()?;
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].client_id, "second");
        Ok(())
    }

    #[test]
    fn touching_a_client_records_use_and_extends_expiry() -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now();
        let initial_expiry = now + chrono::Duration::hours(1);
        let extended_expiry = now + chrono::Duration::days(90);
        let client = registered_client("client", "source", now, initial_expiry);
        let limits = RegistrationLimits {
            now,
            window_seconds: 60,
            per_source_limit: 5,
            global_limit: 20,
            max_clients: 256,
        };
        assert_eq!(
            store.register_client_limited(&client, &limits)?,
            RegistrationOutcome::Registered
        );
        let touched_at =
            DateTime::from_timestamp((now + chrono::Duration::minutes(10)).timestamp(), 0)
                .ok_or(StoreError::Corrupt("test timestamp is invalid"))?;
        let extended_expiry = DateTime::from_timestamp(extended_expiry.timestamp(), 0)
            .ok_or(StoreError::Corrupt("test timestamp is invalid"))?;
        assert!(store.touch_client("client", touched_at, extended_expiry)?);
        let clients = store.registered_clients()?;
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].last_used_at, Some(touched_at));
        assert_eq!(clients[0].expires_at, extended_expiry);
        Ok(())
    }

    #[test]
    fn oauth_schema_version_is_recorded_and_future_versions_are_rejected() -> Result<(), StoreError>
    {
        let store = SqliteOAuthStore::in_memory()?;
        let version: i64 = store.test_call(|connection| {
            connection
                .query_row(
                    "SELECT version FROM schema_versions WHERE component = 'oauth'",
                    [],
                    |row| row.get(0),
                )
                .map_err(Into::into)
        })?;
        assert_eq!(version, OAUTH_SCHEMA_VERSION);
        let connection = Connection::open_in_memory()?;
        connection.execute_batch(
            "CREATE TABLE schema_versions (component TEXT PRIMARY KEY, version INTEGER NOT NULL); INSERT INTO schema_versions(component, version) VALUES ('oauth', 999);",
        )?;
        assert!(
            SqliteOAuthStore::from_connection(connection, Some(TEST_CONNECTOR_ID.to_owned()),)
                .is_err()
        );
        Ok(())
    }
}
