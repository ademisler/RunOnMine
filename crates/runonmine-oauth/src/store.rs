use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use url::Url;
use uuid::Uuid;

use crate::crypto::verify_pkce;
use crate::model::{
    AccessGrant, AuthorizationCodeGrant, OAuthSession, PendingAuthorization, PendingConsent,
    RegisteredClient, RegistrationLimits, RegistrationOutcome, TokenGrant, TokenPairDraft,
};
use crate::{ScopeSet, SecretHash, StoreError};

const OAUTH_SCHEMA_VERSION: i64 = 3;
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
    fn take_authorization(
        &self,
        state_hash: &SecretHash,
        now: DateTime<Utc>,
    ) -> Result<PendingAuthorization, StoreError>;
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

pub struct SqliteOAuthStore {
    worker: Arc<SqliteWorker>,
}

impl std::fmt::Debug for SqliteOAuthStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SqliteOAuthStore")
            .finish_non_exhaustive()
    }
}

impl SqliteOAuthStore {
    pub fn open(path: &Path) -> Result<Self, StoreError> {
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
        let store = Self::from_connection(connection)?;
        restrict_database_files(path)?;
        Ok(store)
    }

    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory()?)
    }

    fn from_connection(mut connection: Connection) -> Result<Self, StoreError> {
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
        migrate_oauth_schema(&mut connection)?;
        connection.execute(
            "INSERT INTO schema_versions(component, version) VALUES ('oauth', ?1)
             ON CONFLICT(component) DO UPDATE SET version = excluded.version",
            [OAUTH_SCHEMA_VERSION],
        )?;
        cleanup_expired_connection(&mut connection, Utc::now())?;
        Ok(Self {
            worker: Arc::new(SqliteWorker::start(connection)?),
        })
    }

    pub fn registered_clients(&self) -> Result<Vec<RegisteredClient>, StoreError> {
        self.call(registered_clients_connection)
    }

    pub fn revoke_client_tokens(&self, client_id: &str) -> Result<usize, StoreError> {
        let client_id = client_id.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "UPDATE oauth_tokens SET status = 'revoked' WHERE client_id = ?1 AND status = 'active'",
                [client_id],
            )?)
        })
    }

    pub fn delete_client(&self, client_id: &str) -> Result<bool, StoreError> {
        let client_id = client_id.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "DELETE FROM oauth_clients WHERE client_id = ?1",
                [client_id],
            )? == 1)
        })
    }

    pub fn sessions(&self, client_id: Option<&str>) -> Result<Vec<OAuthSession>, StoreError> {
        let client_id = client_id.map(str::to_owned);
        self.call(move |connection| sessions_connection(connection, client_id.as_deref()))
    }

    pub fn revoke_session(&self, family_id: Uuid) -> Result<usize, StoreError> {
        self.call(move |connection| {
            Ok(connection.execute(
                "UPDATE oauth_tokens SET status = 'revoked' WHERE family_id = ?1 AND status = 'active'",
                [family_id.to_string()],
            )?)
        })
    }

    pub fn emergency_revoke_all(&self) -> Result<usize, StoreError> {
        self.call(|connection| {
            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM oauth_authorizations", [])?;
            transaction.execute("DELETE FROM oauth_consents", [])?;
            transaction.execute("DELETE FROM oauth_codes", [])?;
            let revoked = transaction.execute(
                "UPDATE oauth_tokens SET status = 'revoked' WHERE status = 'active'",
                [],
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

fn migrate_oauth_schema(connection: &mut Connection) -> Result<(), StoreError> {
    let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    migrate_registration_attempts(&transaction)?;
    migrate_registered_clients(&transaction)?;
    create_oauth_tables(&transaction)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_registration_attempts(connection: &Connection) -> Result<(), StoreError> {
    if table_exists(connection, "oauth_registration_attempts")?
        && !table_has_column(connection, "oauth_registration_attempts", "source_key")?
    {
        // Historical global attempts contain no caller identity and are not
        // useful for the source-partitioned limiter.
        connection.execute("DROP TABLE oauth_registration_attempts", [])?;
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
            source_key TEXT NOT NULL,
            attempted_at INTEGER NOT NULL
         );
         CREATE INDEX IF NOT EXISTS oauth_registration_attempts_time_idx
            ON oauth_registration_attempts(attempted_at);
         CREATE INDEX IF NOT EXISTS oauth_registration_attempts_source_time_idx
            ON oauth_registration_attempts(source_key, attempted_at);
         CREATE TABLE IF NOT EXISTS oauth_clients (
            client_id TEXT PRIMARY KEY,
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
         CREATE TABLE IF NOT EXISTS oauth_authorizations (
            provider_state_hash BLOB PRIMARY KEY,
            client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
            redirect_uri TEXT NOT NULL,
            client_state TEXT NOT NULL,
            scopes TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            expires_at INTEGER NOT NULL
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

fn prune_expired_clients(connection: &Connection, now: DateTime<Utc>) -> Result<usize, StoreError> {
    Ok(connection.execute(
        "DELETE FROM oauth_clients
         WHERE expires_at <= ?1
           AND NOT EXISTS (
             SELECT 1 FROM oauth_tokens
             WHERE oauth_tokens.client_id = oauth_clients.client_id
               AND oauth_tokens.status = 'active'
               AND oauth_tokens.expires_at > ?1
           )",
        [now.timestamp()],
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
            let global_count = transaction.query_row(
                "SELECT COUNT(*) FROM oauth_registration_attempts",
                [],
                |row| row.get::<_, i64>(0),
            )?;
            let source_count = transaction.query_row(
                "SELECT COUNT(*) FROM oauth_registration_attempts WHERE source_key = ?1",
                [&client.registration_source_hash],
                |row| row.get::<_, i64>(0),
            )?;
            if global_count >= limit_as_i64(limits.global_limit)?
                || source_count >= limit_as_i64(limits.per_source_limit)?
            {
                transaction.commit()?;
                return Ok(RegistrationOutcome::RateLimited);
            }
            prune_expired_clients(&transaction, limits.now)?;
            let client_count =
                transaction.query_row("SELECT COUNT(*) FROM oauth_clients", [], |row| {
                    row.get::<_, i64>(0)
                })?;
            if client_count >= limit_as_i64(limits.max_clients)? {
                transaction.commit()?;
                return Ok(RegistrationOutcome::CapacityReached);
            }
            let redirects = serde_json::to_string(&client.redirect_uris)
                .map_err(|_| StoreError::Corrupt("client redirect URI serialization failed"))?;
            transaction.execute(
                "INSERT INTO oauth_registration_attempts (source_key, attempted_at)
                 VALUES (?1, ?2)",
                params![client.registration_source_hash, limits.now.timestamp()],
            )?;
            transaction.execute(
                "INSERT INTO oauth_clients (
                    client_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    client.client_id,
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
        let client_id = client_id.to_owned();
        self.call(move |connection| client_connection(connection, &client_id))
    }

    fn touch_client(
        &self,
        client_id: &str,
        now: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<bool, StoreError> {
        let client_id = client_id.to_owned();
        self.call(move |connection| {
            Ok(connection.execute(
                "UPDATE oauth_clients
                 SET last_used_at = ?1,
                     expires_at = CASE WHEN expires_at < ?2 THEN ?2 ELSE expires_at END
                 WHERE client_id = ?3 AND expires_at > ?1",
                params![now.timestamp(), expires_at.timestamp(), client_id],
            )? == 1)
        })
    }

    fn put_authorization(&self, pending: &PendingAuthorization) -> Result<(), StoreError> {
        let pending = pending.clone();
        self.call(move |connection| {
            connection.execute(
                "INSERT INTO oauth_authorizations (provider_state_hash, client_id, redirect_uri, client_state, scopes, code_challenge, expires_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![pending.provider_state_hash.as_bytes().as_slice(), pending.client_id, pending.redirect_uri.as_str(), pending.client_state, pending.scopes.to_space_delimited(), pending.code_challenge, pending.expires_at.timestamp()],
            )?;
            Ok(())
        })
    }

    fn take_authorization(
        &self,
        state_hash: &SecretHash,
        now: DateTime<Utc>,
    ) -> Result<PendingAuthorization, StoreError> {
        let state_hash = *state_hash;
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM oauth_authorizations WHERE expires_at <= ?1", [now.timestamp()])?;
            let pending = transaction.query_row(
                "SELECT client_id, redirect_uri, client_state, scopes, code_challenge, expires_at FROM oauth_authorizations WHERE provider_state_hash = ?1",
                [state_hash.as_bytes().as_slice()], map_authorization,
            ).optional()?.ok_or(StoreError::NotFound)?;
            transaction.execute("DELETE FROM oauth_authorizations WHERE provider_state_hash = ?1", [state_hash.as_bytes().as_slice()])?;
            transaction.commit()?;
            Ok(PendingAuthorization { provider_state_hash: state_hash, ..pending })
        })
    }

    fn put_consent(&self, pending: &PendingConsent) -> Result<(), StoreError> {
        let pending = pending.clone();
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
        let csrf_hash = *csrf_hash;
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            transaction.execute("DELETE FROM oauth_consents WHERE expires_at <= ?1", [now.timestamp()])?;
            let consent = transaction.query_row(
                "SELECT client_id, redirect_uri, client_state, scopes, code_challenge, subject, expires_at FROM oauth_consents WHERE id = ?1 AND csrf_hash = ?2",
                params![id.to_string(), csrf_hash.as_bytes().as_slice()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, String>(5)?, row.get::<_, i64>(6)?)),
            ).optional()?.ok_or(StoreError::NotFound)?;
            transaction.execute("DELETE FROM oauth_consents WHERE id = ?1", [id.to_string()])?;
            transaction.commit()?;
            Ok(PendingConsent { id, csrf_hash, client_id: consent.0, redirect_uri: parse_url(&consent.1)?, client_state: consent.2, scopes: parse_scopes(&consent.3)?, code_challenge: consent.4, subject: consent.5, expires_at: from_timestamp(consent.6)? })
        })
    }

    fn put_authorization_code(&self, code: &AuthorizationCodeGrant) -> Result<(), StoreError> {
        let code = code.clone();
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
        let code_hash = *code_hash;
        let client_id = client_id.to_owned();
        let redirect_uri = redirect_uri.clone();
        let verifier = verifier.to_owned();
        let tokens = tokens.clone();
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
        let refresh_hash = *refresh_hash;
        let client_id = client_id.to_owned();
        let requested_scopes = requested_scopes.cloned();
        let tokens = tokens.clone();
        self.call(move |connection| {
            let transaction = connection.transaction()?;
            let row = transaction.query_row(
                "SELECT token_kind, family_id, client_id, subject, scopes, expires_at, status FROM oauth_tokens WHERE token_hash = ?1",
                [refresh_hash.as_bytes().as_slice()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, String>(6)?)),
            ).optional()?.ok_or(StoreError::InvalidGrant)?;
            if row.0 != "refresh" || row.2 != client_id || row.5 <= now.timestamp() { return Err(StoreError::InvalidGrant); }
            if row.6 != "active" {
                transaction.execute("UPDATE oauth_tokens SET status = 'revoked' WHERE family_id = ?1", [&row.1])?;
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
        let token_hash = *token_hash;
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
                        "UPDATE oauth_tokens SET status = 'revoked' WHERE family_id = ?1",
                        [family],
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
        let token_hash = *token_hash;
        self.call(move |connection| {
            let row = connection.query_row(
                "SELECT client_id, subject, scopes, expires_at FROM oauth_tokens WHERE token_hash = ?1 AND token_kind = 'access' AND status = 'active' AND expires_at > ?2",
                params![token_hash.as_bytes().as_slice(), now.timestamp()],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?)),
            ).optional()?;
            row.map(|(client_id, subject, scopes, expires_at)| Ok(AccessGrant { client_id, subject, scopes: parse_scopes(&scopes)?, expires_at: from_timestamp(expires_at)? })).transpose()
        })
    }
}

fn registered_clients_connection(
    connection: &mut Connection,
) -> Result<Vec<RegisteredClient>, StoreError> {
    prune_expired_clients(connection, Utc::now())?;
    let mut statement = connection.prepare(
        "SELECT client_id, client_name, redirect_uris, scopes, issued_at,
                expires_at, last_used_at, registration_source_hash
         FROM oauth_clients
         ORDER BY issued_at DESC, client_id ASC",
    )?;
    let rows = statement.query_map([], map_registered_client_row)?;
    rows.map(|row| decode_registered_client(row?)).collect()
}

fn client_connection(
    connection: &mut Connection,
    client_id: &str,
) -> Result<Option<RegisteredClient>, StoreError> {
    let now = Utc::now();
    prune_expired_clients(connection, now)?;
    connection
        .query_row(
            "SELECT client_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
             FROM oauth_clients
             WHERE client_id = ?1 AND expires_at > ?2",
            params![client_id, now.timestamp()],
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
    ))
}

fn decode_registered_client(row: RegisteredClientRow) -> Result<RegisteredClient, StoreError> {
    Ok(RegisteredClient {
        client_id: row.0,
        client_name: row.1,
        redirect_uris: serde_json::from_str(&row.2)
            .map_err(|_| StoreError::Corrupt("invalid registered redirect URI"))?,
        scopes: parse_scopes(&row.3)?,
        issued_at: from_timestamp(row.4)?,
        expires_at: from_timestamp(row.5)?,
        last_used_at: row.6.map(from_timestamp).transpose()?,
        registration_source_hash: row.7,
    })
}

fn sessions_connection(
    connection: &mut Connection,
    client_id: Option<&str>,
) -> Result<Vec<OAuthSession>, StoreError> {
    let mut statement = connection.prepare("SELECT family_id, client_id, subject, scopes, MIN(issued_at), MAX(expires_at), MAX(CASE WHEN status = 'active' AND expires_at > ?1 THEN 1 ELSE 0 END) FROM oauth_tokens WHERE (?2 IS NULL OR client_id = ?2) GROUP BY family_id, client_id, subject, scopes ORDER BY MAX(issued_at) DESC, family_id ASC")?;
    let rows = statement.query_map(params![Utc::now().timestamp(), client_id], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, i64>(5)?,
            row.get::<_, bool>(6)?,
        ))
    })?;
    rows.map(|row| {
        let (family_id, client_id, subject, scopes, issued_at, expires_at, active) = row?;
        Ok(OAuthSession {
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
    removed += prune_expired_clients(&transaction, now)?;
    transaction.commit()?;
    Ok(removed)
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
    use super::*;

    fn registered_client(
        client_id: &str,
        source: &str,
        issued_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> RegisteredClient {
        RegisteredClient {
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
    fn emergency_revoke_removes_pending_flows_and_revokes_tokens() -> Result<(), StoreError> {
        let store = SqliteOAuthStore::in_memory()?;
        let now = Utc::now().timestamp();
        store.test_call(move |connection| {
            connection.execute(
                "INSERT INTO oauth_clients (
                    client_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES ('client', 'Client', '[]', 'machine:read', ?1, ?2, NULL, 'test')",
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
                    client_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES ('client', 'Client', '[]', 'machine:read', ?1, ?2, NULL, 'test')",
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
                    client_id, client_name, redirect_uris, scopes, issued_at,
                    expires_at, last_used_at, registration_source_hash
                 ) VALUES ('client', 'Client', '["https://client.example/callback"]',
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
        assert_eq!(clients[0].client_id, "client");
        let sessions = store.sessions(Some("client"))?;
        assert_eq!(sessions.len(), 1);
        assert!(sessions[0].active);
        assert_eq!(store.revoke_session(family)?, 2);
        assert!(!store.sessions(Some("client"))?[0].active);
        assert_eq!(store.revoke_client_tokens("client")?, 0);
        assert!(store.delete_client("client")?);
        assert!(store.registered_clients()?.is_empty());
        Ok(())
    }

    #[test]
    fn oauth_beta_v1_fixture_migrates_without_losing_clients_or_sessions() -> Result<(), StoreError>
    {
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
        let clients = migrated.registered_clients()?;
        assert_eq!(clients.len(), 1);
        assert_eq!(clients[0].client_id, "beta-client");
        assert_eq!(clients[0].client_name, "Beta Client");
        assert_eq!(
            clients[0].scopes.to_space_delimited(),
            "machine:read files:write"
        );
        assert_eq!(
            clients[0].redirect_uris,
            vec![
                Url::parse("https://client.example/callback")
                    .map_err(|_| { StoreError::Corrupt("test fixture redirect URL is invalid") })?
            ]
        );

        let sessions = migrated.sessions(Some("beta-client"))?;
        assert_eq!(sessions.len(), 1);
        assert_eq!(
            sessions[0].family_id,
            Uuid::parse_str("22222222-2222-4222-8222-222222222222")
                .map_err(|_| StoreError::Corrupt("test fixture family ID is invalid"))?
        );
        assert_eq!(sessions[0].subject, "github:42");
        assert_eq!(
            sessions[0].scopes.to_space_delimited(),
            "machine:read files:write"
        );
        assert!(sessions[0].active);

        let (version, registration_table_count, token_count): (i64, i64, i64) =
            migrated.test_call(|connection| {
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
                let token_count = connection.query_row(
                    "SELECT COUNT(*) FROM oauth_tokens WHERE client_id = 'beta-client'",
                    [],
                    |row| row.get(0),
                )?;
                Ok((version, table_count, token_count))
            })?;
        assert_eq!(version, OAUTH_SCHEMA_VERSION);
        assert_eq!(registration_table_count, 1);
        assert_eq!(token_count, 2);
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
        assert!(SqliteOAuthStore::from_connection(connection).is_err());
        Ok(())
    }
}
