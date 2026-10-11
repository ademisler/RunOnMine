BEGIN;
CREATE TABLE schema_versions (
    component TEXT PRIMARY KEY,
    version INTEGER NOT NULL CHECK (version >= 0)
);
INSERT INTO schema_versions(component, version) VALUES ('oauth', 1);

CREATE TABLE oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    scopes TEXT NOT NULL,
    issued_at INTEGER NOT NULL
);
CREATE TABLE oauth_authorizations (
    provider_state_hash BLOB PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    client_state TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE TABLE oauth_consents (
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
CREATE TABLE oauth_codes (
    code_hash BLOB PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    subject TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0 CHECK (used IN (0, 1))
);
CREATE TABLE oauth_tokens (
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
CREATE INDEX oauth_tokens_family_idx ON oauth_tokens(family_id);
CREATE INDEX oauth_tokens_expiry_idx ON oauth_tokens(expires_at);

INSERT INTO oauth_clients (
    client_id, client_name, redirect_uris, scopes, issued_at
) VALUES (
    'beta-client',
    'Beta Client',
    '["https://client.example/callback"]',
    'machine:read files:write',
    1700000000
);
INSERT INTO oauth_tokens (
    token_hash, token_kind, family_id, client_id, subject, scopes,
    issued_at, expires_at, status
) VALUES (
    X'0101010101010101010101010101010101010101010101010101010101010101',
    'access',
    '22222222-2222-4222-8222-222222222222',
    'beta-client',
    'github:42',
    'machine:read files:write',
    1700000000,
    4102444800,
    'active'
);
INSERT INTO oauth_tokens (
    token_hash, token_kind, family_id, client_id, subject, scopes,
    issued_at, expires_at, status
) VALUES (
    X'0202020202020202020202020202020202020202020202020202020202020202',
    'refresh',
    '22222222-2222-4222-8222-222222222222',
    'beta-client',
    'github:42',
    'machine:read files:write',
    1700000000,
    4102444800,
    'active'
);
COMMIT;
