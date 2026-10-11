BEGIN;
CREATE TABLE approvals (
    id TEXT PRIMARY KEY,
    connector_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    argument_summary TEXT NOT NULL,
    argument_hash TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    resolved_at TEXT,
    decision TEXT
);
INSERT INTO approvals (
    id, connector_id, tool_name, argument_summary, argument_hash,
    status, created_at, expires_at, resolved_at, decision
) VALUES (
    '11111111-1111-4111-8111-111111111111',
    'beta-local',
    'fs_write',
    'Path: /tmp/beta.txt',
    'approval-hash-v0',
    'pending',
    '2026-01-02T03:04:05+00:00',
    '2100-01-02T03:04:05+00:00',
    NULL,
    NULL
);

-- Beta v0 temporary grants were tool-wide and had no argument hash.
CREATE TABLE temporary_grants (
    connector_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (connector_id, tool_name)
);
INSERT INTO temporary_grants (connector_id, tool_name, expires_at)
VALUES ('beta-local', 'shell_exec', '2100-01-02T03:04:05+00:00');

CREATE TABLE persistent_grants (
    connector_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    argument_hash TEXT NOT NULL,
    argument_summary TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (connector_id, tool_name, argument_hash)
);
INSERT INTO persistent_grants (
    connector_id, tool_name, argument_hash, argument_summary, created_at
) VALUES (
    'beta-local',
    'fs_write',
    'persistent-hash-v0',
    'Path: /tmp/persisted.txt',
    '2026-01-02T03:04:05+00:00'
);
COMMIT;
