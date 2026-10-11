# Audit integrity and trust boundary

RunOnMine stores audit events in the core state SQLite database. The audit layer
has three complementary integrity mechanisms:

1. each canonical serialized `AuditEvent` is linked to the previous BLAKE3
   record hash;
2. each record receives HMAC-SHA256 over its sequence, previous hash, record
   hash and canonical payload;
3. the chain-state row authenticates the current tail sequence, record hash and
   record MAC with a separate keyed tail MAC.

The 256-bit MAC key is generated once per state database and stored beside it as
`<state-db>.audit-key`. Creation is exclusive, final-component symlinks are
rejected, the key has a fixed 32-byte representation, and Unix permissions must
be owner-only. Losing or replacing the key makes existing records unverifiable;
the application does not silently re-MAC a version-3 database.

## Verification

Verification performs both the original BLAKE3 chain walk and the keyed checks.
It also deserializes every canonical payload and compares all duplicated SQLite
columns—event ID, timestamp, connector, tool, capability, outcome, argument
hash, summary, duration and output size—with that payload. Modifying an indexed
column without changing the payload therefore fails, as does changing a payload,
record MAC or chain link.

Tail state prevents simply deleting the newest rows while leaving an otherwise
valid prefix. Version-1 and version-2 databases are trusted once during their
version-3 migration and receive MACs for their existing history. After the
schema reaches version 3, missing MAC columns are corruption and reopen never
backfills or advances the authenticated tail.

## What this does and does not protect

This design detects accidental corruption and database-only offline edits by an
actor who does not possess the separate MAC key. It materially strengthens the
old unkeyed hash chain, where anyone able to rewrite SQLite could recalculate all
hashes.

It is **not an immutable external audit service**. A process running as the same
OS user may be able to read both the database and its owner-only key, recompute
MACs, or restore a complete older snapshot containing a previously valid state.
Root/SYSTEM and kernel compromise are also out of scope. Strong resistance to
those actors requires exporting signed checkpoints or events to a separately
administered append-only destination with an independent key and monotonic
retention policy.
