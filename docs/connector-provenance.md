# Connector release provenance

RunOnMine treats GitHub as an HTTPS distribution channel, not as the authority
for deciding which `cloudflared` or OpenAI `tunnel-client` bytes are trusted.
Managed setup and update use signed catalogs compiled into the application.

## Verification model

Each catalog is a versioned JSON envelope containing a base64-encoded manifest
payload and Ed25519 signatures. Verification is fail-closed and bounded before
any artifact download.

A catalog must have two independent valid signatures:

- the shared RunOnMine security root;
- the provider-specific Cloudflare or OpenAI catalog root.

Repeating one signature does not satisfy the threshold. Unknown signatures may
coexist for rotation, but they do not count. A Cloudflare provider key cannot
authorize an OpenAI catalog and vice versa.

The signed payload binds:

- manifest format version and positive sequence;
- provider and exact official GitHub repository;
- a lowercase 40-character source commit;
- release tag;
- exact asset name and HTTPS release URL;
- SHA-256 digest and byte size;
- raw/archive format and the only permitted executable basename.

The runtime chooses only the current platform's expected asset from this signed
payload. The downloaded bytes must still match the signed size and digest, and
archive extraction retains the existing traversal, symlink and ambiguity checks.
Compatibility probing runs before activation.

## Receipts and migration

New managed installation receipts retain the signed envelope. Every later
managed-binary resolution re-verifies the signatures and checks that the receipt
release tag and digest still match the signed platform artifact before verifying
the executable itself.

Receipts created by earlier beta builds have no envelope. They remain readable
as legacy digest-only receipts so an existing installation is not destroyed or
silently replaced. The next explicit managed update writes signed evidence.
Doctor and support output must never include private signing material.

## Catalog update procedure

1. Independently review the upstream release, source tag and resolved commit.
2. Record only supported platform assets and verify their official digest, size,
   URL and archive layout.
3. Increase the manifest sequence and serialize the payload without adding
   credentials or local machine data.
4. Sign the exact payload bytes with the shared security key and the applicable
   provider key under separate custody.
5. Replace the envelope under `crates/runonmine-connectors/provenance/` and run
   the complete verification and CLI acceptance gates.
6. Review the diff of the decoded payload, source commit and every asset before
   merging.

Private keys are never committed, embedded, printed by tooling, or stored in
GitHub Actions. The repository contains only public verification roots and
signed envelopes. Production key custody should be separated from the build
runner and backed up using an owner-controlled offline process.

## Rotation and compromise

A planned rotation first ships an application version that trusts the old and
new public roots while existing catalogs still meet the threshold. A subsequent
catalog can add the new signature, after which a later application release can
remove the retired key. A suspected compromise requires an application update
that removes the affected root and publishes a catalog signed by the remaining
approved independent roots. Lowering the threshold or accepting unsigned live
metadata is not a recovery mechanism.
