# RunOnMine OAuth

This crate contains the embedded OAuth 2.1 authorization server used by the
recommended Cloudflare Named Tunnel connection mode.

Security properties:

- RFC 8414 authorization-server metadata and RFC 9728 protected-resource metadata.
- Public dynamic clients with exact redirect URI matching and mandatory PKCE S256.
- Separate one-time state for GitHub owner authentication and a separate one-time CSRF token for consent.
- GitHub identity is revalidated on every authorization flow against only the immutable numeric user ID; login is bounded display metadata and safe same-ID renames can be reconciled separately.
- Opaque 256-bit authorization codes and tokens. Only keyed, domain-separated hashes are persisted.
- 15-minute access tokens and rotating 30-day refresh tokens with family-wide reuse revocation.
- Token scopes are always intersected with current local policy; a token cannot expand local permissions.
- RFC 7009-style idempotent revocation.

The public issuer must use HTTPS. TLS is expected to terminate at Cloudflare;
the RunOnMine process itself must remain bound to loopback. The GitHub client
secret and the 32-byte token-hashing key must come from the platform credential
store, never from `config.toml` or the SQLite database.

References: [RFC 8414](https://www.rfc-editor.org/rfc/rfc8414),
[RFC 9728](https://www.rfc-editor.org/rfc/rfc9728),
[RFC 7591](https://www.rfc-editor.org/rfc/rfc7591),
[RFC 7636](https://www.rfc-editor.org/rfc/rfc7636), and
[RFC 7009](https://www.rfc-editor.org/rfc/rfc7009).

