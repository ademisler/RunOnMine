# Testing


## CI platform and coverage contracts

Relevant pull requests run the macOS, Windows and ARM platform jobs directly;
there is no repository variable that silently skips them. Workflows install the
exact Rust toolchain through `scripts/ci/install-rust-toolchain.sh`, which pins
components and targets with `rustup` rather than relying on unsupported action
inputs.

Coverage is a ratchet, not a fabricated target claim. `coverage.yml` produces
LCOV and `scripts/ci/check-lcov.py` currently requires at least 50% globally,
70% in policy/auth/storage/approval-critical modules, and 80% of changed
executable lines on pull requests. These thresholds must rise as measured
coverage improves toward the roadmap's 70% global and 90% critical goals.

## Fuzzing and concurrency

Nightly fuzz targets cover TOML config, filesystem resolution, policy,
redaction, OAuth request models, restricted browser URLs, and privileged-helper
request frames. MCP HTTP health publishes a fresh process epoch and documents
that sessions and rate-limit buckets reset after restart. OAuth dynamic client
registration is limited both globally and per registration source. A
64-concurrent-call test exercises atomic rate-limit admission on every normal
quality run.
