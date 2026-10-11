## Summary

- What changed and why?

## Security impact

- [ ] No new capability, network surface, secret handling, process execution, or privilege boundary.
- [ ] Security-sensitive changes are described below and include negative tests.

## Verification

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked`
- [ ] Dependency and secret scans pass.
- [ ] Platform-specific behavior was tested or explicitly marked as unverified.

## Release impact

- [ ] Documentation and changelog updated.
- [ ] Install, restart, rollback, and uninstall implications reviewed.
