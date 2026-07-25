# Release Process

The first candidate version is `0.1.0-beta.1`. Repository visibility is a
separate owner decision and is never changed by CI.

## Required gates

Before creating a tag:

1. run formatting, `xtask verify-versions`, Clippy with warnings denied, and the complete test suite;
2. run `cargo audit --deny warnings`, `cargo deny check`, and a full-history secret scan;
3. pass macOS arm64/x86_64, Linux x86_64/aarch64 headless, and Windows x86_64 builds;
4. complete install, restart, connect, tool-call, and uninstall acceptance on a Mac, clean Linux VPS, and Windows VM;
5. confirm no MacMCP service, file, or port was changed;
6. present remaining risks and the secret-scan result to the repository owner.

The tag must exactly match the Cargo version:

```console
v0.1.0-beta.1
```

## Artifacts

The tag workflow uses pinned versions of `cargo-dist` and `cargo-packager`.
It produces:

- cargo-dist portable archives for supported target triples;
- a universal macOS DMG;
- Linux x86_64 and aarch64 DEB packages;
- a Windows x86_64 NSIS installer;
- combined unsigned portable archives with an exact target-specific binary manifest;
- CycloneDX JSON SBOMs containing component references, dependency edges, Cargo.lock package checksums where available, and the Cargo.lock integrity hash;
- SHA-256 files for release artifacts.

The workflow opens a draft prerelease only. Artifacts are deliberately unsigned and must not be described as signed, notarized, or trusted by the operating system. Signing and notarization require external publisher credentials and a separate owner decision; CI cannot manufacture those credentials. Publishing the draft and making the repository public both require separate owner approval.

## Hosted platform validation

`Platform CI` always runs its Linux platform contract on the hardened self-hosted runner. The GitHub-hosted macOS, Windows, and ARM matrix runs for manual dispatches, or automatically when the repository variable `ENABLE_GITHUB_HOSTED_PLATFORM_CI` is set to `true`. This guard prevents account billing or spending-limit failures from appearing as product failures while keeping the full matrix ready to enable without changing workflow code.

## Local packaging helpers

```console
cargo run --locked -p xtask -- verify-versions
cargo run --locked -p xtask -- sync-versions
cargo run -p xtask -- package --target <rust-target>
cargo run -p xtask -- stage-packager --target <rust-target>
cargo run -p xtask -- checksums
```

On macOS, after building both architectures:

```console
cargo run -p xtask -- universal-macos
```

The packaging helpers accept only validated target names and operate below the
workspace `target` and `dist` directories.

## Uninstall acceptance

`runonmine uninstall` removes the per-user service and preserves configuration,
state, profiles, logs, and credentials. Permanent removal requires the separate
confirmation phrase:

```console
runonmine uninstall --purge --confirm PURGE
```

The optional privileged helper and Linux system service have separate elevated
uninstall commands and are never silently removed by a per-user purge.
