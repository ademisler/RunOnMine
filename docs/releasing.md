# Release Process

The first candidate version is `0.1.0-beta.1`. Repository visibility is a
separate owner decision and is never changed by CI.

## Required gates

Before creating a tag:

1. run `cargo run --locked -p xtask -- verify` without skipping the secret scan;
2. keep headless line coverage at or above the enforced baseline and review the latest scheduled fuzz run;
3. pass macOS arm64/x86_64, Linux x86_64/aarch64 headless, and Windows x86_64 builds;
4. complete install, restart, connect, tool-call, lock, and uninstall acceptance on a Mac, clean Linux VPS, and Windows VM;
5. confirm no MacMCP service, file, or port was changed;
6. record evidence in `acceptance/release-gates.toml` and pass `cargo run --locked -p xtask -- release-readiness --profile private-beta`;
7. present remaining risks and the secret-scan result to the repository owner.

The release workflow independently runs the private-beta readiness command and
stops before packaging while any required gate is `pending` or `blocked`. Public
beta also requires signing/notarization and protected-main gates. See
[release acceptance](acceptance.md).

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

`CI` runs one consolidated Linux quality job on the hardened self-hosted runner. It executes `xtask verify --headless` (formatting, version consistency, headless Clippy/tests, both dependency audits, dependency policy, and the complete-history Gitleaks scan), the desktop crate's no-UI contract, and the enforced coverage baseline in one checkout. The job uses an ephemeral Cargo target directory and removes it even after failure, avoiding repeated clean builds and stale runner disk growth. Independent `Security` and `Coverage` workflows remain available for manual dispatch and scheduled sweeps.

`Platform CI` is separate from the self-hosted quality path. The full desktop-enabled macOS/Windows and ARM headless matrix runs for manual dispatches, or on pull requests when the repository variable `ENABLE_GITHUB_HOSTED_PLATFORM_CI` is set to `true`. This guard prevents account billing or spending-limit failures from appearing as product failures while keeping the full matrix ready to enable without changing workflow code. Linux desktop UI dependencies are intentionally not part of the product's headless Linux target.

## Local packaging helpers

```console
cargo run --locked -p xtask -- verify
cargo run --locked -p xtask -- release-readiness --profile private-beta
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
