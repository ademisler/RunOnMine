# Release Process

The first candidate version is `0.1.0-beta.1`. Repository visibility is a
separate owner decision and is never changed by CI.

## Required gates

Before creating a tag:

1. run `cargo run --locked -p xtask -- verify` without skipping the secret scan;
2. keep headless line coverage at or above the enforced baseline and review the latest scheduled fuzz run;
3. pass macOS arm64/x86_64, Linux x86_64/aarch64 headless, Linux x86_64 desktop, and Windows x86_64 builds;
4. complete install, restart, connect, tool-call, lock, and uninstall acceptance on a Mac, clean Linux VPS, clean Linux desktop, and Windows VM;
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
- Linux x86_64 and aarch64 headless DEB packages;
- a standalone Linux x86_64 desktop DEB containing all four binaries;
- a Windows x86_64 NSIS installer;
- combined unsigned portable archives with an exact target-specific binary manifest;
- CycloneDX JSON SBOMs containing component references, dependency edges, Cargo.lock package checksums where available, and the Cargo.lock integrity hash;
- SHA-256 files for release artifacts.

The workflow opens a draft prerelease only. Artifacts are deliberately unsigned and must not be described as signed, notarized, or trusted by the operating system. Signing and notarization require external publisher credentials and a separate owner decision; CI cannot manufacture those credentials. Publishing the draft and making the repository public both require separate owner approval.

## Hosted platform validation

`CI` runs one consolidated Linux quality job on the hardened self-hosted runner. It executes `xtask verify --headless` (formatting, version consistency, headless Clippy/tests, both dependency audits, dependency policy, and the complete-history Gitleaks scan), the desktop crate's no-UI contract, and the enforced coverage baseline in one checkout. The job uses an ephemeral Cargo target directory and removes it even after failure, avoiding repeated clean builds and stale runner disk growth. Independent `Security` and `Coverage` workflows remain available for manual dispatch and scheduled sweeps.

`Platform CI` is separate from the self-hosted quality path. Its macOS
arm64/x86_64, Windows x86_64, and Linux ARM64 jobs run on every pull request and
on manual dispatch; there is no repository-variable skip guard. `Artifact
preflight` runs on every push to `main` and on manual dispatch, adding hosted
Linux x86/ARM, Linux desktop, macOS universal, and Windows package validation.
Linux desktop UI dependencies remain outside the headless Linux target.

A hosted job that ends before checkout with no runner name and an empty step list
is an infrastructure-allocation failure, not product acceptance evidence. Do not
record it as a passed or failed application test, and do not infer a billing
cause unless GitHub reports that cause explicitly.

## Local packaging helpers

```console
cargo run --locked -p xtask -- verify
cargo run --locked -p xtask -- release-readiness --profile private-beta
cargo run --locked -p xtask -- sync-versions
cargo run --locked -p xtask -- package --target <rust-target>
cargo run --locked -p xtask -- stage-packager --target <rust-target>
cargo run --locked -p xtask -- checksums
```

On macOS, after building both architectures:

```console
cargo run --locked -p xtask -- universal-macos
```

The packaging helpers accept only validated target names and operate below the
workspace `target` and `dist` directories.


Linux DEBs must be created through `packaging/package-linux-deb.sh` or
`packaging/package-linux-desktop.sh`, not a direct `cargo packager` invocation.
The wrappers normalize the Debian package identity, add explicit runtime
`Depends`, enforce mutual headless/desktop `Conflicts` and `Replaces`, rebuild
the checksum, and run `scripts/acceptance/linux-deb-metadata.sh`. Release and
artifact-preflight workflows use the same path for x86_64 and aarch64 headless
packages and the x86_64 desktop package. Formal Linux evidence is generated with
`scripts/acceptance/linux-clean-install-vm.sh` for x86_64 headless/desktop and
`scripts/acceptance/linux-headless-clean-install-vm.sh` for ARM64 headless.


## Uninstall acceptance

`runonmine uninstall` removes the per-user service and preserves configuration,
state, profiles, logs, and credentials. Permanent removal requires the separate
confirmation phrase:

```console
runonmine uninstall --purge --confirm PURGE
```

The optional privileged helper and Linux system service have separate elevated
uninstall commands and are never silently removed by a per-user purge.

## Supply-chain evidence and target allowlist

`xtask package` accepts only the exact supported target triples documented in
the workflow. Substring or suffixed targets are rejected. Every archive has a
CycloneDX 1.6 SBOM containing the Cargo.lock SHA-256, exact target, source
revision, included binary manifest, components and dependency graph. Run
`cargo run --locked -p xtask -- validate-sbom --path <file> --target <exact-target>`
before upload.

`python3 scripts/release/check-duplicate-dependencies.py` is a ratchet: new
duplicate package names or versions fail, while intentional removals are
accepted. Update the baseline only after reviewing platform compatibility and
audit/binary-size impact.

Private-beta artifacts remain explicitly unsigned. Public-beta packaging is
hard-blocked until checked-in Apple signing/notarization and Windows Authenticode
steps exist; merely supplying secret values is not accepted as signing evidence.
Do not relabel unsigned artifacts as public candidates.

## Clean-install evidence

Copy `acceptance/evidence/clean-install.template.json` for headless artifacts
or `acceptance/evidence/clean-install.desktop.template.json` for desktop
artifacts, then
artifact, fill the real SHA-256, source revision, tester, timestamp and evidence
references, then run:

```console
python3 scripts/release/validate-clean-install-evidence.py evidence.json
```

Evidence must cover install, reboot, agent readiness, MCP initialize, an approved
tool call, connector operation, uninstall and residue inspection. A retained
residue must be explicitly classified as expected. Templates are never evidence.

## Branch protection

Repository owners apply and verify the intended `main` policy with:

```console
scripts/release/branch-protection.sh apply
scripts/release/branch-protection.sh check
```

The policy requires strict Linux quality, platform matrix and dependency-review
checks, one CODEOWNERS-approved review, conversation resolution and linear
history, and disables force-push and deletion. Review the exact GitHub check names
before applying after workflow renames. On private repositories where the current
GitHub plan returns HTTP 403 for branch protection, leave the machine-readable
gate blocked rather than claiming the policy is active.

See [release-rollback.md](release-rollback.md) for rollback and downgrade rules.

## Artifact preflight versus release acceptance

When GitHub assigns its hosted runners, the `Artifact preflight` workflow runs
on fresh Linux x86/ARM, Linux desktop, macOS, and Windows images and records
build, checksum/SBOM, setup, agent, MCP, owner-approved tool call, desktop launch
where applicable, uninstall, and residue checks. A job with no assigned runner
or executed steps produces no acceptance evidence. Its
report type is `artifact_preflight_not_release_acceptance` and explicitly does
not claim an operating-system reboot, publisher signature or notarization.
Those items remain required evidence for the release clean-install gate.
