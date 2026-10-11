# Release Process

The first candidate version is `0.1.0-beta.1`. Repository visibility is a
separate owner decision and is never changed by CI.

## Current repository status

Current release status is defined by `acceptance/release-candidate.toml` and
`acceptance/release-gates.toml`, not by a remembered candidate hash in this
document. Only evidence produced for the exact frozen revision and recorded
artifact SHA-256 may satisfy a candidate-scoped gate. Any non-evidence commit
after a freeze invalidates readiness and requires a new freeze plus fresh
applicable platform acceptance.

Public beta remains fail-closed on the gates declared for `public-beta`, including
hosted-platform execution, untrusted-fork isolation, protected-main enforcement,
exact-candidate platform acceptance, and owner risk review. Publisher signing,
Apple notarization, and an independent external security review are strongly
recommended hardening, but an explicitly unsigned beta may ship without them.
The physical macOS reboot gate is still not equivalent to native smoke: a
FileVault preboot screen requires owner authentication before post-reboot
LaunchAgent/MCP recovery can be verified.

## Required gates

Before creating a tag:

1. run `python3 scripts/release/check-duplicate-dependencies.py` and `cargo run --locked -p xtask -- verify` without skipping the secret scan;
2. keep headless line coverage at or above the enforced baseline and review the latest scheduled fuzz run;
3. pass macOS arm64/x86_64, Linux x86_64/aarch64 headless, Linux x86_64 desktop, and Windows x86_64 builds;
4. complete install, restart, connect, tool-call, lock, and uninstall acceptance on a Mac, clean Linux VPS, clean Linux desktop, and Windows VM;
5. confirm install, lock, uninstall, and purge do not modify unrelated local services or application data;
6. record evidence in `acceptance/release-gates.toml` and pass `cargo run --locked -p xtask -- release-readiness --profile public-beta`;
7. present remaining risks and the secret-scan result to the repository owner.

After all production code, dependency, workflow, documentation, and packaging
changes are committed, freeze that exact source revision:

```console
cargo run --locked -p xtask -- freeze-release-candidate
git add acceptance/release-candidate.toml
git commit -m "chore(release): freeze beta candidate"
```

Run every platform acceptance job against the revision recorded in
`acceptance/release-candidate.toml`. Only that manifest,
`acceptance/release-gates.toml`, and machine-readable files below
`acceptance/evidence/` may be committed after the freeze. Readiness fingerprints
the complete source tree and inspects every path touched after the candidate;
a later code, dependency, workflow, package, or narrative-documentation change
invalidates the candidate even if it is subsequently reverted.

The release workflow runs readiness at the tag commit, then checks out and builds
the frozen source revision. Beta tag pushes always resolve to `public-beta`;
manual dispatch remains an explicit profile choice so `private-beta` validation
can still be run deliberately. It stops while any gate required for the selected
profile is `pending` or `blocked`. Public beta requires hosted platform CI,
untrusted-fork isolation, protected-main enforcement, exact-candidate platform
acceptance, and owner risk review. Signing/notarization and independent review
remain visible advisory gates rather than mandatory beta gates. See
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

The workflow opens a draft prerelease only. Beta artifacts may be unsigned and must never be described as signed, notarized, or publisher-trusted unless that exact artifact passed the corresponding verification. When Apple signing credentials are configured, the checked-in macOS path imports the Developer ID certificate, enables hardened runtime, notarizes and staples the universal application, signs the DMG, and runs Gatekeeper verification; incomplete configured signing material fails closed. Without those credentials, the macOS beta follows the checked ad-hoc hardened-runtime path. That unsigned path explicitly removes empty or ambient Apple credential variables before invoking `cargo-packager`, because missing GitHub Actions secrets are represented as empty strings and must not trigger keychain setup. Artifact preflight exercises this exact empty-secret environment. Windows beta installers may likewise be unsigned. Publishing the draft and making the repository public both require separate owner approval.

## Hosted platform validation

`CI` exposes one stable `Linux quality` check on GitHub-hosted `ubuntu-24.04` for pushes, manual runs, owner pull requests, and fork pull requests. No repository workflow selects a persistent self-hosted runner. The job installs Gitleaks 8.24.3 only after verifying the checked-in official SHA-256, executes the headless quality, MCP, and coverage contract, and removes ephemeral targets after the run. `Security`, `Coverage`, `Fuzz`, `Mutation`, and the Linux `Soak` job use the same ephemeral hosted trust model.

`Platform CI` is separate from the Linux quality path. Its macOS
arm64/x86_64, Windows x86_64, and Linux ARM64 jobs run on every pull request and
on manual dispatch; there is no repository-variable skip guard. `Artifact
preflight` runs on every push to `main` and on manual dispatch, adding hosted
Linux x86/ARM, Linux desktop, macOS universal, and Windows package validation.
Linux desktop UI dependencies remain outside the headless Linux target.

A hosted job that ends before checkout with no runner name and an empty step list
is an infrastructure-allocation failure, not product acceptance evidence. Do not
record it as a passed or failed application test. When GitHub explicitly reports
failed account payments or an exceeded spending limit, keep the hosted-platform
gate blocked with that diagnosis until billing/execution is restored; do not
misclassify the run as a source-code failure.

## Local packaging helpers

```console
cargo run --locked -p xtask -- verify
cargo run --locked -p xtask -- freeze-release-candidate
cargo run --locked -p xtask -- release-readiness --profile public-beta
cargo run --locked -p xtask -- release-readiness --profile private-beta
cargo run --quiet --locked -p xtask -- release-candidate-revision
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
accepted. The required Linux quality PR check runs this ratchet before merge so
a stale baseline cannot first surface during tag publication. Update the baseline
only after reviewing dependency paths, platform compatibility, advisories, and
audit/binary-size impact.

Unsigned artifacts are allowed for beta distribution when the release notes and
platform documentation state that limitation prominently. Public-beta packaging
remains blocked by its declared release gates, including hosted platform CI and
protected-main evidence, but not by the absence of Developer ID, notarization,
Windows Authenticode, or an independent external review. If signing is configured,
verification remains fail-closed and secret presence alone is never accepted as
signing evidence.

## Clean-install evidence

Copy `acceptance/evidence/clean-install.template.json` for headless artifacts
or `acceptance/evidence/clean-install.desktop.template.json` for desktop
artifacts. Fill the real artifact SHA-256, source revision, tester, timestamp,
and evidence references, then run:

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

The policy requires strict Linux quality, Platform matrix and Dependency review
checks, administrator enforcement, pull requests, conversation resolution and
linear history, and disables force-push and deletion. The repository currently
has one maintainer, so `RUNONMINE_REQUIRED_APPROVALS` defaults to `0`; GitHub still
requires the pull-request and status-check policy, but no second-person approval
is fabricated. Set `RUNONMINE_REQUIRED_APPROVALS=1` (or higher) when another
trusted maintainer is available; CODEOWNERS and last-push approval become
mandatory in that mode. Review the exact GitHub check names before applying after
workflow renames. On private repositories where the current GitHub plan returns
HTTP 403 for branch protection, leave the machine-readable gate blocked rather
than claiming the policy is active.

See [release-rollback.md](release-rollback.md) for rollback and downgrade rules.

## Artifact preflight versus release acceptance

When GitHub assigns its hosted runners, the `Artifact preflight` workflow runs
on fresh Linux x86/ARM, Linux desktop, macOS, and Windows images and records
build, checksum/SBOM, setup, agent, MCP, owner-approved tool call, desktop launch
where applicable, uninstall, and residue checks. A job with no assigned runner
or executed steps produces no acceptance evidence. Its
report type is `artifact_preflight_not_release_acceptance` and explicitly does
not claim an operating-system reboot, publisher signature or notarization.
Clean-install and reboot evidence remain separate candidate gates. Publisher
signature/notarization are recorded when present but are optional for an
explicitly unsigned beta.
