# macOS

RunOnMine supports macOS 12 or later. The desktop application and bundled CLI,
agent, and optional helper binaries are packaged as one universal arm64/x86_64
application and DMG.

## Desktop control center

The macOS control center contains Overview, Approvals, Connections,
Permissions, OAuth, Audit, and Diagnostics. Its native menu-bar item exposes
**Open RunOnMine**, **Lock RunOnMine**, and **Quit**. Closing the main window
hides it while the menu-bar item remains active; activating the item restores
and focuses the window. Diagnostics reports whether the native shell and
close-to-tray behavior are available.

Screen capture requires macOS Screen Recording permission. Synthetic input and
window focus require Accessibility permission. RunOnMine does not bypass these
prompts. Browser automation uses a separate Chromium profile and does not need
access to the user's normal Chrome profile.

## User service

The normal user agent is installed as `dev.runonmine.agent` below
`~/Library/LaunchAgents`. The agent executable is copied into RunOnMine's
versioned per-user `service-bin` directory before the plist is loaded:

```console
runonmine setup --root /absolute/project/path
runonmine service install
runonmine service status
```

The LaunchAgent restarts only after unsuccessful exits, applies a 10-second
crash throttle, and reports `launchctl print` state through `service status`.
Private stdout/stderr files live in RunOnMine's platform log directory. The
agent tracing writer checks the stderr file before each write and truncates it
before it would exceed 5 MiB; symlinked or unexpected log paths are rejected.

## Building and packaging

Install Rust 1.95.0 plus Xcode Command Line Tools and `cargo-packager` 0.11.8.
Build both architectures, merge the four binaries, validate the portable
archive/SBOM, and create the DMG with:

```console
cargo build --release --locked --target aarch64-apple-darwin \
  --workspace --exclude xtask
cargo build --release --locked --target x86_64-apple-darwin \
  --workspace --exclude xtask
cargo run --locked -p xtask -- universal-macos
cargo run --locked -p xtask -- package --target universal-apple-darwin
cargo run --locked -p xtask -- validate-sbom \
  --path dist/runonmine-0.1.0-beta.1-universal-apple-darwin-unsigned.sbom.json \
  --target universal-apple-darwin
cargo run --locked -p xtask -- stage-packager \
  --target universal-apple-darwin
./packaging/package-macos.sh
cargo run --locked -p xtask -- checksums
```

The release workflow performs the same universal merge and package contract.

The private-beta DMG and every bundled Mach-O use ad-hoc code signatures with
hardened runtime, and the application resource envelope is sealed. This proves
bundle integrity but does not establish a publisher identity or Apple trust.
The private beta is not Developer ID signed or notarized, so Gatekeeper
rejection remains expected on quarantined downloads. Do not remove quarantine
attributes as a substitute for a signed public release. Setting
`RUNONMINE_APPLE_SIGNING_IDENTITY` switches the same script to the fail-closed
Developer ID/notarization path and requires the documented Apple credentials.

## Uninstall and retained data

Removing `RunOnMine.app` removes the application bundle but does not remove the
per-user LaunchAgent, configuration, state, logs, browser profiles, or
credential-store entries. Use the bundled CLI at
`/Applications/RunOnMine.app/Contents/MacOS/runonmine` (or an equivalent CLI
installation) before deleting the bundle:

Choose one of the two service/data lifecycles:

```console
runonmine uninstall
# Alternative: runonmine uninstall --purge --confirm PURGE
```

The first form removes the per-user service and retains application data. The
explicit purge alternative also removes RunOnMine user data and connector
secrets. The separately elevated privileged helper is not removed by either
operation; run `sudo runonmine admin uninstall` before deleting the bundle when
that helper was explicitly installed.

## Privileged helper and MacMCP boundary

The optional privileged helper is installed only through `sudo runonmine admin
install` and authenticates the local peer with `getpeereid`. It accepts only
explicit absolute executable paths recorded at installation and hash-pinned in
its root-owned policy. Arguments must also match an installed executable-specific
command profile; `--allow-program` alone permits only an empty argument vector.

The helper retains the verified executable descriptor and compares its
device/inode identity and SHA-256 with a freshly opened canonical path
immediately before spawn. Unlike Linux, the current macOS implementation does
not claim descriptor-path execution. Helper upgrades stage the executable,
policy, and launchd plist before booting out the old daemon. A failed bootstrap
or health check restores prior files and the former loaded/running state.

The existing `com.idemasler.macmcp.*` services, port `45799`, and MacMCP config,
logs, and data are outside RunOnMine's ownership and must not be modified.
