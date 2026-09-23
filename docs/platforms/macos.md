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

## Local voice workstation tools

RunOnMine can expose `mac_voice_notify`, `mac_voice_listen`, and
`mac_voice_ask` when the local voice assets are installed:

```console
./scripts/setup-macos-voice.sh
```

The setup compiles `packaging/macos/runonmine-record-audio.swift` into the
private RunOnMine data directory and installs SHA-256-verified Whisper
`large-v3-turbo-q8_0`, `large-v3-q5_0`, and Silero VAD models. The microphone
recorder is installed as the dedicated `RunOnMine Voice Recorder.app` helper so
macOS can bind Microphone permission to a stable bundle identity. On first use,
allow Microphone access for that helper. It explicitly verifies permission,
enables AVAudioEngine voice processing when available, starts listening only
after the start cue completes, and closes automatically after about 2.5 seconds
of silence once speech has begun. Whisper transcription and microphone
audio remain local.

`mac_voice_ask` is a blocking interaction and the MCP instructions require the
agent to wait for the returned transcript before continuing work that depends on
the answer. Voice operations share one playback/listening gate and recent
identical requests are deduplicated to avoid double playback. Ahmet and Emel use
the optional Microsoft Edge neural TTS service, so spoken text is sent to that
service; select Yelda when local-only speech synthesis is required. Microphone
permission may be required on first use.

## User service

The normal user agent is installed as `dev.runonmine.agent` below
`~/Library/LaunchAgents`. On macOS the installer resolves the canonical bundled
`runonmine` CLI, copies those exact signed bytes into RunOnMine's versioned
per-user `service-bin/<version>/runonmine-agent` path, and launches the immutable
copy as `agent run`. This deliberately gives the CLI and background service the
same code-signing identity within one installed build so Keychain credentials
created by the CLI do not require access from a second ad-hoc binary identity:

```console
runonmine setup --root /absolute/project/path
runonmine service install
runonmine service status
```

The LaunchAgent restarts only after unsuccessful exits, applies a 10-second
crash throttle, and reports `launchctl print` state through `service status`.
RunOnMine service lifecycle commands unload the job with `launchctl bootout`,
which prevents the `KeepAlive` policy from immediately restarting a process that
is shutting down. The plist grants a 20-second exit window so the agent can stop
and reap its managed connector process groups before launchd removes the job.
`service start`/restart classify a single `launchctl print` snapshot, then use
`bootstrap` (or a non-forcing `kickstart` only for an already-loaded idle job).
If launchd unloads that idle job between the snapshot and kickstart, RunOnMine
re-checks the job and bootstraps the installed plist only when it is now absent.
Do not use `launchctl kickstart -k` for routine RunOnMine restarts: force-killing
the agent can strand a separately supervised `cloudflared` process. The agent
handles launchd's SIGTERM through its graceful shutdown path and waits for
managed connector supervisors to terminate their process groups before exit.
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

The unsigned beta DMG path and every bundled Mach-O use ad-hoc code signatures with
hardened runtime, and the application resource envelope is sealed. This proves
bundle integrity but does not establish a publisher identity or Apple trust.
Unsigned/ad-hoc beta builds are not Developer ID signed or notarized, so Gatekeeper
rejection remains expected on quarantined downloads. Do not remove quarantine
attributes as a substitute for publisher trust. Public beta may remain unsigned
when this limitation is explicit and all required release gates pass. Setting
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

## Privileged helper and service ownership

For a dedicated owner workstation, macOS also supports the explicit dangerous
profile:

```console
runonmine admin install --owner-root-shell
```

This keeps the normal helper architecture but installs a hash-pinned `/bin/zsh`
profile that permits `-c <command>` for `mac_run_root_shell`. It is never part of
normal setup and should be combined only with a connector the owner intentionally
trusts.

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

Unrelated launchd services, listeners, configuration, logs, and application data
are outside RunOnMine's ownership and must not be modified.
