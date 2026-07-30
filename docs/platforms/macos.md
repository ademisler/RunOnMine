# macOS

The normal user agent is installed as `dev.runonmine.agent` in
`~/Library/LaunchAgents`; the executable itself is copied into the versioned
per-user `service-bin` directory:

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

The desktop application needs macOS Screen Recording permission for capture and
Accessibility permission for synthetic input and window focus. RunOnMine does
not bypass these prompts. Browser automation with its isolated Chromium profile
does not require access to the user's normal Chrome profile.

The optional privileged helper is installed only through `runonmine admin
install` and authenticates the local peer with `getpeereid`. It accepts only
explicit absolute executable paths recorded at installation and hash-pinned in
its root-owned policy.

The first beta DMG is a universal arm64/x86_64 build assembled with `lipo`. It is
unsigned and not notarized; that limitation is displayed in release notes and
must be considered before installation.

The existing `com.idemasler.macmcp.*` services, port `45799`, and MacMCP config,
logs, and data are outside RunOnMine's ownership and must not be modified.

Arguments are additionally restricted by the installed executable-specific command profile; an executable added with `--allow-program` alone accepts no arguments.

The privileged helper retains the verified executable descriptor and compares
its device/inode identity and SHA-256 with a freshly opened canonical path
immediately before spawn. This narrows the replacement window; unlike Linux,
the current macOS implementation does not claim descriptor-path execution.

Helper upgrades stage the executable, policy and launchd plist before booting out the old daemon. A failed bootstrap or health check restores all prior files, recreates the former loaded/running launchd state and verifies the restored helper when it was previously running.
