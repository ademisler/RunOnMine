# Linux and VPS

Headless builds contain the agent, CLI, and optional helper without GUI
dependencies:

```console
cargo build --release --no-default-features \
  -p runonmine -p runonmine-agent -p runonmine-helper
```

## Desktop control center

The x86_64 desktop package is a standalone alternative to the headless DEB. It
installs `runonmine`, `runonmine-agent`, `runonmine-helper`, and
`runonmine-desktop` together under `/usr/bin`, plus a validated freedesktop menu
entry and icon. The two DEBs intentionally own the same CLI and service
binaries, so their metadata declares mutual `Conflicts` and `Replaces`; `apt`
performs an explicit package replacement instead of leaving both installed.

On Ubuntu 24.04, source builds require the X11/Wayland, PipeWire, EGL, GBM, DRM,
and XKB development libraries used by eframe and optional desktop-control
capture:

```console
sudo apt-get install --yes --no-install-recommends \
  dbus-x11 desktop-file-utils pkg-config xvfb \
  libdrm-dev libegl1-mesa-dev libgbm-dev \
  libpipewire-0.3-dev libspa-0.2-dev \
  libwayland-dev libx11-dev libxcb1-dev \
  libxkbcommon-dev libxkbcommon-x11-0
cargo build --release --locked --target x86_64-unknown-linux-gnu \
  -p runonmine -p runonmine-agent -p runonmine-helper -p runonmine-desktop
```

The control center is a normal Linux window and taskbar application with a
freedesktop StatusNotifierItem tray. It does not require GTK or AppIndicator.
The tray exposes the same **Open RunOnMine**, **Lock RunOnMine**, and **Quit**
actions as macOS and Windows. Closing the window through the window manager
hides it while the tray remains active; activating the tray restores and focuses
the window. A second desktop launch connects to an owner-private Unix socket in
the RunOnMine state directory, asks the primary process to show itself, and exits
without creating another window. Unsafe non-socket or foreign-owned entries are
never replaced. Sessions without a working StatusNotifierItem host fall back to
a normal window whose close action exits.

Install a built candidate and start the user service with:

```console
sudo apt install ./runonmine-desktop_*_amd64.deb
runonmine setup --root /absolute/path/to/a/project
runonmine service install
runonmine-desktop
```

The desktop emergency lock calls the current user's `runonmine lock`; it does
not request the root-only `--system` path. Although the package contains
`runonmine-helper`, it does not install, register, or activate the privileged
helper service.

Package removal and application-data removal are separate operations:

Choose one service/data lifecycle, then remove any separately installed helper
and finally remove the package:

```console
runonmine uninstall
# Alternative: runonmine uninstall --purge --confirm PURGE
# If applicable: sudo runonmine admin uninstall
sudo apt remove runonmine-desktop
```

The package manager removes package-owned binaries, the menu entry, the icon,
and packaged resources. It does not own or delete per-user XDG configuration,
state, logs, browser profiles, or credential-store entries. `runonmine
uninstall` removes the per-user service while retaining those data; the explicit
purge command removes application data and connector secrets but still does not
silently uninstall the separately elevated helper or Linux system service.

The platform-independent smoke renders all seven control-center views in an
isolated D-Bus/Xvfb session and writes a privacy-bounded JSON contract:

```console
./scripts/acceptance/desktop-parity-smoke.sh \
  "$PWD/target/x86_64-unknown-linux-gnu/release/runonmine-desktop"
```

On a real X11 desktop, install `wmctrl`, `xdotool`, `libglib2.0-bin`, and the
normal systemd/D-Bus tools, then validate StatusNotifier registration,
window-manager close-to-tray behavior, tray activation, single-instance
activation, and clean tray removal with:

```console
DISPLAY=:0 \
XAUTHORITY="$HOME/.Xauthority" \
DBUS_SESSION_BUS_ADDRESS="unix:path=$XDG_RUNTIME_DIR/bus" \
./scripts/acceptance/linux-desktop-session-smoke.sh \
  "$PWD/target/x86_64-unknown-linux-gnu/release/runonmine-desktop"
```

## Per-user service

Install the normal systemd user unit beside the current account:

```console
runonmine service install
runonmine service status
```

The unit is stored below `~/.config/systemd/user` and runs with the current
account's normal authority. The agent is copied first into the platform data
directory at `service-bin/<package-version>/runonmine-agent`; moving or deleting
the downloaded archive therefore does not break the service. It uses `ProtectSystem=strict` and
`ProtectHome=read-only`, then opens RunOnMine's private configuration, state,
local-data directories, and every canonical selected filesystem root through
explicit `ReadWritePaths` entries. `runonmine service install` reads the current
validated configuration. Later `runonmine setup --root ...` operations and root
changes from the desktop application re-render the installed unit; a running
service is restarted immediately so write policy and the systemd sandbox cannot
disagree.

A headless user service needs durable key material. When a valid 32-byte
`RUNONMINE_MASTER_KEY` is present during `runonmine service install`, RunOnMine
copies it without whitespace into an owner-only mode-0600 file below the local
data directory and renders a systemd `LoadCredential` directive. The service
then receives only systemd's read-only runtime credential copy. The source path,
its parents, ownership, mode, size, and symlink state are validated before use.
A desktop session that uses Secret Service and does not supply an explicit master
key continues to use the platform credential store instead.

The same hardened user-service namespace can display root-owned external
connector binaries with the kernel overflow UID/GID. Pin verification translates
only identities described by `/proc/self/uid_map`, `/proc/self/gid_map`, and the
kernel overflow settings; canonical path, SHA-256, size, modification time, and
mode must still match exactly. A user-owned replacement therefore remains a pin
failure.

## Headless system service

For a machine without a login session, choose an existing non-root account,
create a root-owned systemd credential, and install the explicit system unit as
root:

```console
sudo install -d -m 0700 /etc/runonmine
openssl rand -hex 32 | sudo tee /etc/runonmine/master-key >/dev/null
sudo chmod 0600 /etc/runonmine/master-key
sudo chown root:root /etc/runonmine/master-key
sudo runonmine service install --system --user runonmine
runonmine service status --system
```

Installation copies `runonmine-agent` to
`/usr/local/libexec/runonmine/runonmine-agent`, writes
`/etc/systemd/system/runonmine-agent.service`, and enables it. The service uses
systemd hardening and then runs as the selected account, never as root. Its
`HOME` and XDG data locations remain those of that account, so initialize the
same account before starting the service.

```console
sudo -u runonmine -H runonmine setup --root /srv/projects
```

Uninstalling the unit removes only the unit and managed executable. Per-user
configuration, state, and secrets are preserved.

## Secrets

Secret Service is used when a session bus is available. The headless system unit
uses systemd `LoadCredential` and reads
`$CREDENTIALS_DIRECTORY/runonmine-master-key`; the source file must be the
root-owned, non-symlink `/etc/runonmine/master-key` with no group/other access.
The value is base64 or hex and must decode to exactly 32 bytes. RunOnMine then
uses an XChaCha20-Poly1305 file backend with a private cross-process lock.
`RUNONMINE_MASTER_KEY` remains an explicit compatibility fallback for non-systemd
hosts and the input used when installing a headless per-user service. Explicit
headless key material takes precedence over ambient `XDG_RUNTIME_DIR` or session
bus variables so a lingering user manager cannot accidentally select Secret
Service without a usable keyring.

To rotate the key, stop the service, export or recreate connector credentials,
atomically replace `/etc/runonmine/master-key` with a new 32-byte value at mode
0600, remove the old encrypted secret file only after credentials are safely
reprovisioned, and restart. Never place the key in the repository, unit file,
shell history, or a world-readable environment file.

## Conditional tools

Chromium, desktop capture/input, and D-Bus tools are listed only when the
current session has the required executable, display, and session bus.
The optional root helper uses `SO_PEERCRED`, restricts its Unix socket to the
installing user, and is not installed by either service command.

Arguments are additionally restricted by the installed executable-specific command profile; an executable added with `--allow-program` alone accepts no arguments.

Privileged helper execution is inode-pinned. The root-owned executable is opened
with `O_NOFOLLOW`, verified and hashed through that handle, rehashed immediately
before spawn, and executed through `/proc/self/fd/<fd>`. A pathname replacement
after authorization cannot redirect the child to a different inode.

Helper upgrades stage the executable, policy and systemd unit before stopping the service. A failed start or health check restores the previous files, reloads systemd, recreates the former enabled/running state and verifies the restored helper when it was previously running.

## Full Linux clean-install acceptance

The x86_64 release candidate is exercised in a disposable Ubuntu 24.04 QEMU VM,
then the exact desktop DEB binary is exercised against Oty's real X11 and user
D-Bus session. The harness verifies synthetic beta.0-to-beta.1 upgrades, package
replacement, user and system services, two distinct VM reboots, MCP initialize,
a locally approved write, denied administrator execution, a real Cloudflare
Quick Tunnel, emergency lock and stale-token rejection, seven-view rendering,
tray lifecycle, single-instance activation, uninstall, and residue inspection.

```console
sudo ./scripts/acceptance/linux-clean-install-vm.sh \
  /var/lib/runonmine-acceptance/cache/noble-server-cloudimg-amd64.img \
  "$PWD/dist/runonmine_0.1.0-beta.1_amd64.deb" \
  "$PWD/dist/runonmine-desktop_0.1.0-beta.1_amd64.deb" \
  /usr/local/bin/cloudflared \
  /var/lib/runonmine-acceptance/evidence/linux-x86_64
```

Formal evidence requires a clean committed worktree. Development-only runs may
set `RUNONMINE_ACCEPTANCE_ALLOW_DIRTY=1`; their report is explicitly labeled
`development_clean_install_acceptance` and cannot satisfy a release gate.

The ARM64 headless artifact uses the matching full-system QEMU path. The guest
downloads the architecture-correct `cloudflared` through RunOnMine's verified
managed-binary resolver, then verifies one real reboot and the complete
user/system-service, MCP, lock, uninstall, and residue lifecycle:

```console
sudo ./scripts/acceptance/linux-headless-clean-install-vm.sh \
  /var/lib/runonmine-acceptance/cache/noble-server-cloudimg-arm64.img \
  "$PWD/dist/runonmine_0.1.0-beta.1_arm64.deb" \
  /var/lib/runonmine-acceptance/evidence/linux-aarch64
```
