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
entry and icon. Do not install the headless and desktop DEBs together because
both intentionally own the same CLI and service binaries.

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
the window. Sessions without a working StatusNotifierItem host fall back to a
normal window whose close action exits.

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
window-manager close-to-tray behavior, tray activation, and clean tray removal
with:

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
hosts, not the recommended service configuration.

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
