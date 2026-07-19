# Linux and VPS

Headless builds contain the agent, CLI, and optional helper without GUI
dependencies:

```console
cargo build --release --no-default-features \
  -p runonmine -p runonmine-agent -p runonmine-helper
```

## Per-user service

Install the normal systemd user unit beside the current account:

```console
runonmine service install
runonmine service status
```

The unit is stored below `~/.config/systemd/user` and runs with the current
account's normal authority.

## Headless system service

For a machine without a login session, choose an existing non-root account and
install the explicit system unit as root:

```console
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

Secret Service is used when a session bus is available. A truly headless
process must explicitly provide `RUNONMINE_MASTER_KEY`, encoded as base64 or hex
and decoding to exactly 32 bytes. RunOnMine then uses an XChaCha20-Poly1305 file
backend. Without Secret Service or a valid master key, secret-dependent
connectors fail closed.

Do not put the master key in the repository, unit file, shell history, or
world-readable environment file. Supply it through the host's secret injection
facility.

## Conditional tools

Chromium, desktop capture/input, and D-Bus tools are listed only when the
current session has the required executable, display, and session bus.
The optional root helper uses `SO_PEERCRED`, restricts its Unix socket to the
installing user, and is not installed by either service command.
