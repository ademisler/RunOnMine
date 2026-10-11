# MCP Tools

Tool names are platform-independent. Unsupported tools are omitted from
`tools/list`; they are not advertised as operations that will fail later.

## System and files

- `machine_info`
- `fs_list`, `fs_read`, `fs_search`
- `fs_write`, `fs_patch`, `fs_move`, `fs_delete`

File tools operate only below selected canonical roots. Read and output sizes
are bounded. Writes use atomic replacement where an overwrite is intended.

## Processes and privilege

- `shell_exec`
- `admin_exec`

Shell timeouts terminate the process tree through Unix process groups or a
Windows Job Object. The canonical effective working directory is part of policy
and exact-grant identity. stdout and stderr share one configured retained-output
budget; both pipes continue draining after that budget is exhausted so a noisy
child cannot deadlock on a full pipe. Environment values are not returned in
errors. `admin_exec` appears only when the optional helper is healthy and
has at least one allowlisted, hash-pinned executable. The helper additionally
requires the complete argument vector to match an installed command profile;
executable-only compatibility entries accept no arguments.

## Browser

- `browser_open`, `browser_navigate`, `browser_close`
- `browser_get_url`, `browser_get_text`, `browser_snapshot`
- `browser_click`, `browser_type`, `browser_press`, `browser_evaluate`
- `browser_screenshot`, `browser_profile_info`

Browser objects are separated by connector and MCP session. Screenshots are
complete JPEG images reduced by quality and scale rather than byte truncation.

## Desktop

- `desktop_list_windows`, `desktop_focus_window`, `desktop_screenshot`
- `desktop_click`, `desktop_type`, `desktop_key`

Capture, accessibility, and input permissions are controlled by the operating
system. Linux advertises only capabilities available in the current X11 or
Wayland session; input fails closed on unsupported Wayland configurations.

## Platform-native

- macOS: `macos_applescript`
- Windows: `windows_powershell`
- Linux: `linux_dbus_call`

AppleScript and PowerShell are passed on stdin to fixed system executables.
Linux D-Bus calls use structured, validated `busctl --user call` arguments.
These are execution capabilities, not safe data-query shortcuts.


## Connector binary trust commands

`runonmine connect list` includes the configured connector binary trust state.
Use `runonmine connect pin-external-binaries` after reviewing an explicit
external executable; later content or ownership/metadata changes fail before
process start. `runonmine connect update-managed-binaries` updates managed
Cloudflare and OpenAI paths through immutable version preparation,
compatibility probing and rollback-aware activation. Explicit external paths are
never silently replaced. Unsupported or prerelease clients are rejected before
the active manifest changes.
