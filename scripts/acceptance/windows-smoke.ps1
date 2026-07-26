param(
    [string]$RunOnMine = "runonmine.exe"
)
$ErrorActionPreference = "Stop"
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("runonmine-acceptance-" + [guid]::NewGuid())
$home = Join-Path $root "home"
$project = Join-Path $root "project"
New-Item -ItemType Directory -Force -Path $home, $project | Out-Null

$old = @{
    HOME = $env:HOME
    USERPROFILE = $env:USERPROFILE
    APPDATA = $env:APPDATA
    LOCALAPPDATA = $env:LOCALAPPDATA
    RUNONMINE_TEST_FILE_SECRETS = $env:RUNONMINE_TEST_FILE_SECRETS
    RUNONMINE_MASTER_KEY = $env:RUNONMINE_MASTER_KEY
}
try {
    $env:HOME = $home
    $env:USERPROFILE = $home
    $env:APPDATA = Join-Path $root "appdata"
    $env:LOCALAPPDATA = Join-Path $root "localappdata"
    $env:RUNONMINE_TEST_FILE_SECRETS = "1"
    $env:RUNONMINE_MASTER_KEY = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

    (& $RunOnMine setup --root $project | Out-String) | Select-String -SimpleMatch "RunOnMine is initialized." | Out-Null
    (& $RunOnMine policy show | Out-String) | Select-String -SimpleMatch "AdminExec: Deny" | Out-Null
    (& $RunOnMine connect list | Out-String) | Select-String -SimpleMatch "LocalHttp" | Out-Null
    (& $RunOnMine approvals list | Out-String) | Select-String -SimpleMatch "No pending approvals." | Out-Null
    & $RunOnMine audit tail --limit 5 | Out-Null
    (& $RunOnMine lock | Out-String) | Select-String -SimpleMatch "RunOnMine is locked." | Out-Null
    (& $RunOnMine uninstall --purge --confirm PURGE | Out-String) | Select-String -SimpleMatch "permanently removed" | Out-Null
    Write-Host "RunOnMine isolated Windows CLI smoke test passed."
}
finally {
    foreach ($name in $old.Keys) {
        [Environment]::SetEnvironmentVariable($name, $old[$name], "Process")
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
}
