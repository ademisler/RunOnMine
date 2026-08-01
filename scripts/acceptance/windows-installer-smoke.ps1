param(
    [Parameter(Mandatory = $true)] [string]$Installer,
    [switch]$SkipInteractiveDesktop
)
$ErrorActionPreference = "Stop"
. "$(Join-Path $PSScriptRoot "windows-desktop-acceptance.ps1")"

$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("runonmine-installer-" + [guid]::NewGuid())
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\RunOnMine"
$localDataRoot = Join-Path $env:LOCALAPPDATA "RunOnMine\RunOnMine"
$roamingDataRoot = Join-Path $env:APPDATA "RunOnMine\RunOnMine"
$installLocation = $null
$uninstaller = $null
New-Item -ItemType Directory -Force -Path $root | Out-Null

if (Test-Path -LiteralPath $registryPath) {
    throw "RunOnMine is already installed for the current user; installer acceptance refuses to replace it"
}
if ((Test-Path -LiteralPath $localDataRoot) -or (Test-Path -LiteralPath $roamingDataRoot)) {
    throw "RunOnMine user data already exists; installer acceptance refuses to modify it"
}
try {
    $install = Start-Process -FilePath $installerPath -ArgumentList "/S" -PassThru -Wait
    if ($install.ExitCode -ne 0) { throw "NSIS installer exited with code $($install.ExitCode)" }
    if (-not (Test-Path -LiteralPath $registryPath)) { throw "NSIS installer did not create the current-user uninstall record" }
    $entry = Get-ItemProperty -LiteralPath $registryPath
    if ($entry.DisplayName -ne "RunOnMine" -or $entry.Publisher -ne "RunOnMine contributors") {
        throw "NSIS uninstall metadata is incorrect"
    }
    $installLocation = $entry.InstallLocation.Trim('"')
    if (-not [System.IO.Path]::IsPathFullyQualified($installLocation)) { throw "NSIS install location is not absolute" }
    foreach ($binary in @("runonmine.exe", "runonmine-agent.exe", "runonmine-desktop.exe", "runonmine-helper.exe")) {
        if (-not (Test-Path -LiteralPath (Join-Path $installLocation $binary) -PathType Leaf)) {
            throw "installed binary is missing: $binary"
        }
    }
    $programs = [Environment]::GetFolderPath("Programs")
    $startMenuCandidates = @(
        (Join-Path $programs "RunOnMine.lnk"),
        (Join-Path $programs "RunOnMine\RunOnMine.lnk")
    )
    $startMenu = $startMenuCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "RunOnMine.lnk"
    if (-not $startMenu) { throw "RunOnMine Start Menu shortcut is missing" }
    if (-not (Test-Path -LiteralPath $desktopShortcut)) { throw "RunOnMine desktop shortcut is missing" }
    Invoke-RunOnMineDesktopAcceptance -Desktop (Join-Path $installLocation "runonmine-desktop.exe") `
        -Root $root -ExpectNativeShell $true -RequireInteractiveWindow (-not $SkipInteractiveDesktop.IsPresent)

    $uninstaller = Join-Path $installLocation "uninstall.exe"
    if (-not (Test-Path -LiteralPath $uninstaller -PathType Leaf)) { throw "NSIS uninstaller is missing" }
    $remove = Start-Process -FilePath $uninstaller -ArgumentList "/S" -PassThru -Wait
    if ($remove.ExitCode -ne 0) { throw "NSIS uninstaller exited with code $($remove.ExitCode)" }
    $uninstaller = $null
    for ($attempt = 0; $attempt -lt 100 -and (Test-Path -LiteralPath $installLocation); $attempt++) {
        Start-Sleep -Milliseconds 100
    }
    if (Test-Path -LiteralPath $registryPath) { throw "NSIS uninstall record remained after removal" }
    foreach ($managedName in @("runonmine.exe", "runonmine-agent.exe", "runonmine-desktop.exe", "runonmine-helper.exe", "uninstall.exe", "README.md")) {
        if (Test-Path -LiteralPath (Join-Path $installLocation $managedName)) {
            throw "NSIS managed file remained after removal: $managedName"
        }
    }
    if (Test-Path -LiteralPath $startMenu) { throw "RunOnMine Start Menu shortcut remained after removal" }
    if (Test-Path -LiteralPath $desktopShortcut) { throw "RunOnMine desktop shortcut remained after removal" }
    if (-not (Test-Path -LiteralPath $localDataRoot)) {
        throw "NSIS uninstall did not preserve RunOnMine local user data by default"
    }
    $unexpectedFiles = @(Get-ChildItem -LiteralPath $installLocation -Recurse -File -ErrorAction SilentlyContinue | Where-Object {
        -not $_.FullName.StartsWith($localDataRoot, [System.StringComparison]::OrdinalIgnoreCase)
    })
    if ($unexpectedFiles.Count -ne 0) {
        throw "NSIS uninstall left unexpected managed files: $($unexpectedFiles.FullName -join ', ')"
    }
    if ($SkipInteractiveDesktop) {
        Write-Host "RunOnMine Windows NSIS install, desktop render/report, retained-data uninstall and managed-file residue test passed; interactive HWND/tray lifecycle was not claimed."
    } else {
        Write-Host "RunOnMine Windows NSIS install, interactive desktop acceptance, retained-data uninstall and managed-file residue test passed."
    }
}
finally {
    if ($uninstaller -and (Test-Path -LiteralPath $uninstaller)) {
        Start-Process -FilePath $uninstaller -ArgumentList "/S" -Wait -ErrorAction SilentlyContinue
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $localDataRoot
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $roamingDataRoot
    if ($installLocation -and (Test-Path -LiteralPath $installLocation)) {
        $remaining = @(Get-ChildItem -LiteralPath $installLocation -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) {
            Remove-Item -Force -LiteralPath $installLocation -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
}
