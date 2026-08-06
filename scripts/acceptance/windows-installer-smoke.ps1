param(
    [Parameter(Mandatory = $true)] [string]$Installer,
    [switch]$SkipInteractiveDesktop
)
$ErrorActionPreference = "Stop"
. "$(Join-Path $PSScriptRoot "windows-desktop-acceptance.ps1")"

function Test-RunOnMineFullyQualifiedWindowsPath {
    param([AllowEmptyString()] [string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    return ($Path -match '^[A-Za-z]:[\\/]') -or
        ($Path -match '^[\\/]{2}[^\\/]+[\\/][^\\/]+(?:[\\/]|$)')
}


function Test-RunOnMinePath {
    param(
        [Parameter(Mandatory = $true)] [string]$LiteralPath,
        [ValidateSet("Any", "Leaf", "Container")] [string]$PathType = "Any",
        [int]$TimeoutMilliseconds = 60000
    )
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    do {
        try {
            if ($PathType -eq "Any") {
                return Test-Path -LiteralPath $LiteralPath -ErrorAction Stop
            }
            return Test-Path -LiteralPath $LiteralPath -PathType $PathType -ErrorAction Stop
        }
        catch {
            if ($_.Exception.Message -notmatch 'Access is denied') { throw }
            if ([DateTime]::UtcNow -ge $deadline) {
                throw "access remained denied while probing path: $LiteralPath"
            }
            Start-Sleep -Milliseconds 100
        }
    } while ($true)
}

function Test-RunOnMineManagedFilesRemain {
    param([string]$Location)
    foreach ($managedName in @("runonmine.exe", "runonmine-agent.exe", "runonmine-desktop.exe", "runonmine-helper.exe", "uninstall.exe", "README.md")) {
        if (Test-RunOnMinePath -LiteralPath (Join-Path $Location $managedName)) { return $true }
    }
    return $false
}

$installerPath = (Resolve-Path -LiteralPath $Installer).Path
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("runonmine-installer-" + [guid]::NewGuid())
$registryPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\RunOnMine"
$localDataRoot = Join-Path $env:LOCALAPPDATA "RunOnMine\RunOnMine"
$roamingDataRoot = Join-Path $env:APPDATA "RunOnMine\RunOnMine"
$installLocation = $null
$uninstaller = $null
New-Item -ItemType Directory -Force -Path $root | Out-Null

if (Test-RunOnMinePath -LiteralPath $registryPath) {
    throw "RunOnMine is already installed for the current user; installer acceptance refuses to replace it"
}
if ((Test-RunOnMinePath -LiteralPath $localDataRoot) -or (Test-RunOnMinePath -LiteralPath $roamingDataRoot)) {
    throw "RunOnMine user data already exists; installer acceptance refuses to modify it"
}
try {
    $install = Start-RunOnMineNativeProcess -FilePath $installerPath -ArgumentList @("/S")
    if (-not $install.WaitForExit(1800000)) {
        Stop-Process -Id $install.Id -Force -ErrorAction SilentlyContinue
        [void]$install.WaitForExit(30000)
        throw "NSIS installer timed out after 1800 seconds"
    }
    $install.WaitForExit()
    if ($install.ExitCode -ne 0) { throw "NSIS installer exited with code $($install.ExitCode)" }
    $install.Dispose()
    if (-not (Test-RunOnMinePath -LiteralPath $registryPath)) { throw "NSIS installer did not create the current-user uninstall record" }
    $entry = Get-ItemProperty -LiteralPath $registryPath
    $installLocation = ([string]$entry.InstallLocation).Trim('"')
    $uninstaller = ([string]$entry.UninstallString).Trim('"')
    if ($entry.DisplayName -ne "RunOnMine" -or $entry.Publisher -ne "RunOnMine contributors") {
        throw "NSIS uninstall metadata is incorrect"
    }
    if (-not (Test-RunOnMineFullyQualifiedWindowsPath -Path $installLocation)) {
        throw "NSIS install location is not absolute"
    }
    foreach ($binary in @("runonmine.exe", "runonmine-agent.exe", "runonmine-desktop.exe", "runonmine-helper.exe")) {
        if (-not (Test-RunOnMinePath -LiteralPath (Join-Path $installLocation $binary) -PathType Leaf)) {
            throw "installed binary is missing: $binary"
        }
    }
    $programs = [Environment]::GetFolderPath("Programs")
    $startMenuCandidates = @(
        (Join-Path $programs "RunOnMine.lnk"),
        (Join-Path $programs "RunOnMine\RunOnMine.lnk")
    )
    $startMenu = $startMenuCandidates | Where-Object { Test-RunOnMinePath -LiteralPath $_ } | Select-Object -First 1
    $desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "RunOnMine.lnk"
    if (-not $startMenu) { throw "RunOnMine Start Menu shortcut is missing" }
    if (-not (Test-RunOnMinePath -LiteralPath $desktopShortcut)) { throw "RunOnMine desktop shortcut is missing" }
    Invoke-RunOnMineDesktopAcceptance -Desktop (Join-Path $installLocation "runonmine-desktop.exe") `
        -Root $root -ExpectNativeShell $true -RequireInteractiveWindow (-not $SkipInteractiveDesktop.IsPresent)

    $expectedUninstaller = Join-Path $installLocation "uninstall.exe"
    if (-not [string]::Equals($uninstaller, $expectedUninstaller, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "NSIS uninstall command is incorrect"
    }
    if (-not (Test-RunOnMinePath -LiteralPath $uninstaller -PathType Leaf)) { throw "NSIS uninstaller is missing" }
    $remove = Start-RunOnMineNativeProcess -FilePath $uninstaller -ArgumentList @("/S")
    if (-not $remove.WaitForExit(1800000)) {
        Stop-Process -Id $remove.Id -Force -ErrorAction SilentlyContinue
        [void]$remove.WaitForExit(30000)
        throw "NSIS uninstaller timed out after 1800 seconds"
    }
    $remove.WaitForExit()
    if ($remove.ExitCode -ne 0) { throw "NSIS uninstaller exited with code $($remove.ExitCode)" }
    $remove.Dispose()
    for ($attempt = 0; $attempt -lt 1800; $attempt++) {
        $registryRemains = Test-RunOnMinePath -LiteralPath $registryPath
        $managedRemains = Test-RunOnMineManagedFilesRemain -Location $installLocation
        if (-not $registryRemains -and -not $managedRemains) { break }
        Start-Sleep -Milliseconds 100
    }
    if (Test-RunOnMinePath -LiteralPath $registryPath) { throw "NSIS uninstall record remained after removal" }
    foreach ($managedName in @("runonmine.exe", "runonmine-agent.exe", "runonmine-desktop.exe", "runonmine-helper.exe", "uninstall.exe", "README.md")) {
        if (Test-RunOnMinePath -LiteralPath (Join-Path $installLocation $managedName)) {
            throw "NSIS managed file remained after removal: $managedName"
        }
    }
    if (Test-RunOnMinePath -LiteralPath $startMenu) { throw "RunOnMine Start Menu shortcut remained after removal" }
    if (Test-RunOnMinePath -LiteralPath $desktopShortcut) { throw "RunOnMine desktop shortcut remained after removal" }
    if (-not (Test-RunOnMinePath -LiteralPath $localDataRoot)) {
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
    if (-not $uninstaller -and (Test-RunOnMinePath -LiteralPath $registryPath)) {
        $cleanupEntry = Get-ItemProperty -LiteralPath $registryPath -ErrorAction SilentlyContinue
        if ($cleanupEntry) {
            $uninstaller = ([string]$cleanupEntry.UninstallString).Trim('"')
            if (-not $installLocation) {
                $installLocation = ([string]$cleanupEntry.InstallLocation).Trim('"')
            }
        }
    }
    if ($uninstaller -and (Test-RunOnMinePath -LiteralPath $uninstaller)) {
        try {
            $cleanup = Start-RunOnMineNativeProcess -FilePath $uninstaller -ArgumentList @("/S")
            if (-not $cleanup.WaitForExit(1800000)) {
                Stop-Process -Id $cleanup.Id -Force -ErrorAction SilentlyContinue
                [void]$cleanup.WaitForExit(30000)
            }
            $cleanup.WaitForExit()
            $cleanup.Dispose()
        } catch {}
        for ($attempt = 0; $attempt -lt 1800; $attempt++) {
            $registryRemains = Test-RunOnMinePath -LiteralPath $registryPath
            $managedRemains = $installLocation -and (Test-RunOnMineManagedFilesRemain -Location $installLocation)
            if (-not $registryRemains -and -not $managedRemains) { break }
            Start-Sleep -Milliseconds 100
        }
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $localDataRoot
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $roamingDataRoot
    if ($installLocation -and (Test-RunOnMinePath -LiteralPath $installLocation)) {
        $remaining = @(Get-ChildItem -LiteralPath $installLocation -Force -ErrorAction SilentlyContinue)
        if ($remaining.Count -eq 0) {
            Remove-Item -Force -LiteralPath $installLocation -ErrorAction SilentlyContinue
        }
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
}
