if (-not ("RunOnMine.NativeWindow" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace RunOnMine {
    public static class NativeWindow {
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool IsWindowVisible(IntPtr hWnd);
    }
}
"@
}

function Assert-RunOnMineDesktopReport {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [bool]$ExpectNativeShell
    )
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "desktop acceptance report was not created: $Path"
    }
    $report = Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json
    $expectedViews = @("overview", "approvals", "connections", "permissions", "oauth", "audit", "diagnostics")
    $actualViews = @($report.rendered_views | ForEach-Object { $_.name })
    if (($actualViews -join ",") -ne ($expectedViews -join ",")) {
        throw "desktop acceptance did not render the exact seven views: $($actualViews -join ',')"
    }
    foreach ($view in $report.rendered_views) {
        if ($view.width -le 0 -or $view.height -le 0) {
            throw "desktop acceptance recorded an invalid viewport for $($view.name)"
        }
    }
    if ($report.schema_version -ne 1 -or $report.platform -ne "windows") {
        throw "desktop acceptance report identity is invalid"
    }
    if (($report.native_shell_actions -join ",") -ne "show,lock,quit") {
        throw "desktop native shell action contract is incomplete"
    }
    if (($report.default_viewport -join ",") -ne "1320,860") {
        throw "desktop default viewport contract changed"
    }
    if (($report.minimum_viewport -join ",") -ne "1040,680") {
        throw "desktop minimum viewport contract changed"
    }
    if (-not $report.application_icon) {
        throw "desktop application icon was not enabled"
    }
    if ([bool]$report.native_shell_available -ne $ExpectNativeShell) {
        throw "desktop native shell availability did not match the interactive Windows contract"
    }
    if ([bool]$report.close_to_tray -ne $ExpectNativeShell) {
        throw "desktop close-to-tray contract did not match native shell availability"
    }
    return $report
}

function Wait-RunOnMineMainWindow {
    param(
        [Parameter(Mandatory = $true)] [System.Diagnostics.Process]$Process,
        [int]$TimeoutMilliseconds = 15000
    )
    $deadline = [DateTime]::UtcNow.AddMilliseconds($TimeoutMilliseconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $Process.Refresh()
        if ($Process.HasExited) {
            return [IntPtr]::Zero
        }
        if ($Process.MainWindowHandle -ne [IntPtr]::Zero -and $Process.MainWindowTitle -eq "RunOnMine") {
            return $Process.MainWindowHandle
        }
        Start-Sleep -Milliseconds 50
    }
    return [IntPtr]::Zero
}

function Invoke-RunOnMineDesktopAcceptance {
    param(
        [Parameter(Mandatory = $true)] [string]$Desktop,
        [Parameter(Mandatory = $true)] [string]$Root,
        [bool]$ExpectNativeShell = $true
    )
    $reportPath = Join-Path $Root "desktop-acceptance.json"
    if (Test-Path -LiteralPath $reportPath) {
        Remove-Item -Force -LiteralPath $reportPath
    }
    $previousReport = $env:RUNONMINE_DESKTOP_ACCEPTANCE_REPORT
    $desktopProcess = $null
    try {
        $env:RUNONMINE_DESKTOP_ACCEPTANCE_REPORT = $reportPath
        $desktopProcess = Start-Process -FilePath $Desktop -PassThru
        $window = Wait-RunOnMineMainWindow -Process $desktopProcess
        if ($window -eq [IntPtr]::Zero) {
            throw "RunOnMine desktop did not expose its native main window"
        }
        if (-not $desktopProcess.WaitForExit(30000)) {
            throw "RunOnMine desktop acceptance did not finish"
        }
        if ($desktopProcess.ExitCode -ne 0) {
            throw "RunOnMine desktop acceptance exited with code $($desktopProcess.ExitCode)"
        }
        $desktopProcess = $null
        Assert-RunOnMineDesktopReport -Path $reportPath -ExpectNativeShell $ExpectNativeShell | Out-Null
    }
    finally {
        if ($desktopProcess -and -not $desktopProcess.HasExited) {
            Stop-Process -Id $desktopProcess.Id -Force -ErrorAction SilentlyContinue
            $desktopProcess.WaitForExit()
        }
        $env:RUNONMINE_DESKTOP_ACCEPTANCE_REPORT = $previousReport
    }

    if (-not $ExpectNativeShell) {
        return
    }
    $desktopProcess = $null
    try {
        $desktopProcess = Start-Process -FilePath $Desktop -PassThru
        $window = Wait-RunOnMineMainWindow -Process $desktopProcess
        if ($window -eq [IntPtr]::Zero) {
            throw "RunOnMine desktop did not expose a window for close-to-tray acceptance"
        }
        if (-not $desktopProcess.CloseMainWindow()) {
            throw "Windows did not deliver WM_CLOSE to RunOnMine desktop"
        }
        $deadline = [DateTime]::UtcNow.AddSeconds(10)
        do {
            Start-Sleep -Milliseconds 100
            $desktopProcess.Refresh()
            if ($desktopProcess.HasExited) {
                throw "RunOnMine desktop exited instead of remaining in the system tray"
            }
            $visible = [RunOnMine.NativeWindow]::IsWindowVisible($window)
        } while ($visible -and [DateTime]::UtcNow -lt $deadline)
        if ($visible) {
            throw "RunOnMine desktop window did not hide after WM_CLOSE"
        }
    }
    finally {
        if ($desktopProcess -and -not $desktopProcess.HasExited) {
            Stop-Process -Id $desktopProcess.Id -Force -ErrorAction SilentlyContinue
            $desktopProcess.WaitForExit()
        }
    }
}
