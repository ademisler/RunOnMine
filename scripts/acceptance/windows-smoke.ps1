param(
    [string]$RunOnMine = "runonmine.exe",
    [string]$Agent = "runonmine-agent.exe",
    [string]$Desktop = "",
    [string]$McpClient = ""
)
$ErrorActionPreference = "Stop"
. "$(Join-Path $PSScriptRoot "windows-desktop-acceptance.ps1")"
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("runonmine-acceptance-" + [guid]::NewGuid())
$sandboxHome = Join-Path $root "home"
$project = Join-Path $root "project"
$agentProcess = $null
New-Item -ItemType Directory -Force -Path $sandboxHome, $project | Out-Null

$old = @{
    HOME = $env:HOME
    USERPROFILE = $env:USERPROFILE
    APPDATA = $env:APPDATA
    LOCALAPPDATA = $env:LOCALAPPDATA
    RUNONMINE_TEST_FILE_SECRETS = $env:RUNONMINE_TEST_FILE_SECRETS
    RUNONMINE_MASTER_KEY = $env:RUNONMINE_MASTER_KEY
    RUNONMINE_DESKTOP_ACCEPTANCE_REPORT = $env:RUNONMINE_DESKTOP_ACCEPTANCE_REPORT
}
try {
    $env:HOME = $sandboxHome
    $env:USERPROFILE = $sandboxHome
    $env:APPDATA = Join-Path $root "appdata"
    $env:LOCALAPPDATA = Join-Path $root "localappdata"
    $env:RUNONMINE_TEST_FILE_SECRETS = "1"
    $env:RUNONMINE_MASTER_KEY = -join ((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }) | ForEach-Object { $_.ToString("x2") })

    (& $RunOnMine setup --root $project | Out-String) | Select-String -SimpleMatch "RunOnMine is initialized." | Out-Null
    (& $RunOnMine policy show | Out-String) | Select-String -SimpleMatch "AdminExec: Deny" | Out-Null
    (& $RunOnMine connect list | Out-String) | Select-String -SimpleMatch "LocalHttp" | Out-Null

    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
    $listener.Stop()
    $config = Get-ChildItem -Path $root -Filter config.toml -File -Recurse | Select-Object -First 1
    if (-not $config) { throw "isolated config.toml was not created" }
    $text = Get-Content -Raw $config.FullName
    $updated = [regex]::Replace($text, '(?m)^port = \d+$', "port = $port", 1)
    if ($updated -eq $text) { throw "isolated agent port was not updated" }
    [System.IO.File]::WriteAllText($config.FullName, $updated)

    $credential = Join-Path $root "local-http.json"
    & $RunOnMine connect local-http enable --token-output $credential | Out-Null
    if (-not (Test-Path $credential)) { throw "local HTTP credential file was not created" }
    $stdout = Join-Path $root "agent.stdout.log"
    $stderr = Join-Path $root "agent.stderr.log"
    $agentProcess = Start-Process -FilePath $Agent -ArgumentList "run" -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($agentProcess.HasExited) {
            throw "agent exited before readiness: $(Get-Content -Raw -ErrorAction SilentlyContinue $stderr)"
        }
        try {
            $health = Invoke-WebRequest -UseBasicParsing -TimeoutSec 1 -Uri "http://127.0.0.1:$port/healthz" -Headers @{ Host = "127.0.0.1:$port" }
            if ($health.StatusCode -eq 200 -and $health.Content -eq "ok") {
                $ready = $true
                break
            }
        } catch {}
        Start-Sleep -Milliseconds 100
    }
    if (-not $ready) { throw "agent did not become ready" }

    if ($McpClient) {
        & python $McpClient --url "http://127.0.0.1:$port/mcp" --token-file $credential --iterations 25
        if ($LASTEXITCODE -ne 0) { throw "MCP HTTP acceptance client failed" }
    }

    if ($Desktop) {
        Invoke-RunOnMineDesktopAcceptance -Desktop $Desktop -Root $root -ExpectNativeShell $true
    }

    (& $RunOnMine approvals list | Out-String) | Select-String -SimpleMatch "No pending approvals." | Out-Null
    & $RunOnMine audit tail --limit 5 | Out-Null
    (& $RunOnMine lock | Out-String) | Select-String -SimpleMatch "RunOnMine is locked." | Out-Null

    if ($agentProcess -and -not $agentProcess.HasExited) {
        Stop-Process -Id $agentProcess.Id -Force
        $agentProcess.WaitForExit()
        $agentProcess = $null
    }
    (& $RunOnMine uninstall --purge --confirm PURGE | Out-String) | Select-String -SimpleMatch "permanently removed" | Out-Null
    Write-Host "RunOnMine isolated Windows CLI, agent, MCP, desktop and purge smoke test passed."
}
finally {
    if ($agentProcess -and -not $agentProcess.HasExited) {
        Stop-Process -Id $agentProcess.Id -Force -ErrorAction SilentlyContinue
    }
    foreach ($name in $old.Keys) {
        [Environment]::SetEnvironmentVariable($name, $old[$name], "Process")
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
}
