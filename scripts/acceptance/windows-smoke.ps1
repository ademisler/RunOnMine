param(
    [string]$RunOnMine = "runonmine.exe",
    [string]$Agent = "runonmine-agent.exe",
    [string]$Desktop = "",
    [string]$McpClient = "",
    [switch]$SkipInteractiveDesktop
)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Net.Http
. "$(Join-Path $PSScriptRoot "windows-desktop-acceptance.ps1")"
$root = Join-Path ([System.IO.Path]::GetTempPath()) ("runonmine-acceptance-" + [guid]::NewGuid())
$pathsRoot = Join-Path $root "runonmine"
$project = Join-Path $root "project"
$agentProcess = $null
$clientProcess = $null
New-Item -ItemType Directory -Force -Path $pathsRoot, $project | Out-Null

$old = @{
    RUNONMINE_TEST_FILE_SECRETS = $env:RUNONMINE_TEST_FILE_SECRETS
    RUNONMINE_TEST_PATHS_ROOT = $env:RUNONMINE_TEST_PATHS_ROOT
    RUNONMINE_AGENT_STATUS_FILE = $env:RUNONMINE_AGENT_STATUS_FILE
    RUNONMINE_MASTER_KEY = $env:RUNONMINE_MASTER_KEY
    RUNONMINE_DESKTOP_ACCEPTANCE_REPORT = $env:RUNONMINE_DESKTOP_ACCEPTANCE_REPORT
}
try {
    $env:RUNONMINE_TEST_FILE_SECRETS = "1"
    $env:RUNONMINE_TEST_PATHS_ROOT = $pathsRoot
    $env:RUNONMINE_AGENT_STATUS_FILE = Join-Path $root "agent-runtime.json"
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

    $mcpResult = $null
    if ($McpClient) {
        $approvedPath = Join-Path $project "approved.txt"
        $clientStdout = Join-Path $root "mcp-client.stdout.log"
        $clientStderr = Join-Path $root "mcp-client.stderr.log"
        $python = Get-Command python -ErrorAction Stop
        $clientProcess = Start-RunOnMineNativeProcess -FilePath $python.Source -ArgumentList @(
            $McpClient,
            "--url", "http://127.0.0.1:$port/mcp",
            "--token-file", $credential,
            "--iterations", "25",
            "--approval-write-path", $approvedPath
        ) -CaptureOutput -CreateNoWindow
        $approvalId = $null
        $lastApprovalError = ""
        for ($attempt = 0; $attempt -lt 1800; $attempt++) {
            $approvalPoll = Invoke-RunOnMineNativeProcess -FilePath $RunOnMine `
                -ArgumentList @("approvals", "list") -TimeoutMilliseconds 10000
            if ($approvalPoll.ExitCode -eq 0) {
                $match = [regex]::Match($approvalPoll.Stdout, '(?m)^([0-9a-fA-F-]{36})  ')
                if ($match.Success) {
                    $approvalId = $match.Groups[1].Value
                    $approval = Invoke-RunOnMineNativeProcess -FilePath $RunOnMine `
                        -ArgumentList @("approvals", "approve", $approvalId, "--once") `
                        -TimeoutMilliseconds 10000
                    if ($approval.ExitCode -ne 0) {
                        throw "owner approval failed with code $($approval.ExitCode): $($approval.Stderr)"
                    }
                    break
                }
            } else {
                $lastApprovalError = $approvalPoll.Stderr
            }
            if ($clientProcess.HasExited) { break }
            Start-Sleep -Milliseconds 50
        }
        if (-not $clientProcess.WaitForExit(120000)) {
            $clientProcess.Kill()
            $clientProcess.WaitForExit()
            throw "MCP HTTP acceptance client timed out"
        }
        $clientOutput = $clientProcess.StandardOutput.ReadToEnd()
        $clientFailure = $clientProcess.StandardError.ReadToEnd()
        $clientProcess.WaitForExit()
        [System.IO.File]::WriteAllText($clientStdout, $clientOutput)
        [System.IO.File]::WriteAllText($clientStderr, $clientFailure)
        if ($clientProcess.ExitCode -ne 0 -or -not $approvalId) {
            throw "MCP HTTP acceptance client failed with code $($clientProcess.ExitCode): $clientFailure; last approval poll error: $lastApprovalError"
        }
        $clientProcess.Dispose()
        $clientProcess = $null
        $mcpResult = $clientOutput | ConvertFrom-Json
        if ($mcpResult.status -ne "passed" -or -not $mcpResult.approved_write -or -not $mcpResult.denied_admin_call) {
            throw "MCP HTTP acceptance did not prove approved fs_write and denied admin_exec"
        }
        if ((Get-Content -Raw -LiteralPath $approvedPath) -ne "approved MCP acceptance write`n") {
            throw "MCP approved write content is incorrect"
        }
    }

    if ($Desktop) {
        Invoke-RunOnMineDesktopAcceptance -Desktop $Desktop -Root $root -ExpectNativeShell $true `
            -RequireInteractiveWindow (-not $SkipInteractiveDesktop.IsPresent)
    }

    $pendingAfterMcp = Invoke-RunOnMineNativeProcess -FilePath $RunOnMine `
        -ArgumentList @("approvals", "list") -TimeoutMilliseconds 10000
    if ($pendingAfterMcp.ExitCode -ne 0 -or $pendingAfterMcp.Stdout -notmatch 'No pending approvals\.') {
        throw "pending approval inventory was not empty after MCP acceptance: $($pendingAfterMcp.Stderr)"
    }
    & $RunOnMine audit tail --limit 5 | Out-Null
    (& $RunOnMine lock | Out-String) | Select-String -SimpleMatch "RunOnMine is locked." | Out-Null

    $staleToken = (Get-Content -Raw -LiteralPath $credential | ConvertFrom-Json).bearer_token
    $payload = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"stale-token-check","version":"1"}}}'
    $handler = [System.Net.Http.HttpClientHandler]::new()
    $handler.UseProxy = $false
    $http = [System.Net.Http.HttpClient]::new($handler)
    try {
        $request = [System.Net.Http.HttpRequestMessage]::new(
            [System.Net.Http.HttpMethod]::Post,
            "http://127.0.0.1:$port/mcp"
        )
        $request.Headers.Authorization = [System.Net.Http.Headers.AuthenticationHeaderValue]::new("Bearer", $staleToken)
        $request.Headers.Accept.ParseAdd("application/json, text/event-stream")
        $request.Headers.Host = "127.0.0.1:$port"
        $request.Content = [System.Net.Http.StringContent]::new($payload, [Text.Encoding]::UTF8, "application/json")
        $response = $http.SendAsync($request).GetAwaiter().GetResult()
        try {
            if ([int]$response.StatusCode -ne 401) {
                throw "stale local HTTP token returned $([int]$response.StatusCode), expected 401"
            }
        }
        finally {
            $response.Dispose()
            $request.Dispose()
        }
    }
    finally {
        $http.Dispose()
        $handler.Dispose()
    }

    if ($agentProcess -and -not $agentProcess.HasExited) {
        Stop-Process -Id $agentProcess.Id -Force
        $agentProcess.WaitForExit()
        $agentProcess = $null
    }
    (& $RunOnMine uninstall --purge --confirm PURGE | Out-String) | Select-String -SimpleMatch "permanently removed" | Out-Null
    if ($SkipInteractiveDesktop) {
        Write-Host "RunOnMine isolated Windows CLI, agent, MCP, desktop render/report and purge smoke test passed; interactive HWND/tray lifecycle was not claimed."
    } else {
        Write-Host "RunOnMine isolated Windows CLI, agent, MCP, interactive desktop and purge smoke test passed."
    }
}
finally {
    if ($clientProcess) {
        if (-not $clientProcess.HasExited) {
            $clientProcess.Kill()
            $clientProcess.WaitForExit()
        }
        $clientProcess.Dispose()
    }
    if ($agentProcess -and -not $agentProcess.HasExited) {
        Stop-Process -Id $agentProcess.Id -Force -ErrorAction SilentlyContinue
    }
    foreach ($name in $old.Keys) {
        [Environment]::SetEnvironmentVariable($name, $old[$name], "Process")
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
}
