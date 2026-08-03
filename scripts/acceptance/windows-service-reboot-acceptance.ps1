param(
    [Parameter(Mandatory = $true)] [ValidateSet("Prepare", "Verify", "Cleanup")] [string]$Stage,
    [Parameter(Mandatory = $true)] [string]$RunOnMine,
    [Parameter(Mandatory = $true)] [string]$StatePath,
    [string]$AcceptanceRoot = "$env:ProgramData\RunOnMineWindowsAcceptance"
)
$ErrorActionPreference = "Stop"

$runOnMinePath = (Resolve-Path -LiteralPath $RunOnMine).Path
$stateFullPath = [IO.Path]::GetFullPath($StatePath)
$rootFullPath = [IO.Path]::GetFullPath($AcceptanceRoot)
$project = Join-Path $rootFullPath "project"
$private = Join-Path $rootFullPath "private"
$tokenFile = Join-Path $private "local-http.json"
$taskName = "RunOnMine Agent"

function Invoke-RunOnMine {
    param([Parameter(ValueFromRemainingArguments = $true)] [string[]]$Arguments)
    $output = (& $runOnMinePath @Arguments 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        throw "RunOnMine exited with code $LASTEXITCODE while running $($Arguments -join ' '): $output"
    }
    return $output
}

function Wait-Health {
    param([int]$Seconds = 30)
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri "http://127.0.0.1:47821/healthz" -Headers @{ Host = "127.0.0.1:47821" }
            if ($response.StatusCode -eq 200 -and $response.Content -eq "ok") { return }
        }
        catch {}
        Start-Sleep -Milliseconds 200
    }
    throw "RunOnMine agent health did not become ready"
}

function Assert-TaskContract {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $settings = $task.Settings
    if ($settings.RestartCount -ne 3) { throw "scheduled task RestartCount is $($settings.RestartCount), expected 3" }
    if ($settings.RestartInterval -ne "PT1M") { throw "scheduled task RestartInterval is $($settings.RestartInterval), expected PT1M" }
    if ([string]$settings.MultipleInstances -ne "IgnoreNew") { throw "scheduled task MultipleInstances is $($settings.MultipleInstances)" }
    if (-not $settings.StartWhenAvailable) { throw "scheduled task StartWhenAvailable is disabled" }
    if ([string]$task.Principal.RunLevel -ne "Limited") { throw "scheduled task RunLevel is $($task.Principal.RunLevel)" }
    $action = @($task.Actions | Select-Object -First 1)[0]
    if (-not $action -or [string]$action.Arguments -ne "run") { throw "scheduled task action arguments are not 'run'" }
    $agent = [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$action.Execute))
    if (-not (Test-Path -LiteralPath $agent -PathType Leaf)) { throw "versioned scheduled-task agent is missing" }
    if ($agent -notmatch "(?i)\\service-bin\\0\.1\.0-beta\.1\\runonmine-agent\.exe$") {
        throw "scheduled task does not use the versioned RunOnMine agent"
    }
    return [ordered]@{
        agent = $agent
        agent_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $agent).Hash.ToLowerInvariant()
    }
}

switch ($Stage) {
    "Prepare" {
        if (Test-Path -LiteralPath $stateFullPath) { throw "acceptance state already exists: $stateFullPath" }
        New-Item -ItemType Directory -Force -Path $project, $private | Out-Null
        Invoke-RunOnMine setup --root $project | Out-Null
        Invoke-RunOnMine connect local-http enable --token-output $tokenFile | Out-Null
        Invoke-RunOnMine service install | Out-Null
        Wait-Health
        $contract = Assert-TaskContract
        $status = Invoke-RunOnMine service status --json | ConvertFrom-Json
        if (-not $status.data.installed -or -not $status.data.running) { throw "scheduled task is not installed and running" }
        $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("o")
        [ordered]@{
            schema_version = 1
            source_revision = (& (Join-Path (Split-Path $runOnMinePath) "runonmine.exe") --version 2>$null | Out-String).Trim()
            boot_before = $boot
            agent_sha256 = $contract.agent_sha256
            prepared_at = [DateTime]::UtcNow.ToString("o")
        } | ConvertTo-Json | Set-Content -LiteralPath $stateFullPath -Encoding UTF8
        [ordered]@{
            status = "prepared"
            task_contract = "passed"
            agent_health = "passed"
            boot_before = $boot
        } | ConvertTo-Json -Compress | Write-Host
    }
    "Verify" {
        if (-not (Test-Path -LiteralPath $stateFullPath -PathType Leaf)) { throw "acceptance state is missing" }
        $state = Get-Content -Raw -LiteralPath $stateFullPath | ConvertFrom-Json
        $bootAfter = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString("o")
        if ($bootAfter -eq $state.boot_before) { throw "Windows did not reboot between service acceptance stages" }
        Wait-Health -Seconds 60
        $contract = Assert-TaskContract
        if ($contract.agent_sha256 -ne $state.agent_sha256) { throw "versioned agent changed across reboot" }
        $status = Invoke-RunOnMine service status --json | ConvertFrom-Json
        if (-not $status.data.installed -or -not $status.data.running) { throw "scheduled task did not recover after reboot" }
        [ordered]@{
            status = "passed"
            reboot = "passed"
            task_contract = "passed"
            agent_recovery = "passed"
            boot_before = $state.boot_before
            boot_after = $bootAfter
        } | ConvertTo-Json -Compress | Write-Host
    }
    "Cleanup" {
        try { Invoke-RunOnMine service uninstall | Out-Null } catch {}
        try { Invoke-RunOnMine connect local-http disable | Out-Null } catch {}
        Invoke-RunOnMine uninstall --purge --confirm PURGE | Out-Null
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            throw "RunOnMine scheduled task remained after cleanup"
        }
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $rootFullPath
        Remove-Item -Force -ErrorAction SilentlyContinue $stateFullPath
        Write-Host '{"status":"cleaned","scheduled_task_residue":"absent"}'
    }
}
