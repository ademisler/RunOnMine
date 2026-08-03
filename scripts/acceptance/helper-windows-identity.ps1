param(
    [Parameter(Mandatory = $true)] [string]$RunOnMine,
    [Parameter(Mandatory = $true)] [string]$AllowedProgram
)
$ErrorActionPreference = "Stop"
. "$(Join-Path $PSScriptRoot "windows-process.ps1")"

$runOnMinePath = (Resolve-Path -LiteralPath $RunOnMine).Path
$allowedProgramPath = (Resolve-Path -LiteralPath $AllowedProgram).Path
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Windows helper identity acceptance requires an elevated Administrator token"
}

function Invoke-RunOnMineHelperCommand {
    param(
        [Parameter(Mandatory = $true)] [string[]]$Arguments,
        [int]$TimeoutMilliseconds = 120000,
        [switch]$IgnoreFailure
    )
    $result = Invoke-RunOnMineNativeProcess -FilePath $runOnMinePath -ArgumentList $Arguments `
        -TimeoutMilliseconds $TimeoutMilliseconds
    if (-not $IgnoreFailure -and $result.ExitCode -ne 0) {
        $detail = ($result.Stdout + $result.Stderr).Trim()
        throw "RunOnMine exited with code $($result.ExitCode) while running $($Arguments -join ' '): $detail"
    }
    return $result
}

function Invoke-CleanupNativeCommand {
    param(
        [Parameter(Mandatory = $true)] [string]$FilePath,
        [Parameter(Mandatory = $true)] [string[]]$Arguments
    )
    try {
        Invoke-RunOnMineNativeProcess -FilePath $FilePath -ArgumentList $Arguments `
            -TimeoutMilliseconds 30000 | Out-Null
    }
    catch {}
}

$testId = [guid]::NewGuid().ToString("N").Substring(0, 10)
$userName = "RomAttack$testId"
$taskName = "RunOnMine helper attacker $testId"
$root = Join-Path $env:ProgramData ("RunOnMineHelperAcceptance-" + $testId)
$attackerScript = Join-Path $root "attacker.ps1"
$resultPath = Join-Path $root "attacker-result.json"
$passwordBytes = New-Object byte[] 32
$random = [Security.Cryptography.RandomNumberGenerator]::Create()
try {
    $random.GetBytes($passwordBytes)
}
finally {
    $random.Dispose()
}
$passwordText = [Convert]::ToBase64String($passwordBytes) + "aA1!"
[Array]::Clear($passwordBytes, 0, $passwordBytes.Length)
$password = ConvertTo-SecureString $passwordText -AsPlainText -Force
$helperInstalled = $false
$userCreated = $false
$taskRegistered = $false

try {
    New-Item -ItemType Directory -Force -Path $root | Out-Null
    $icacls = Invoke-RunOnMineNativeProcess -FilePath "$env:SystemRoot\System32\icacls.exe" -ArgumentList @(
        $root,
        "/inheritance:r",
        "/grant", "*S-1-5-18:(OI)(CI)F",
        "/grant", "*S-1-5-32-544:(OI)(CI)F",
        "/grant", "*S-1-5-32-545:(OI)(CI)M"
    ) -TimeoutMilliseconds 30000
    if ($icacls.ExitCode -ne 0) {
        throw "failed to prepare the helper acceptance directory ACL: $($icacls.Stderr)"
    }

    Invoke-RunOnMineHelperCommand -Arguments @("admin", "install", "--allow-program", $allowedProgramPath) | Out-Null
    $helperInstalled = $true

    $statusResult = Invoke-RunOnMineHelperCommand -Arguments @("admin", "status")
    try {
        $status = $statusResult.Stdout | ConvertFrom-Json
    }
    catch {
        throw "owner helper status was not valid JSON: $($statusResult.Stdout)"
    }
    if (
        -not [bool]$status.installed -or
        -not [bool]$status.running -or
        -not [bool]$status.available -or
        [string]$status.state.status -ne "available"
    ) {
        throw "owner helper health check failed: $($statusResult.Stdout)"
    }
    $service = Get-CimInstance Win32_Service -Filter "Name='RunOnMineHelper'"
    if (-not $service) { throw "RunOnMineHelper service was not registered" }
    if ($service.StartName -ne "LocalSystem" -and $service.StartName -ne "LocalSystem account") {
        throw "RunOnMineHelper does not run as LocalSystem: $($service.StartName)"
    }
    if ($service.State -ne "Running") { throw "RunOnMineHelper is not running" }

    @'
$ErrorActionPreference = "Stop"
$resultPath = '__RESULT_PATH__'
try {
    $pipe = [IO.Pipes.NamedPipeClientStream]::new(
        ".",
        "RunOnMine.Helper",
        [IO.Pipes.PipeDirection]::InOut,
        [IO.Pipes.PipeOptions]::Asynchronous
    )
    try {
        $pipe.Connect(5000)
        $result = @{ outcome = "connected"; exception = "" }
    }
    catch [UnauthorizedAccessException] {
        $result = @{ outcome = "denied"; exception = $_.Exception.GetType().FullName }
    }
    catch [IO.IOException] {
        $result = @{ outcome = "denied"; exception = $_.Exception.GetType().FullName }
    }
    catch [TimeoutException] {
        $result = @{ outcome = "timeout"; exception = $_.Exception.GetType().FullName }
    }
    finally {
        $pipe.Dispose()
    }
}
catch {
    $result = @{ outcome = "failed"; exception = $_.Exception.GetType().FullName }
}
$result | ConvertTo-Json -Compress | Set-Content -LiteralPath $resultPath -Encoding UTF8
'@.Replace('__RESULT_PATH__', $resultPath.Replace("'", "''")) |
        Set-Content -LiteralPath $attackerScript -Encoding UTF8

    New-LocalUser -Name $userName -Password $password -PasswordNeverExpires -AccountNeverExpires | Out-Null
    $userCreated = $true
    $qualifiedUser = "$env:COMPUTERNAME\$userName"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument (
        "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$attackerScript`""
    )
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $taskName -Action $action -Settings $settings `
        -User $qualifiedUser -Password $passwordText -RunLevel Limited -Force | Out-Null
    $taskRegistered = $true

    Start-ScheduledTask -TaskName $taskName
    for ($attempt = 0; $attempt -lt 300 -and -not (Test-Path -LiteralPath $resultPath); $attempt++) {
        Start-Sleep -Milliseconds 100
    }
    if (-not (Test-Path -LiteralPath $resultPath)) {
        $task = Get-ScheduledTaskInfo -TaskName $taskName
        throw "attacker task did not write a result; last result=$($task.LastTaskResult)"
    }
    $attack = Get-Content -Raw -LiteralPath $resultPath | ConvertFrom-Json
    if ($attack.outcome -ne "denied") {
        throw "second Windows user was not denied by the helper pipe: $($attack | ConvertTo-Json -Compress)"
    }

    Invoke-RunOnMineHelperCommand -Arguments @("admin", "uninstall") | Out-Null
    Invoke-RunOnMineHelperCommand -Arguments @("admin", "uninstall") | Out-Null
    $helperInstalled = $false

    Write-Host "RunOnMine Windows LocalSystem helper owner access, second-user named-pipe denial and idempotent uninstall passed."
}
finally {
    $passwordText = $null
    $password = $null
    if ($taskRegistered) {
        Invoke-CleanupNativeCommand -FilePath "$env:SystemRoot\System32\schtasks.exe" `
            -Arguments @("/Delete", "/TN", $taskName, "/F")
    }
    if ($userCreated) {
        Invoke-CleanupNativeCommand -FilePath "$env:SystemRoot\System32\net.exe" `
            -Arguments @("user", $userName, "/delete")
    }
    if ($helperInstalled) {
        try {
            Invoke-RunOnMineHelperCommand -Arguments @("admin", "uninstall") `
                -TimeoutMilliseconds 60000 -IgnoreFailure | Out-Null
        }
        catch {}
    }
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $root
}
exit 0
