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

if (-not ("RunOnMineAcceptance.NativeLogon" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace RunOnMineAcceptance {
    public static class NativeLogon {
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool LogonUser(
            string username,
            string domain,
            string password,
            int logonType,
            int logonProvider,
            out IntPtr token
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);
    }
}
'@
}

$testId = [guid]::NewGuid().ToString("N").Substring(0, 10)
$userName = "RomAttack$testId"
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
$logonToken = [IntPtr]::Zero
$attackerIdentity = $null
$impersonationContext = $null

try {
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

    New-LocalUser -Name $userName -Password $password -PasswordNeverExpires -AccountNeverExpires | Out-Null
    $userCreated = $true
    if (-not [RunOnMineAcceptance.NativeLogon]::LogonUser(
        $userName,
        $env:COMPUTERNAME,
        $passwordText,
        2,
        0,
        [ref]$logonToken
    )) {
        $win32Error = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "failed to log on the temporary second Windows user (win32=$win32Error)"
    }

    $attackerIdentity = [Security.Principal.WindowsIdentity]::new($logonToken)
    if ($attackerIdentity.User.Value -eq $identity.User.Value) {
        throw "temporary second-user token unexpectedly matched the owner SID"
    }
    $impersonationContext = $attackerIdentity.Impersonate()
    try {
        $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $currentPrincipal = [Security.Principal.WindowsPrincipal]::new($currentIdentity)
        if ($currentIdentity.User.Value -ne $attackerIdentity.User.Value) {
            throw "thread impersonation did not activate the temporary second-user SID"
        }
        if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            throw "temporary second-user token unexpectedly has Administrator membership"
        }

        $pipe = [IO.Pipes.NamedPipeClientStream]::new(
            ".",
            "RunOnMine.Helper",
            [IO.Pipes.PipeDirection]::InOut,
            [IO.Pipes.PipeOptions]::Asynchronous
        )
        try {
            try {
                $pipe.Connect(5000)
                $attack = @{ outcome = "connected"; exception = "" }
            }
            catch [UnauthorizedAccessException] {
                $attack = @{ outcome = "denied"; exception = $_.Exception.GetType().FullName }
            }
            catch [IO.IOException] {
                $attack = @{ outcome = "denied"; exception = $_.Exception.GetType().FullName }
            }
            catch [TimeoutException] {
                $attack = @{ outcome = "timeout"; exception = $_.Exception.GetType().FullName }
            }
        }
        finally {
            $pipe.Dispose()
        }
    }
    finally {
        if ($impersonationContext) {
            $impersonationContext.Undo()
            $impersonationContext.Dispose()
            $impersonationContext = $null
        }
    }
    if ($attack.outcome -ne "denied") {
        throw "second Windows user was not denied by the helper pipe: $($attack | ConvertTo-Json -Compress)"
    }

    Invoke-RunOnMineHelperCommand -Arguments @("admin", "uninstall") | Out-Null
    Invoke-RunOnMineHelperCommand -Arguments @("admin", "uninstall") | Out-Null
    $helperInstalled = $false

    Write-Host "RunOnMine Windows LocalSystem helper owner access, second-user token named-pipe denial and idempotent uninstall passed."
}
finally {
    if ($impersonationContext) {
        try { $impersonationContext.Undo() } catch {}
        try { $impersonationContext.Dispose() } catch {}
    }
    if ($attackerIdentity) {
        try { $attackerIdentity.Dispose() } catch {}
    }
    if ($logonToken -ne [IntPtr]::Zero) {
        [void][RunOnMineAcceptance.NativeLogon]::CloseHandle($logonToken)
    }
    $passwordText = $null
    $password = $null
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
}
exit 0
