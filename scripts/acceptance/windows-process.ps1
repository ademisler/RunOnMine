function ConvertTo-RunOnMineNativeArgument {
    param([AllowEmptyString()] [string]$Argument)
    if ($Argument.Length -gt 0 -and $Argument -notmatch '[\s"]') {
        return $Argument
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0
    foreach ($character in $Argument.ToCharArray()) {
        if ($character -eq [char]92) {
            $backslashes += 1
            continue
        }
        if ($character -eq [char]34) {
            [void]$builder.Append(('\' * (($backslashes * 2) + 1)) -join '')
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }
        if ($backslashes -gt 0) {
            [void]$builder.Append(('\' * $backslashes) -join '')
            $backslashes = 0
        }
        [void]$builder.Append($character)
    }
    if ($backslashes -gt 0) {
        [void]$builder.Append(('\' * ($backslashes * 2)) -join '')
    }
    [void]$builder.Append('"')
    return $builder.ToString()
}

function Start-RunOnMineNativeProcess {
    param(
        [Parameter(Mandatory = $true)] [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [switch]$CaptureOutput,
        [switch]$CreateNoWindow
    )
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $FilePath
    $startInfo.Arguments = (($ArgumentList | ForEach-Object {
        ConvertTo-RunOnMineNativeArgument -Argument ([string]$_)
    }) -join ' ')
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $CreateNoWindow.IsPresent
    if ($CaptureOutput) {
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    if (-not $process.Start()) {
        $process.Dispose()
        throw "failed to start native process: $FilePath"
    }
    return $process
}

function Invoke-RunOnMineNativeProcess {
    param(
        [Parameter(Mandatory = $true)] [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [int]$TimeoutMilliseconds = 120000
    )
    $process = Start-RunOnMineNativeProcess -FilePath $FilePath -ArgumentList $ArgumentList `
        -CaptureOutput -CreateNoWindow
    try {
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutMilliseconds)) {
            $process.Refresh()
            if ($process.HasExited) {
                $process.WaitForExit()
            }
            else {
                $cleanupError = ""
                try {
                    $process.Kill()
                }
                catch {
                    $process.Refresh()
                    if (-not $process.HasExited) {
                        $cleanupError = $_.Exception.Message
                        try {
                            $taskkill = [System.Diagnostics.Process]::Start(
                                "$env:SystemRoot\System32\taskkill.exe",
                                "/PID $($process.Id) /T /F"
                            )
                            if ($taskkill) {
                                [void]$taskkill.WaitForExit(30000)
                                $taskkill.Dispose()
                            }
                        }
                        catch {
                            $cleanupError = "$cleanupError; taskkill: $($_.Exception.Message)"
                        }
                    }
                }
                [void]$process.WaitForExit(30000)
                [void]$stdoutTask.GetAwaiter().GetResult()
                [void]$stderrTask.GetAwaiter().GetResult()
                $suffix = if ([string]::IsNullOrWhiteSpace($cleanupError)) {
                    ""
                }
                else {
                    "; cleanup: $cleanupError"
                }
                throw "native process timed out after $TimeoutMilliseconds ms: $FilePath $($ArgumentList -join ' ')$suffix"
            }
        }
        $process.WaitForExit()
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        return [pscustomobject]@{
            ExitCode = [int]$process.ExitCode
            Stdout = $stdout
            Stderr = $stderr
        }
    }
    finally {
        $process.Dispose()
    }
}
