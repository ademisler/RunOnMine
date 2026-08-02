param(
    [Parameter(Mandatory = $true)] [string]$Desktop
)
$ErrorActionPreference = "Stop"
$desktopPath = (Resolve-Path -LiteralPath $Desktop).Path
$bytes = [System.IO.File]::ReadAllBytes($desktopPath)
if ($bytes.Length -lt 512 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw "desktop executable is not a valid PE file"
}
$peOffset = [BitConverter]::ToInt32($bytes, 0x3c)
if ([BitConverter]::ToUInt32($bytes, $peOffset) -ne 0x00004550) {
    throw "desktop executable has no PE signature"
}
$machine = [BitConverter]::ToUInt16($bytes, $peOffset + 4)
if ($machine -ne 0x8664) { throw "desktop executable is not x86_64 PE" }
$optionalHeader = $peOffset + 24
$subsystem = [BitConverter]::ToUInt16($bytes, $optionalHeader + 68)
if ($subsystem -ne 2) { throw "desktop release does not use the Windows GUI subsystem" }

$version = (Get-Item -LiteralPath $desktopPath).VersionInfo
if ($version.ProductName -ne "RunOnMine") { throw "PE ProductName resource is missing" }
if ($version.FileDescription -ne "RunOnMine security control center") {
    throw "PE FileDescription resource is missing"
}
if ($version.OriginalFilename -ne "runonmine-desktop.exe") {
    throw "PE OriginalFilename resource is missing"
}

if (-not ("RunOnMine.PeIcon" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
namespace RunOnMine {
    public static class PeIcon {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern IntPtr LoadLibraryEx(string path, IntPtr file, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FreeLibrary(IntPtr module);
        [DllImport("user32.dll", EntryPoint = "LoadImageW", SetLastError = true)]
        public static extern IntPtr LoadImage(IntPtr instance, IntPtr name, uint type, int width, int height, uint flags);
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyIcon(IntPtr icon);
    }
}
"@
}
$module = [RunOnMine.PeIcon]::LoadLibraryEx($desktopPath, [IntPtr]::Zero, 0x22)
if ($module -eq [IntPtr]::Zero) { throw "PE resources could not be mapped" }
try {
    $icon = [RunOnMine.PeIcon]::LoadImage($module, [IntPtr]1, 1, 32, 32, 0)
    if ($icon -eq [IntPtr]::Zero) { throw "PE application icon resource ID 1 is missing" }
    [RunOnMine.PeIcon]::DestroyIcon($icon) | Out-Null
}
finally {
    [RunOnMine.PeIcon]::FreeLibrary($module) | Out-Null
}

$mt = Get-Command mt.exe -ErrorAction SilentlyContinue
if (-not $mt) {
    $kits = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $mt = Get-ChildItem -Path $kits -Filter mt.exe -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
}
if (-not $mt) { throw "Windows SDK mt.exe is unavailable" }
$mtPath = if ($mt.Path) { $mt.Path } else { $mt.FullName }
if (-not $mtPath) { throw "Windows SDK mt.exe path is unavailable" }
$manifest = Join-Path ([System.IO.Path]::GetTempPath()) ("runonmine-manifest-" + [guid]::NewGuid() + ".xml")
try {
    & $mtPath -nologo "-inputresource:$desktopPath;#1" "-out:$manifest"
    if ($LASTEXITCODE -ne 0) { throw "mt.exe could not extract the desktop manifest" }
    $manifestText = Get-Content -Raw -LiteralPath $manifest
    foreach ($required in @('level="asInvoker"', '>PerMonitorV2<', '>true</longPathAware>')) {
        if (-not $manifestText.Contains($required)) {
            throw "desktop manifest is missing $required"
        }
    }
}
finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $manifest
}
Write-Host "RunOnMine Windows PE subsystem, metadata, icon and manifest acceptance passed."
