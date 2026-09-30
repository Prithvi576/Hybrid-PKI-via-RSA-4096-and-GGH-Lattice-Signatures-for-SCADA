#Requires -Version 5.1
<#
.SYNOPSIS
  Build/test (if needed) and launch the Hybrid PKI SCADA cryptography GUI.
#>
[CmdletBinding()]
param(
    [switch]$SkipTests,
    [switch]$ForceSetup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ScriptRoot

$BuildDir = Join-Path $ScriptRoot "build"
$StateFile = Join-Path $BuildDir "setup_state.json"
$GuiExe = Join-Path $BuildDir "hybrid_crypto_gui.exe"
$SetupScript = Join-Path $ScriptRoot "setup.ps1"
$PreferredToolchain = "C:\mingw64"
$OpenSslRootDefault = "C:\Program Files\OpenSSL-Win64"

function Write-Status {
    param(
        [ValidateSet("OK", "WARNING", "ERROR", "INFO")]
        [string]$Level,
        [string]$Message
    )
    $color = switch ($Level) {
        "OK" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR" { "Red" }
        default { "Cyan" }
    }
    Write-Host "[$Level] $Message" -ForegroundColor $color
}

function Test-DependencyReady {
    $gpp = Join-Path $PreferredToolchain "bin\g++.exe"
    $cmake = "C:\Program Files\CMake\bin\cmake.exe"
    if (-not (Test-Path -LiteralPath $cmake)) {
        $cmd = Get-Command cmake -ErrorAction SilentlyContinue
        if ($null -ne $cmd) { $cmake = $cmd.Source }
    }
    $opensslHeader = Join-Path $OpenSslRootDefault "include\openssl\evp.h"
    $opensslDll = Join-Path $OpenSslRootDefault "bin\libcrypto-4-x64.dll"

    $ready = (Test-Path -LiteralPath $gpp) -and
             (Test-Path -LiteralPath $cmake) -and
             (Test-Path -LiteralPath $opensslHeader) -and
             (Test-Path -LiteralPath $opensslDll) -and
             (Test-Path -LiteralPath $StateFile)

    return [pscustomobject]@{
        Ready  = [bool]$ready
        CMake  = $cmake
        Gpp    = $gpp
    }
}

function Invoke-Setup {
    Write-Status INFO "Running setup.ps1..."
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $SetupScript
    if ($LASTEXITCODE -ne 0) {
        Write-Status ERROR "setup.ps1 failed."
        exit 1
    }
}

Write-Host ""
Write-Host "Hybrid PKI SCADA - run.ps1" -ForegroundColor White
Write-Host ""

if (-not (Test-Path -LiteralPath $SetupScript)) {
    Write-Status ERROR "setup.ps1 is missing from the repository root."
    exit 1
}

$deps = Test-DependencyReady
if ($ForceSetup -or -not $deps.Ready) {
    if (-not $deps.Ready) {
        Write-Status WARNING "Setup incomplete or dependencies missing - invoking setup.ps1."
    }
    Invoke-Setup
    $deps = Test-DependencyReady
    if (-not $deps.Ready) {
        Write-Status ERROR "Dependencies still incomplete after setup."
        exit 1
    }
} else {
    Write-Status OK "Setup state present; dependencies look usable."
}

# Prefer the space-free toolchain on PATH for this session.
$bin = Join-Path $PreferredToolchain "bin"
$env:PATH = "$bin;C:\Program Files\CMake\bin;$env:PATH"
$env:OPENSSL_ROOT_DIR = $OpenSslRootDefault

$cmake = $deps.CMake
if (-not (Test-Path -LiteralPath $cmake)) {
    Write-Status ERROR "CMake not found."
    exit 1
}

$cache = Join-Path $BuildDir "CMakeCache.txt"
if (-not (Test-Path -LiteralPath $cache)) {
    Write-Status INFO "CMake cache missing - configuring..."
    & $cmake -S $ScriptRoot -B $BuildDir -G "MinGW Makefiles" `
        "-DCMAKE_BUILD_TYPE=Release" `
        "-DCMAKE_CXX_COMPILER=C:/mingw64/bin/g++.exe" `
        "-DCMAKE_MAKE_PROGRAM=C:/mingw64/bin/mingw32-make.exe" `
        "-DOPENSSL_ROOT_DIR=C:/Program Files/OpenSSL-Win64"
    if ($LASTEXITCODE -ne 0) {
        Write-Status ERROR "CMake configure failed."
        exit 1
    }
}

Write-Status INFO "Building backend and GUI..."
& $cmake --build $BuildDir --parallel
if ($LASTEXITCODE -ne 0) {
    Write-Status ERROR "Build failed - GUI will not launch."
    exit 1
}
Write-Status OK "Build succeeded"

if (-not $SkipTests) {
    Write-Status INFO "Running crypto tests before launch..."
    Push-Location -LiteralPath $BuildDir
    try {
        & $cmake -E chdir $BuildDir ctest --output-on-failure
        if ($LASTEXITCODE -ne 0) {
            Write-Status ERROR "Critical crypto tests failed - GUI will not launch."
            exit 1
        }
    } finally {
        Pop-Location
    }
    Write-Status OK "Crypto tests passed"
} else {
    Write-Status WARNING "SkipTests set - launching without re-running tests."
}

if (-not (Test-Path -LiteralPath $GuiExe)) {
    Write-Status ERROR "GUI executable missing: $GuiExe"
    exit 1
}

$cryptoDll = Join-Path $BuildDir "libcrypto-4-x64.dll"
if (-not (Test-Path -LiteralPath $cryptoDll)) {
    $srcDll = Join-Path $OpenSslRootDefault "bin\libcrypto-4-x64.dll"
    if (Test-Path -LiteralPath $srcDll) {
        Copy-Item -LiteralPath $srcDll -Destination $cryptoDll -Force
        Write-Status WARNING "Copied OpenSSL DLL beside GUI."
    } else {
        Write-Status ERROR "OpenSSL runtime DLL missing."
        exit 1
    }
}

Write-Status INFO "Launching GUI: $GuiExe"
$proc = Start-Process -FilePath $GuiExe -WorkingDirectory $BuildDir -PassThru
if ($null -eq $proc) {
    Write-Status ERROR "Failed to start GUI process."
    exit 1
}

Start-Sleep -Seconds 1
if ($proc.HasExited) {
    Write-Status ERROR "GUI exited immediately (code $($proc.ExitCode))."
    exit 1
}

Write-Status OK "GUI started (PID $($proc.Id)). Close the window when finished."
exit 0
