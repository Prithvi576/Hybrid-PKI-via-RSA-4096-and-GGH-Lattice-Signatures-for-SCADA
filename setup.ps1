#Requires -Version 5.1
<#
.SYNOPSIS
  Idempotent Windows setup for Hybrid PKI SCADA (Person 1 cryptography).

.DESCRIPTION
  Detects/installs CMake, a modern MinGW-w64 toolchain, and OpenSSL from trusted
  winget packages, configures the project, builds, and runs crypto tests.
#>
[CmdletBinding()]
param(
    [switch]$SkipInstall,
    [switch]$SkipTests
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location -LiteralPath $ScriptRoot

$StateDir = Join-Path $ScriptRoot "build"
$StateFile = Join-Path $StateDir "setup_state.json"
$PreferredToolchain = "C:\mingw64"
$OpenSslRootDefault = "C:\Program Files\OpenSSL-Win64"
$OldMingwMarker = "C:\MinGW\bin"

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

function Test-IsWindows {
    return $env:OS -eq "Windows_NT"
}

function Get-CommandPath {
    param([string]$Name)
    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if ($null -eq $cmd) { return $null }
    return $cmd.Source
}

function Get-GccMajorVersion {
    param([string]$GppPath)
    if (-not $GppPath -or -not (Test-Path -LiteralPath $GppPath)) { return 0 }
    $out = & $GppPath --version 2>&1 | Out-String
    if ($out -match "\)\s+(\d+)\.") {
        return [int]$Matches[1]
    }
    return 0
}

function Ensure-Winget {
    $winget = Get-CommandPath "winget"
    if ($null -eq $winget) {
        Write-Status ERROR "winget is not available. Install App Installer from Microsoft Store, then re-run setup.ps1."
        exit 1
    }
    Write-Status OK "winget found: $winget"
    return $winget
}

function Install-WingetPackage {
    param(
        [string]$Id,
        [string]$DisplayName
    )
    Write-Status INFO "Installing $DisplayName via winget ($Id)..."
    & winget install --id $Id --accept-package-agreements --accept-source-agreements --disable-interactivity
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1978335189) {
        # -1978335189 often means already installed
        Write-Status ERROR "Failed to install $DisplayName (winget exit $LASTEXITCODE)."
        exit 1
    }
    Write-Status OK "$DisplayName install step finished"
}

function Find-WinLibsSource {
    $packagesRoot = Join-Path $env:LOCALAPPDATA "Microsoft\WinGet\Packages"
    if (-not (Test-Path -LiteralPath $packagesRoot)) { return $null }
    $candidate = Get-ChildItem -LiteralPath $packagesRoot -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like "BrechtSanders.WinLibs.POSIX.UCRT*" } |
        Select-Object -First 1
    if ($null -eq $candidate) { return $null }
    $mingw = Join-Path $candidate.FullName "mingw64"
    if (Test-Path -LiteralPath (Join-Path $mingw "bin\g++.exe")) {
        return $mingw
    }
    return $null
}

function Ensure-Toolchain {
    param([switch]$AllowInstall)

    $gppPreferred = Join-Path $PreferredToolchain "bin\g++.exe"
    $major = Get-GccMajorVersion $gppPreferred
    if ($major -ge 11) {
        Write-Status OK "Usable MinGW-w64 toolchain at $PreferredToolchain (GCC $major)"
        return $PreferredToolchain
    }

    $source = Find-WinLibsSource
    if ($null -ne $source) {
        Write-Status INFO "Copying WinLibs toolchain to $PreferredToolchain (paths with spaces break MinGW linking)..."
        if (Test-Path -LiteralPath $PreferredToolchain) {
            $item = Get-Item -LiteralPath $PreferredToolchain
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
                cmd /c "rmdir `"$PreferredToolchain`""
            }
        }
        New-Item -ItemType Directory -Force -Path $PreferredToolchain | Out-Null
        & robocopy $source $PreferredToolchain /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
        $major = Get-GccMajorVersion $gppPreferred
        if ($major -ge 11) {
            Write-Status OK "Toolchain ready at $PreferredToolchain (GCC $major)"
            return $PreferredToolchain
        }
    }

    if (-not $AllowInstall) {
        Write-Status ERROR "No usable MinGW-w64 GCC (>= 11) found. Re-run without -SkipInstall."
        exit 1
    }

    Write-Status WARNING "Ancient MinGW (e.g. GCC 6.3 under C:\MinGW) cannot build this project."
    Install-WingetPackage -Id "BrechtSanders.WinLibs.POSIX.UCRT" -DisplayName "WinLibs MinGW-w64 (UCRT)"
    $source = Find-WinLibsSource
    if ($null -eq $source) {
        Write-Status ERROR "WinLibs installed but mingw64\bin\g++.exe was not found under WinGet Packages."
        exit 1
    }
    Write-Status INFO "Copying WinLibs toolchain to $PreferredToolchain..."
    if (Test-Path -LiteralPath $PreferredToolchain) {
        $item = Get-Item -LiteralPath $PreferredToolchain -ErrorAction SilentlyContinue
        if ($item -and ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            cmd /c "rmdir `"$PreferredToolchain`""
        }
    }
    New-Item -ItemType Directory -Force -Path $PreferredToolchain | Out-Null
    & robocopy $source $PreferredToolchain /E /NFL /NDL /NJH /NJS /nc /ns /np | Out-Null
    $major = Get-GccMajorVersion $gppPreferred
    if ($major -lt 11) {
        Write-Status ERROR "Toolchain copy failed or GCC remains too old."
        exit 1
    }
    Write-Status OK "Toolchain ready at $PreferredToolchain (GCC $major)"
    return $PreferredToolchain
}

function Ensure-CMake {
    param([switch]$AllowInstall)
    $cmake = Get-CommandPath "cmake"
    if ($null -eq $cmake) {
        $fallback = "C:\Program Files\CMake\bin\cmake.exe"
        if (Test-Path -LiteralPath $fallback) { $cmake = $fallback }
    }
    if ($null -ne $cmake) {
        $ver = & $cmake --version 2>&1 | Select-Object -First 1
        Write-Status OK "CMake found: $cmake ($ver)"
        return $cmake
    }
    if (-not $AllowInstall) {
        Write-Status ERROR "CMake not found."
        exit 1
    }
    Install-WingetPackage -Id "Kitware.CMake" -DisplayName "CMake"
    $cmake = "C:\Program Files\CMake\bin\cmake.exe"
    if (-not (Test-Path -LiteralPath $cmake)) {
        $cmake = Get-CommandPath "cmake"
    }
    if ($null -eq $cmake -or -not (Test-Path -LiteralPath $cmake)) {
        Write-Status ERROR "CMake install did not place cmake.exe on PATH. Open a new shell and retry."
        exit 1
    }
    Write-Status OK "CMake ready: $cmake"
    return $cmake
}

function Ensure-OpenSSL {
    param([switch]$AllowInstall)
    $root = $OpenSslRootDefault
    $header = Join-Path $root "include\openssl\evp.h"
    $dll = Join-Path $root "bin\libcrypto-4-x64.dll"
    $def = Join-Path $root "lib\VC\x64\MD\libcrypto.def"
    if ((Test-Path -LiteralPath $header) -and (Test-Path -LiteralPath $dll) -and (Test-Path -LiteralPath $def)) {
        $openssl = Join-Path $root "bin\openssl.exe"
        $ver = if (Test-Path -LiteralPath $openssl) { (& $openssl version 2>&1 | Out-String).Trim() } else { "headers+DLL present" }
        Write-Status OK "OpenSSL development install found: $root ($ver)"
        return $root
    }
    if (-not $AllowInstall) {
        Write-Status ERROR "OpenSSL not found at $root"
        exit 1
    }
    Install-WingetPackage -Id "ShiningLight.OpenSSL.Dev" -DisplayName "OpenSSL (Shining Light Win64 Dev)"
    if (-not ((Test-Path -LiteralPath $header) -and (Test-Path -LiteralPath $dll))) {
        Write-Status ERROR "OpenSSL Dev install incomplete. Install ShiningLight.OpenSSL.Dev from winget manually."
        exit 1
    }
    Write-Status OK "OpenSSL ready at $root"
    return $root
}

function Invoke-ProjectBuild {
    param(
        [string]$CMake,
        [string]$ToolchainRoot,
        [string]$OpenSslRoot,
        [switch]$RunTests
    )

    $bin = Join-Path $ToolchainRoot "bin"
    $env:PATH = "$bin;C:\Program Files\CMake\bin;" + (
        ($env:PATH -split ";" | Where-Object {
            $_ -and ($_ -notmatch '(?i)^C:\\MinGW\\bin$') -and ($_ -notmatch '(?i)WinLibs')
        }) -join ";"
    )

    if (Test-Path -LiteralPath $OldMingwMarker) {
        Write-Status WARNING "Legacy MinGW detected at C:\MinGW; build PATH prefers $bin instead."
    }

    $gpp = Join-Path $bin "g++.exe"
    $make = Join-Path $bin "mingw32-make.exe"
    $dlltool = Join-Path $bin "dlltool.exe"
    if (-not (Test-Path -LiteralPath $dlltool)) {
        Write-Status ERROR "dlltool.exe missing from toolchain (needed for OpenSSL MinGW import lib)."
        exit 1
    }

    Write-Status INFO "GUI framework: native Win32 (user32/gdi32/comctl32) - no Qt/wxWidgets required."
    Write-Status INFO "Configuring CMake..."
    & $CMake -S $ScriptRoot -B (Join-Path $ScriptRoot "build") -G "MinGW Makefiles" `
        "-DCMAKE_BUILD_TYPE=Release" `
        "-DCMAKE_CXX_COMPILER=$($gpp -replace '\\','/')" `
        "-DCMAKE_MAKE_PROGRAM=$($make -replace '\\','/')" `
        "-DOPENSSL_ROOT_DIR=$($OpenSslRoot -replace '\\','/')"
    if ($LASTEXITCODE -ne 0) {
        Write-Status ERROR "CMake configure failed."
        exit 1
    }
    Write-Status OK "CMake configure succeeded"

    Write-Status INFO "Building project..."
    & $CMake --build (Join-Path $ScriptRoot "build") --parallel
    if ($LASTEXITCODE -ne 0) {
        Write-Status ERROR "Build failed."
        exit 1
    }
    Write-Status OK "Build succeeded"

    if ($RunTests) {
        Write-Status INFO "Running crypto tests..."
        & $CMake -E chdir (Join-Path $ScriptRoot "build") ctest --output-on-failure
        if ($LASTEXITCODE -ne 0) {
            Write-Status ERROR "Tests failed."
            exit 1
        }
        Write-Status OK "All registered tests passed"
    }

    $state = [ordered]@{
        completedUtc     = (Get-Date).ToUniversalTime().ToString("o")
        cmake            = $CMake
        toolchain        = $ToolchainRoot
        opensslRoot      = $OpenSslRoot
        guiFramework     = "Win32 native"
        compilerVersion  = ((& $gpp --version 2>&1 | Select-Object -First 1) | Out-String).Trim()
    }
    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    ($state | ConvertTo-Json) | Set-Content -LiteralPath $StateFile -Encoding UTF8
    Write-Status OK "Setup state written to $StateFile"
}

# ---- main ----
Write-Host ""
Write-Host "Hybrid PKI SCADA - setup.ps1" -ForegroundColor White
Write-Host ""

if (-not (Test-IsWindows)) {
    Write-Status ERROR "This project setup targets Windows only."
    exit 1
}
Write-Status OK "Windows environment detected"

$allowInstall = -not $SkipInstall
if ($allowInstall) {
    Ensure-Winget | Out-Null
} else {
    Write-Status WARNING "SkipInstall set - will not download packages."
}

$cmake = Ensure-CMake -AllowInstall:$allowInstall
$toolchain = Ensure-Toolchain -AllowInstall:$allowInstall
$openssl = Ensure-OpenSSL -AllowInstall:$allowInstall

Invoke-ProjectBuild -CMake $cmake -ToolchainRoot $toolchain -OpenSslRoot $openssl -RunTests:(-not $SkipTests)

Write-Host ""
Write-Status OK "Setup complete. Run .\run.ps1 to launch the dashboard."
exit 0
