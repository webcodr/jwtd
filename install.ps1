#!/usr/bin/env pwsh
#
# jwtd installer for Windows.
#
# Downloads the release archive matching the detected architecture, verifies it
# against the release's checksums.txt (and, when cosign is installed, verifies
# the keyless signature over that checksum file), then installs the binary into
# %LOCALAPPDATA%\Programs\jwtd and adds that directory to the user PATH. No
# administrator privileges are required.
#
#   irm https://jwtd.sh/install.ps1 | iex
#
# Invoke-Expression cannot forward arguments, so the environment variables
# JWTD_VERSION, JWTD_INSTALL_DIR, and JWTD_NO_MODIFY_PATH set the same values:
#
#   $env:JWTD_VERSION = 'v5.3.0'; irm https://jwtd.sh/install.ps1 | iex
#
# To pass parameters directly, create the script block explicitly:
#
#   & ([scriptblock]::Create((irm https://jwtd.sh/install.ps1))) -Version v5.3.0
#
# macOS and Linux are served by install.sh; see the README.

param(
    [string]$Version,
    [string]$Dir,
    [switch]$NoModifyPath,
    [switch]$Help
)

$Repo = 'webcodr/jwtd'
$CertificateIdentityRegexp = '^https://github.com/webcodr/jwtd/\.github/workflows/release\.yml@'
$CertificateOidcIssuer = 'https://token.actions.githubusercontent.com'

# The user PATH lives here. It is deliberately read and written through the
# registry rather than [Environment]::SetEnvironmentVariable: that API expands
# entries such as %USERPROFILE% and writes the expanded text back as a plain
# string, silently rewriting parts of the PATH the installer never touched.
$UserEnvironmentKey = 'HKCU:\Environment'

function Write-Info {
    param([string]$Message)
    [Console]::Error.WriteLine($Message)
}

function Write-Warn {
    param([string]$Message)
    [Console]::Error.WriteLine("warning: $Message")
}

# Errors are thrown, never `exit`ed. This script is normally piped into
# Invoke-Expression in an interactive session, where `exit` would close the
# user's shell instead of aborting the installation.
function Write-Die {
    param([string]$Message)
    throw $Message
}

function Show-Usage {
    Write-Info @'
Install jwtd, a CLI that decodes and pretty-prints JWT, JWS, and JWE tokens.

Usage:
  install.ps1 [-Version <tag>] [-Dir <path>] [-NoModifyPath]

Parameters:
  -Version <tag>    Release to install (default: the latest release).
                    Accepts "5.3.0" or "v5.3.0".
  -Dir <path>       Installation directory
                    (default: %LOCALAPPDATA%\Programs\jwtd).
  -NoModifyPath     Do not add the installation directory to the user PATH.
  -Help             Show this help.

Environment:
  JWTD_VERSION           Same as -Version.
  JWTD_INSTALL_DIR       Same as -Dir.
  JWTD_NO_MODIFY_PATH    Same as -NoModifyPath when set to any value.

The archive is always verified against the release's checksums.txt. When
cosign is installed, the keyless Cosign bundle over checksums.txt is verified
as well.
'@
}

function Test-WindowsHost {
    # PowerShell 7 runs on Linux and macOS too, where install.sh is the right
    # script. $IsWindows does not exist in Windows PowerShell 5.1, which only
    # ever runs on Windows.
    if ($PSVersionTable.PSEdition -eq 'Desktop') {
        return $true
    }
    $flag = Get-Variable -Name 'IsWindows' -ValueOnly -ErrorAction SilentlyContinue
    return [bool]$flag
}

# Resolve-Architecture maps the OS architecture onto the GOARCH used in the
# release archive names (jwtd-windows-<arch>.zip).
function Resolve-Architecture {
    $architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    switch ($architecture) {
        'X64' { return 'amd64' }
        'Arm64' { return 'arm64' }
        default {
            Write-Die "unsupported architecture: $architecture (release binaries are built for amd64 and arm64)"
        }
    }
}

# An x64 PowerShell running under emulation on an ARM64 machine reports X64,
# which would install the Intel binary on ARM hardware. The machine-level
# environment key records the native architecture and is not rewritten for the
# emulated process, so it distinguishes emulation from a genuine x64 machine.
function Resolve-EmulatedArchitecture {
    param([string]$Architecture)

    if ($Architecture -ne 'amd64') {
        return $Architecture
    }
    if ($env:PROCESSOR_ARCHITEW6432 -eq 'ARM64') {
        return 'arm64'
    }

    $machineKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
    $native = (Get-ItemProperty -Path $machineKey -Name 'PROCESSOR_ARCHITECTURE' -ErrorAction SilentlyContinue).PROCESSOR_ARCHITECTURE
    if ($native -eq 'ARM64') {
        return 'arm64'
    }
    return $Architecture
}

function Get-RemoteFile {
    param([string]$Url, [string]$Destination)

    try {
        Invoke-WebRequest -Uri $Url -OutFile $Destination -UseBasicParsing
    } catch {
        Write-Die "could not download $Url (check the release tag and your network connection)"
    }
}

# Test-Checksum matches the archive against its checksums.txt entry. The entry
# is selected by exact file name, so a substring match against another asset
# cannot stand in for it.
function Test-Checksum {
    param([string]$Archive)

    $expected = $null
    foreach ($line in Get-Content -Path 'checksums.txt') {
        # "<hash>  <name>", with the optional binary-mode asterisk sha256sum
        # writes in front of the name.
        if ($line -match '^\s*([0-9a-fA-F]+)\s+\*?(\S+)\s*$' -and $Matches[2] -eq $Archive) {
            $expected = $Matches[1]
            break
        }
    }
    if (-not $expected) {
        Write-Die "checksums.txt has no entry for $Archive"
    }

    $actual = (Get-FileHash -Path $Archive -Algorithm SHA256).Hash
    # Get-FileHash returns uppercase hex, checksums.txt lowercase; -ne compares
    # strings case-insensitively.
    if ($actual -ne $expected) {
        Write-Die "checksum mismatch for $Archive; refusing to install"
    }
    Write-Info "Checksum verified: $Archive"
}

# Test-Signature is best-effort by design: cosign is not a dependency most
# machines have, and the checksum above already pins the archive bytes. When
# cosign is present the bundle is verified and a failure is fatal.
function Test-Signature {
    param([string]$BaseUrl)

    $cosign = Get-Command -Name 'cosign' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $cosign) {
        Write-Info 'cosign not found - skipping signature verification (install cosign to verify the release signature)'
        return
    }

    Get-RemoteFile -Url "$BaseUrl/checksums.txt.sigstore.json" -Destination 'checksums.txt.sigstore.json'
    & $cosign.Path verify-blob `
        --bundle 'checksums.txt.sigstore.json' `
        --certificate-identity-regexp $CertificateIdentityRegexp `
        --certificate-oidc-issuer $CertificateOidcIssuer `
        'checksums.txt' 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Die 'cosign could not verify checksums.txt against the jwtd release workflow; refusing to install'
    }
    Write-Info 'Signature verified: checksums.txt (cosign, keyless)'
}

# Add-UserPathEntry appends the installation directory to the user PATH. Unlike
# the Unix installer, which can only print a hint because it cannot know which
# shell profile to edit, Windows keeps the user PATH in one registry value the
# installer can update itself.
function Add-UserPathEntry {
    param([string]$Directory)

    $key = Get-Item -Path $UserEnvironmentKey
    $current = [string]$key.GetValue(
        'Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    $entries = @($current -split ';' | Where-Object { $_ -ne '' })
    if ($entries -contains $Directory) {
        return $false
    }

    Set-ItemProperty -Path $UserEnvironmentKey -Name 'Path' `
        -Value (($entries + $Directory) -join ';') -Type ExpandString
    $env:PATH = "$env:PATH;$Directory"
    return $true
}

# Newly launched processes inherit their environment from Explorer, which
# rereads the registry only when this broadcast arrives. Without it a fresh
# terminal would not see the new PATH until the next sign-in. Best-effort: the
# installation is complete either way.
function Publish-EnvironmentChange {
    try {
        if (-not ('JwtdInstaller.NativeMethods' -as [type])) {
            Add-Type -Namespace 'JwtdInstaller' -Name 'NativeMethods' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessageTimeout(
    System.IntPtr hWnd, uint Msg, System.IntPtr wParam, string lParam,
    uint fuFlags, uint uTimeout, out System.UIntPtr lpdwResult);
'@
        }
        $HWND_BROADCAST = [System.IntPtr]0xffff
        $WM_SETTINGCHANGE = 0x1a
        $SMTO_ABORTIFHUNG = 0x2
        $result = [System.UIntPtr]::Zero
        [void][JwtdInstaller.NativeMethods]::SendMessageTimeout(
            $HWND_BROADCAST, $WM_SETTINGCHANGE, [System.IntPtr]::Zero, 'Environment',
            $SMTO_ABORTIFHUNG, 5000, [ref]$result)
    } catch {
        # Nothing to do: the PATH entry is written, only its propagation to
        # already-running processes is delayed.
    }
}

function Install-Jwtd {
    $ErrorActionPreference = 'Stop'
    # Invoke-WebRequest spends most of its time drawing the progress bar in
    # Windows PowerShell 5.1.
    $ProgressPreference = 'SilentlyContinue'
    # PowerShell 7.4 turns a nonzero native exit code into a terminating error
    # under the preference above, which would pre-empt the cosign check below
    # with a less useful message.
    if (Get-Variable -Name 'PSNativeCommandUseErrorActionPreference' -ErrorAction SilentlyContinue) {
        $PSNativeCommandUseErrorActionPreference = $false
    }

    if ($Help) {
        Show-Usage
        return
    }

    if (-not (Test-WindowsHost)) {
        Write-Die 'unsupported operating system: this script installs on Windows; on macOS and Linux use "curl -fsSL https://jwtd.sh/install.sh | sh"'
    }

    $releaseVersion = if ($Version) { $Version } else { $env:JWTD_VERSION }
    $installDir = if ($Dir) { $Dir } else { $env:JWTD_INSTALL_DIR }
    $skipPath = $NoModifyPath.IsPresent -or [bool]$env:JWTD_NO_MODIFY_PATH

    if (-not $installDir) {
        $installDir = Join-Path $env:LOCALAPPDATA 'Programs\jwtd'
    }
    # The download happens from a temporary working directory, so a relative
    # -Dir has to be anchored to the caller's directory before that move.
    if (-not [System.IO.Path]::IsPathRooted($installDir)) {
        $installDir = Join-Path (Get-Location).Path $installDir
    }

    $architecture = Resolve-EmulatedArchitecture -Architecture (Resolve-Architecture)
    $archive = "jwtd-windows-$architecture.zip"

    if ($releaseVersion) {
        if (-not $releaseVersion.StartsWith('v')) {
            $releaseVersion = "v$releaseVersion"
        }
        $baseUrl = "https://github.com/$Repo/releases/download/$releaseVersion"
        Write-Info "Installing jwtd $releaseVersion (windows/$architecture)"
    } else {
        $baseUrl = "https://github.com/$Repo/releases/latest/download"
        Write-Info "Installing the latest jwtd release (windows/$architecture)"
    }

    $workDir = Join-Path ([System.IO.Path]::GetTempPath()) "jwtd-install-$([System.IO.Path]::GetRandomFileName())"
    New-Item -ItemType Directory -Path $workDir | Out-Null
    $previousLocation = Get-Location
    $staged = $null
    try {
        Set-Location -Path $workDir

        Get-RemoteFile -Url "$baseUrl/$archive" -Destination $archive
        Get-RemoteFile -Url "$baseUrl/checksums.txt" -Destination 'checksums.txt'
        Test-Checksum -Archive $archive
        Test-Signature -BaseUrl $baseUrl

        Expand-Archive -Path $archive -DestinationPath 'extracted' -Force
        $binary = Join-Path 'extracted' 'jwtd.exe'
        if (-not (Test-Path -Path $binary)) {
            Write-Die 'the release archive did not contain a jwtd.exe binary'
        }

        if (-not (Test-Path -Path $installDir)) {
            try {
                New-Item -ItemType Directory -Path $installDir -Force | Out-Null
            } catch {
                Write-Die "could not create $installDir"
            }
        }

        # Windows refuses to overwrite a running .exe but does allow renaming
        # one, so an upgrade moves the installed binary aside, moves the new one
        # into place, and then deletes the old file. The delete fails while an
        # older jwtd is still running, which is why it is best-effort: the
        # upgrade itself has already taken effect.
        $installed = Join-Path $installDir 'jwtd.exe'
        $staged = Join-Path $installDir ".jwtd.install.$PID.exe"
        $retired = Join-Path $installDir ".jwtd.old.$PID.exe"
        try {
            Copy-Item -Path $binary -Destination $staged -Force
        } catch {
            Write-Die "could not write to $installDir (choose another directory with -Dir)"
        }
        try {
            if (Test-Path -Path $installed) {
                Move-Item -Path $installed -Destination $retired -Force
            }
            Move-Item -Path $staged -Destination $installed -Force
            $staged = $null
        } catch {
            Write-Die "could not install into $installDir (choose another directory with -Dir)"
        }
        Remove-Item -Path $retired -Force -ErrorAction SilentlyContinue

        $reported = & $installed --version 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $reported) {
            $reported = 'jwtd'
        }
        Write-Info "Installed $reported to $installed"

        if ($skipPath) {
            Write-Info "PATH was left unchanged. Add $installDir to it to run jwtd by name."
        } elseif (Add-UserPathEntry -Directory $installDir) {
            Publish-EnvironmentChange
            Write-Info "Added $installDir to your user PATH. Open a new terminal to pick it up."
        }
    } finally {
        Set-Location -Path $previousLocation
        if ($staged) {
            Remove-Item -Path $staged -Force -ErrorAction SilentlyContinue
        }
        Remove-Item -Path $workDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Install-Jwtd
