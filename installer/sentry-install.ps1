#Requires -Version 5.1
<#
.SYNOPSIS
    M3 installer for m2-agent (embedded UAI broker bridge).
    Deploys m2-agent as a Windows service and optionally writes /EFI/Sentry/ to the ESP.

.DESCRIPTION
    Installs the m2-agent binary, registers it as a Windows service via NSSM,
    and configures it to heartbeat to the UAI broker.

.PARAMETER Broker
    Full broker heartbeat URL. Example: http://192.168.110.25:7700/broker/heartbeat

.PARAMETER Token
    Org token passed to agent (optional).

.PARAMETER Name
    Agent name registered with broker. Default: hostname.

.PARAMETER Port
    Local agent listen port. Default: 7800.

.PARAMETER BinaryPath
    Path to local m2-agent-windows-amd64.exe. If omitted, downloads from GitHub Releases.

.PARAMETER EFI
    Also write /EFI/Sentry/ to the host ESP partition.

.PARAMETER Uninstall
    Remove the agent service (and /EFI/Sentry/ if present).

.PARAMETER DryRun
    Print all planned actions. Touch nothing.

.EXAMPLE
    # Basic install
    .\sentry-install.ps1 -Broker "http://192.168.110.185:7702/broker/heartbeat"

.EXAMPLE
    # Install with token, also write ESP stub
    .\sentry-install.ps1 -Broker "http://broker:7700/broker/heartbeat" -Token "abc123" -EFI

.EXAMPLE
    # Uninstall
    .\sentry-install.ps1 -Uninstall

.EXAMPLE
    # Dry run
    .\sentry-install.ps1 -Broker "http://broker:7700/broker/heartbeat" -DryRun
#>

[CmdletBinding()]
param(
    [string]$Broker,
    [string]$Token    = "",
    [string]$Name     = $env:COMPUTERNAME,
    [string]$Port     = "7800",
    [string]$BinaryPath = "",
    [switch]$EFI,
    [switch]$Uninstall,
    [switch]$DryRun
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$BINARY_URL    = "https://github.com/larro1991/bedrock/releases/latest/download/m2-agent-windows-amd64.exe"
$NSSM_URL      = "https://nssm.cc/release/nssm-2.24.zip"
$INSTALL_DIR   = "C:\Program Files\Sentry"
$BINARY_DEST   = "$INSTALL_DIR\m2-agent.exe"
$NSSM_PATH     = "$INSTALL_DIR\nssm.exe"
$SERVICE_NAME  = "m2-agent"
$LOG_DIR       = "C:\ProgramData\Sentry\logs"

function Write-Log {
    param([string]$Msg)
    Write-Host "[sentry] $Msg"
}

function Invoke-Run {
    param([scriptblock]$Action, [string]$Desc)
    if ($DryRun) {
        Write-Host "[dry-run] $Desc"
    } else {
        & $Action
    }
}

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = [Security.Principal.WindowsPrincipal]$id
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Must run as Administrator. Right-click PowerShell -> Run as Administrator."
    }
}

function Get-NssmPath {
    # NSSM already in PATH or install dir?
    $found = Get-Command nssm -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }
    if (Test-Path $NSSM_PATH) { return $NSSM_PATH }
    return $null
}

function Install-Nssm {
    Write-Log "Downloading NSSM..."
    $zip = "$env:TEMP\nssm-2.24.zip"
    Invoke-Run { Invoke-WebRequest -Uri $NSSM_URL -OutFile $zip -UseBasicParsing } `
                "Download NSSM from $NSSM_URL -> $zip"
    Invoke-Run {
        $extract = "$env:TEMP\nssm-extract"
        Expand-Archive -Path $zip -DestinationPath $extract -Force
        $exe = Get-ChildItem -Path $extract -Recurse -Filter "nssm.exe" |
               Where-Object { $_.DirectoryName -match "win64" } |
               Select-Object -First 1
        if (-not $exe) {
            $exe = Get-ChildItem -Path $extract -Recurse -Filter "nssm.exe" | Select-Object -First 1
        }
        Copy-Item -Path $exe.FullName -Destination $NSSM_PATH -Force
        Remove-Item $extract -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $zip -Force -ErrorAction SilentlyContinue
    } "Extract NSSM -> $NSSM_PATH"
}

function Find-EspDrive {
    # Find the EFI System Partition drive letter (if mounted) or volume path
    $esp = Get-Partition | Where-Object { $_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" } |
           Select-Object -First 1
    if (-not $esp) { return $null }
    $vol = $esp | Get-Volume -ErrorAction SilentlyContinue
    if ($vol -and $vol.DriveLetter) {
        return "$($vol.DriveLetter):"
    }
    # ESP likely not mounted — mount it temporarily
    return $null
}

function Write-EfiSentry {
    Write-Log "Writing /EFI/Sentry/ stub to ESP..."

    $espDrive = Find-EspDrive
    if (-not $espDrive) {
        Write-Log "ESP not mounted. Attempting to mount via mountvol..."
        Invoke-Run {
            $vol = (Get-Partition | Where-Object {
                $_.GptType -eq "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}"
            } | Select-Object -First 1).AccessPaths | Select-Object -First 1
            if ($vol) {
                # Assign a temporary drive letter
                $letter = "Z"
                mountvol "${letter}:" $vol 2>$null
                $script:espDrive = "${letter}:"
            }
        } "Mount ESP to Z:"
        $espDrive = "Z:"
    }

    if (-not $espDrive) {
        Write-Log "WARNING: Could not locate ESP. Skipping /EFI/Sentry/ write."
        return
    }

    $sentryDir = "$espDrive\EFI\Sentry"
    Invoke-Run { New-Item -ItemType Directory -Path $sentryDir -Force | Out-Null } `
                "mkdir $sentryDir"

    $engagement = @"
broker: $Broker
agent_name: $Name
org_token: $Token
installed_at: $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC)
"@
    Invoke-Run { Set-Content -Path "$sentryDir\engagement.yaml" -Value $engagement -Encoding ASCII } `
                "Write $sentryDir\engagement.yaml"

    $manifest = @"
{
  "version": "m3",
  "installed_at": "$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC)",
  "agent_name": "$Name",
  "note": "M4 will add vmlinuz + initramfs + grub.cfg to this directory"
}
"@
    Invoke-Run { Set-Content -Path "$sentryDir\manifest.json" -Value $manifest -Encoding ASCII } `
                "Write $sentryDir\manifest.json"

    Write-Log "ESP stub written to $espDrive\EFI\Sentry\"
    Write-Log "M4 will populate kernel + initramfs -- EFI boot entry not created yet."
}

function Invoke-Install {
    if (-not $Broker) { throw "--Broker URL is required" }
    Assert-Admin

    Write-Log "Installing m2-agent on $Name"
    Write-Log "  Broker: $Broker"
    Write-Log "  Port:   $Port"

    # Create install dir
    Invoke-Run { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null } `
                "mkdir $INSTALL_DIR"
    Invoke-Run { New-Item -ItemType Directory -Path $LOG_DIR -Force | Out-Null } `
                "mkdir $LOG_DIR"

    # Binary
    if ($BinaryPath -ne "") {
        Write-Log "Using local binary: $BinaryPath"
        Invoke-Run { Copy-Item -Path $BinaryPath -Destination $BINARY_DEST -Force } `
                    "Copy $BinaryPath -> $BINARY_DEST"
    } else {
        Write-Log "Downloading $BINARY_URL"
        Invoke-Run { Invoke-WebRequest -Uri $BINARY_URL -OutFile $BINARY_DEST -UseBasicParsing } `
                    "Download m2-agent -> $BINARY_DEST"
    }

    # NSSM
    $nssmExe = Get-NssmPath
    if (-not $nssmExe) {
        Install-Nssm
        $nssmExe = $NSSM_PATH
    }
    Write-Log "NSSM: $nssmExe"

    # Remove existing service if present
    $existing = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "Removing existing $SERVICE_NAME service..."
        Invoke-Run { & $nssmExe stop $SERVICE_NAME confirm 2>$null; & $nssmExe remove $SERVICE_NAME confirm } `
                    "nssm stop+remove $SERVICE_NAME"
    }

    # Install service
    Invoke-Run { & $nssmExe install $SERVICE_NAME $BINARY_DEST } `
                "nssm install $SERVICE_NAME $BINARY_DEST"

    # Configure environment
    Invoke-Run { & $nssmExe set $SERVICE_NAME AppEnvironmentExtra `
        "M2_BROKER_URL=$Broker" `
        "M2_AGENT_PORT=$Port" `
        "M2_AGENT_NAME=$Name" `
        $(if ($Token) { "M2_ORG_TOKEN=$Token" } else { "" }) `
    } "nssm set env vars"

    # Stdout/stderr to log dir
    Invoke-Run { & $nssmExe set $SERVICE_NAME AppStdout "$LOG_DIR\m2-agent.log" } `
                "nssm set stdout log"
    Invoke-Run { & $nssmExe set $SERVICE_NAME AppStderr "$LOG_DIR\m2-agent.err" } `
                "nssm set stderr log"
    Invoke-Run { & $nssmExe set $SERVICE_NAME AppRotateFiles 1 } `
                "nssm set log rotation"
    Invoke-Run { & $nssmExe set $SERVICE_NAME Start SERVICE_AUTO_START } `
                "nssm set auto-start"

    # Start service
    Invoke-Run { & $nssmExe start $SERVICE_NAME } "nssm start $SERVICE_NAME"

    Write-Log "m2-agent installed and started."
    Write-Log "  Binary:  $BINARY_DEST"
    Write-Log "  Logs:    $LOG_DIR"
    Write-Log "  Status:  Get-Service $SERVICE_NAME"

    if ($EFI) {
        Write-Log ""
        Write-EfiSentry
    }

    Write-Log ""
    Write-Log "Done. Verify: Get-Service m2-agent"
}

function Invoke-Uninstall {
    Assert-Admin
    Write-Log "Uninstalling m2-agent..."

    $nssmExe = Get-NssmPath
    if ($nssmExe) {
        $existing = Get-Service -Name $SERVICE_NAME -ErrorAction SilentlyContinue
        if ($existing) {
            Invoke-Run { & $nssmExe stop $SERVICE_NAME confirm 2>$null } "nssm stop $SERVICE_NAME"
            Invoke-Run { & $nssmExe remove $SERVICE_NAME confirm } "nssm remove $SERVICE_NAME"
            Write-Log "Service removed."
        } else {
            Write-Log "Service $SERVICE_NAME not found -- skipping."
        }
    } else {
        Write-Log "NSSM not found -- attempting sc.exe fallback..."
        Invoke-Run { sc.exe stop $SERVICE_NAME 2>$null; sc.exe delete $SERVICE_NAME } `
                    "sc stop + delete $SERVICE_NAME"
    }

    Invoke-Run { Remove-Item -Path $INSTALL_DIR -Recurse -Force -ErrorAction SilentlyContinue } `
                "Remove $INSTALL_DIR"
    Invoke-Run { Remove-Item -Path $LOG_DIR -Recurse -Force -ErrorAction SilentlyContinue } `
                "Remove $LOG_DIR"

    # Remove /EFI/Sentry/ if present
    $espDrive = Find-EspDrive
    if ($espDrive) {
        $sentryDir = "$espDrive\EFI\Sentry"
        if (Test-Path $sentryDir) {
            Write-Log "Removing $sentryDir"
            Invoke-Run { Remove-Item -Path $sentryDir -Recurse -Force } "Remove $sentryDir"
        }
    }

    Write-Log "Uninstall complete."
}

# ── main ──────────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Invoke-Uninstall
} else {
    Invoke-Install
}
