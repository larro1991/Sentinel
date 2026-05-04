@echo off
:: SentryUSB.bat — plug in SENTRYBOOT USB, double-click this.
:: Auto-elevates, mounts the USB, shows server IP, opens engagement.yaml.
:: -------------------------------------------------------------------

:: Re-launch as admin if not already elevated
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -WindowStyle Hidden -Command ^
        "Start-Process cmd -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b
)

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
"
$ErrorActionPreference = 'SilentlyContinue'

Write-Host ''
Write-Host '====================================================' -ForegroundColor Cyan
Write-Host '  SENTRY USB MANAGER' -ForegroundColor Cyan
Write-Host '====================================================' -ForegroundColor Cyan
Write-Host ''

# Find SENTRYBOOT disk
$disk = Get-Disk | Where-Object { $_.BusType -eq 'USB' } |
    ForEach-Object {
        $n = $_.Number
        $parts = Get-Partition -DiskNumber $n -EA SilentlyContinue
        if ($parts | Where-Object { (Get-Volume -Partition $_ -EA SilentlyContinue).FileSystemLabel -eq 'SENTRYBOOT' }) {
            return $_
        }
        $parts | ForEach-Object {
            $v = Get-Volume -Partition $_ -EA SilentlyContinue
            if ($v.FileSystemLabel -eq 'SENTRYBOOT') { return $disk }
        }
    } | Select-Object -First 1

# Also try finding by volume label directly
$vol = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'SENTRYBOOT' } | Select-Object -First 1

if (-not $vol) {
    # Try mounting via partition
    $diskNum = $null
    Get-Disk | Where-Object { $_.BusType -eq 'USB' } | ForEach-Object {
        $n = $_.Number
        Get-Partition -DiskNumber $n -EA SilentlyContinue | ForEach-Object {
            if ($_.Size -gt 200MB -and $_.Size -lt 300MB) {
                $diskNum = $n
                $partNum = $_.PartitionNumber
            }
        }
    }

    if ($diskNum -ne $null) {
        Write-Host 'Mounting SENTRYBOOT partition...' -ForegroundColor Yellow
        Add-PartitionAccessPath -DiskNumber $diskNum -PartitionNumber $partNum -AccessPath 'S:\' -EA SilentlyContinue
        Start-Sleep 2
        $vol = Get-Volume | Where-Object { $_.FileSystemLabel -eq 'SENTRYBOOT' } | Select-Object -First 1
    }
}

if (-not $vol) {
    Write-Host 'ERROR: SENTRYBOOT USB not found. Plug it in and try again.' -ForegroundColor Red
    Write-Host ''
    pause
    exit
}

$drive = $vol.DriveLetter
if (-not $drive) {
    # Assign S: if no letter
    $part = Get-Partition | Where-Object {
        (Get-Volume -Partition $_ -EA SilentlyContinue).FileSystemLabel -eq 'SENTRYBOOT'
    } | Select-Object -First 1
    if ($part) {
        Add-PartitionAccessPath -DiskNumber $part.DiskNumber -PartitionNumber $part.PartitionNumber -AccessPath 'S:\' -EA SilentlyContinue
        Start-Sleep 2
    }
    $drive = 'S'
}

Write-Host \"Found SENTRYBOOT at ${drive}:\" -ForegroundColor Green
Write-Host ''

# Show STATUS.TXT if it exists (written by sentry-init after boot)
$status = \"${drive}:\STATUS.TXT\"
if (Test-Path $status) {
    Write-Host '--- SERVER STATUS (from last boot) ---' -ForegroundColor Yellow
    Get-Content $status | ForEach-Object { Write-Host \"  $_\" }
    Write-Host ''
} else {
    Write-Host '  STATUS.TXT not found (server has not booted yet, or USB was never booted).' -ForegroundColor DarkGray
    Write-Host ''
}

# Show engagement.yaml broker IP
$eng = \"${drive}:\engagement.yaml\"
if (Test-Path $eng) {
    $broker = (Select-String 'broker:' $eng).Line.Trim()
    Write-Host \"Broker setting: $broker\" -ForegroundColor Cyan
    Write-Host ''
}

Write-Host 'What do you want to do?' -ForegroundColor White
Write-Host '  [1] Edit engagement.yaml in Notepad'
Write-Host '  [2] Fix grub.cfg (copy from sentry-stick project)'
Write-Host '  [3] Show full grub.cfg'
Write-Host '  [4] Eject USB and exit'
Write-Host '  [5] Just exit (leave USB mounted)'
Write-Host ''
$choice = Read-Host 'Choice'

switch (\$choice) {
    '1' {
        Write-Host 'Opening engagement.yaml...' -ForegroundColor Yellow
        Start-Process notepad \"${drive}:\engagement.yaml\" -Wait
    }
    '2' {
        \$src = 'C:\Dev\active\sentry-stick\sentry-stick\boot-overlay\grub.cfg'
        if (Test-Path \$src) {
            Copy-Item \$src \"${drive}:\grub\grub.cfg\" -Force
            Write-Host 'grub.cfg updated.' -ForegroundColor Green
        } else {
            Write-Host \"Source not found: \$src\" -ForegroundColor Red
        }
    }
    '3' {
        Write-Host '--- grub.cfg ---' -ForegroundColor Yellow
        Get-Content \"${drive}:\grub\grub.cfg\" | ForEach-Object { Write-Host \"  \$_\" }
    }
    '4' { }
    '5' {
        Write-Host 'USB left mounted.' -ForegroundColor DarkGray
        exit
    }
}

# Eject
Write-Host ''
Write-Host 'Ejecting SENTRYBOOT...' -ForegroundColor Yellow
\$shell = New-Object -ComObject Shell.Application
\$drives = \$shell.Namespace(17).Items()
foreach (\$d in \$drives) {
    if (\$d.Name -match 'SENTRYBOOT') {
        \$d.InvokeVerb('Eject')
        Write-Host 'Ejected.' -ForegroundColor Green
    }
}

Write-Host ''
Write-Host 'Done.' -ForegroundColor Green
Write-Host ''
pause
"
