#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

$destDir = "C:\Program Files\sentry"
$destExe = "$destDir\m2-agent.exe"

if (-not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir | Out-Null
}

Copy-Item -Path ".\m2-agent.exe" -Destination $destExe -Force

if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Error "nssm not found in PATH. Install nssm (https://nssm.cc) and ensure it is on PATH before running this script."
    exit 1
}

nssm install M2Agent "$destExe"
nssm set M2Agent Start SERVICE_AUTO_START
nssm start M2Agent
