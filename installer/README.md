# sentry-install — M3 Installer

Deploys m2-agent as a system service on any Linux or Windows host.
Optionally writes `/EFI/Sentry/` stub to the host ESP (M4 adds kernel/initramfs).

## Linux

```sh
# Basic — installs agent only
sudo ./sentry-install.sh --broker http://192.168.110.185:7702/broker/heartbeat

# With token + ESP stub
sudo ./sentry-install.sh \
  --broker http://192.168.110.25:7700/broker/heartbeat \
  --token myorgtoken \
  --efi

# Use local binary (no download)
sudo ./sentry-install.sh --broker http://... --binary ./m2-agent-linux-amd64

# Dry run
sudo ./sentry-install.sh --broker http://... --dry-run

# Uninstall
sudo ./sentry-install.sh --uninstall
```

Supports: systemd (Ubuntu/Debian/RHEL/Proxmox), OpenRC (Alpine).
Detects arch: amd64, arm64.

## Windows (PowerShell — run as Administrator)

```powershell
# Basic
.\sentry-install.ps1 -Broker "http://192.168.110.25:7700/broker/heartbeat"

# With token + ESP stub
.\sentry-install.ps1 -Broker "http://..." -Token "myorgtoken" -EFI

# Use local binary
.\sentry-install.ps1 -Broker "http://..." -BinaryPath ".\m2-agent-windows-amd64.exe"

# Dry run
.\sentry-install.ps1 -Broker "http://..." -DryRun

# Uninstall
.\sentry-install.ps1 -Uninstall
```

Uses NSSM for service management (downloaded automatically if absent).
Compatible with PS 5.1 and 7.

## Binary releases

Both scripts download from:
- Linux:   `https://github.com/larro1991/bedrock/releases/latest/download/m2-agent-linux-{amd64|arm64}`
- Windows: `https://github.com/larro1991/bedrock/releases/latest/download/m2-agent-windows-amd64.exe`

Set up GitHub Actions in the bedrock repo to publish releases (see M3 next steps below).

## Deploy via MDM / RMM

| Method        | Command |
|---------------|---------|
| GPO / Intune  | `powershell.exe -ExecutionPolicy Bypass -File sentry-install.ps1 -Broker URL` |
| PDQ Deploy    | Run as SYSTEM, pass params |
| Ansible       | `script` module with `sentry-install.sh` |
| ConnectWise Automate | Script step: PS admin shell |

## What M3 writes

### Linux (systemd)
- `/usr/local/bin/m2-agent` — binary
- `/etc/systemd/system/m2-agent.service` — service unit
- `/EFI/Sentry/engagement.yaml` + `manifest.json` — if `--efi` used

### Windows
- `C:\Program Files\Sentry\m2-agent.exe` — binary
- `C:\Program Files\Sentry\nssm.exe` — service manager
- `C:\ProgramData\Sentry\logs\` — stdout/stderr logs
- `{ESP}\EFI\Sentry\engagement.yaml` + `manifest.json` — if `-EFI` used

## M3 → M4 handoff

The `/EFI/Sentry/` directory written here is a stub. M4 adds:
- `vmlinuz-lts` — Alpine LTS kernel
- `initramfs-lts` — custom initramfs
- `grub.cfg` — chainloader config
- `BOOTX64.EFI` — GRUB EFI binary
- EFI boot entry `"Sentry rescue (DO NOT CHANGE)"` kept out of BootOrder

M4 also adds `--verify` subcommand to re-hash ESP files against manifest.
