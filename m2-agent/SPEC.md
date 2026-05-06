# M2 Embedded Agent — Spec

Lightweight service that runs in the HOST OS (Windows or Linux). Acts as a permanent
bridge to the UAI broker. Enables UAI to reach physical machines without needing to
boot the sentry USB stick.

## Protocol

Same HTTP API as the sentry USB stick agent (port 7800):
- GET  /health   → {"ok": true, "hostname": "...", "os": "linux|windows"}
- GET  /info     → machine specs (hostname, OS, IPs, disk, RAM, CPU)
- POST /shell    → {"cmd": "..."} → {"stdout": "...", "stderr": "...", "rc": 0}
- POST /reboot   → {"entry": "sentry"} → sets next boot to sentry, reboots
- POST /poweroff → graceful shutdown

## Heartbeat (outbound)

POST http://192.168.110.25:7700/broker/heartbeat every 30s:
```json
{"hostname": "<hostname>", "ip": "<primary-ip>", "port": 7800, "status": "alive"}
```
Broker auto-registers on first heartbeat. No pre-registration needed.

## Reboot behavior

Linux:
1. Run `efibootmgr -v` to list EFI entries
2. Find entry labeled "SENTRYBOOT" or "sentry"
3. `efibootmgr -n <bootnum>` to set BootNext
4. `reboot` (requires sudo nopasswd for efibootmgr and reboot)

Windows:
1. `bcdedit /enum firmware` to list EFI entries
2. Find entry with "sentry" or "SENTRYBOOT" in description
3. `bcdedit /set {fwbootmgr} bootsequence <id>` (requires SeShutdownPrivilege)
4. `shutdown /r /t 0`

## Privilege model

Linux:
- Runs as `sentry` system account (NOT root)
- sudoers: `sentry ALL=(ALL) NOPASSWD: /usr/sbin/efibootmgr, /sbin/reboot, /sbin/poweroff`
- /shell endpoint: ONLY allows whitelisted commands (no arbitrary root access)

Windows:
- Runs as LocalService or dedicated sentry account
- SeShutdownPrivilege granted
- /shell endpoint: NOPASSWD from admin context only (for now: disabled)

## Implementation: Go

- Single static binary, no runtime deps
- OS detection at compile time or runtime
- `go build -o m2-agent` → ~5MB binary
- Systemd unit: m2-agent.service
- Windows: kardianos/service OR simple .bat + NSSM

## Shell whitelist (Linux)

Only allow these command prefixes in /shell:
- df, du, ls, cat, ps, top, netstat, ss, ip, hostname, uname
- systemctl status (NOT start/stop/enable)
- docker ps, docker logs, docker inspect
- efibootmgr -v (read-only)
- journalctl

Block: rm, curl, wget, chmod, chown, kill, systemctl start/stop, any pipe to sh

## File layout

```
m2-agent/
  main.go          - entry point, HTTP server, heartbeat loop
  reboot.go        - OS-specific reboot/EFI logic
  shell.go         - command whitelist + execution
  info.go          - system info collection
  service.go       - systemd + Windows service wrappers
  go.mod
  m2-agent.service - systemd unit template
  install.sh       - Linux installer (creates sentry user, sudoers, enables service)
  install.ps1      - Windows installer (NSSM service setup)
```
