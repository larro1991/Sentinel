# Sentry Fleet Control — Full Vision

## The Goal

Deploy a hardware-level AI control plane across every UEFI machine on a subnet.
No disruption to existing OS. No user awareness. Persistent across OS reinstalls.

**Not a hack tool.** This is authorized fleet management — for home infrastructure,
MSP-managed client networks (via Conduit), and lab environments where you need
OS-independent control and recovery.

---

## End State

```
UAI Broker (:7700 on GamingPC)
    │
    ├─ driver: windows      → GamingPC (Win32/PS, localhost)
    ├─ driver: android       → Galaxy S22 (ADB)
    ├─ driver: truenas       → 192.168.110.185 (SSH)
    ├─ driver: linux         → uai-ubuntu (SSH→docker)
    │
    ├─ driver: sentry/truenas-server   ← NEW (hardware level, boot-time)
    ├─ driver: sentry/gaming-pc        ← NEW (pre-OS access, disk/boot control)
    ├─ driver: sentry/workstation-X    ← NEW (any UEFI machine on subnet)
    └─ driver: sentry/vm-proxmox-01    ← NEW (VMs get it too)
```

Claude (via MCP tools) → controls every machine → OS-level AND hardware-level.

Current UAI reach: **apps and OS on machines I'm actively logged into.**
Post-sentry reach: **every UEFI machine on the subnet, at any time, even if its OS is broken.**

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│  Deployment                                     │
│  sentry-stick USB ──────────────────────────┐   │
│  sentry-deploy.py (subnet scanner + remote)─┘   │
│                                                 │
│         ↓ install on each machine              │
│                                                 │
│  ┌──────────────────────────────────────────┐  │
│  │  Hidden EFI Partition (ESP-resident)     │  │
│  │  /EFI/sentry/ on every machine           │  │
│  │                                          │  │
│  │  Alpine Linux (baked initramfs)          │  │
│  │  sshd :22                                │  │
│  │  sentry-agent :7800  ←─── NEW           │  │
│  │  sentry-init (boot orchestrator)         │  │
│  └──────────────────────────────────────────┘  │
│                                                 │
│         ↓ registers to                          │
│                                                 │
│  UAI Broker :7700                               │
│  ├─ /app/sentry-<hostname>/state               │
│  ├─ /app/sentry-<hostname>/action              │
│  └─ /machines (aggregated fleet view)          │
│                                                 │
│         ↓ MCP tools                            │
│                                                 │
│  Claude Code / uai_mcp.py                       │
│  uai_machines, uai_sentry_disks,                │
│  uai_sentry_boot, uai_sentry_install, ...       │
└─────────────────────────────────────────────────┘
```

---

## Components

### 1. sentry-stick USB (already built — M1 done)
Bootable Alpine USB. Deploys sentry to a machine interactively.
Use when: machine is accessible but needs first-time setup.

### 2. sentry-install (M3 — designed, not coded)
Runs from within the booted sentry-stick. Copies EFI files to host's ESP,
adds non-default-boot EFI entry. Reversible. Fully documented in 03-installer-design.md.

### 3. sentry-deploy.py (NEW — remote subnet deployer)
Runs on GamingPC. Scans subnet. SSH/WinRM into each running machine.
Deploys sentry-install without rebooting the target machine.
Registers each machine to UAI broker after install.

Modes:
- `--host 192.168.110.185` — deploy to single machine
- `--subnet 192.168.110.0/24` — scan + deploy to all reachable machines
- `--os-detect` — probe SSH/WinRM to determine Linux vs Windows first
- `--dry-run` — show what would be installed, don't touch anything

### 4. sentry-agent (NEW — the UAI bridge, runs in Alpine rescue)
Small HTTP server (Flask or pure Python) that starts in the Alpine rescue environment.
Registers to the main UAI broker on GamingPC (:7700).
Exposes the machine to UAI as a new driver.

### 5. UAI sentry driver (NEW — UAI driver for rescued machines)
New driver in uai_broker.py that speaks to sentry-agent instances.
Adds machines to the /machines fleet view.

---

## sentry-agent Design

Runs inside Alpine rescue at boot time (added to OpenRC).
Lightweight — pure Python 3, no dependencies beyond stdlib.

### Registration (on boot)
```
POST http://192.168.110.XXX:7700/sentry/register
{
  "hostname": "truenas-server",
  "ip": "192.168.110.185",
  "agent_port": 7800,
  "capabilities": ["disk", "boot", "power", "os-probe"],
  "mode": "rescue"   // or "coexistence" if main OS still running
}
```

### State endpoint
```
GET /state
{
  "hostname": "truenas-server",
  "mode": "rescue",
  "ip": "192.168.110.185",
  "uptime": 142,
  "disks": [
    {"device": "/dev/sda", "size": "120G", "label": "TrueNAS boot", "smart": "ok"},
    {"device": "/dev/sdb", "size": "4T", "label": "Main data", "smart": "ok"}
  ],
  "boot_envs": [
    {"name": "TrueNAS SCALE", "device": "/dev/sda2", "status": "unknown"},
    {"name": "Sentry rescue", "device": "current", "status": "running"}
  ],
  "cpu": "AMD Ryzen 5 3600",
  "ram_total_gb": 62,
  "pci_devices": ["RTX 5060 Ti", "Realtek 2.5Gb"],
  "network": {"interface": "eth0", "ip": "192.168.110.185", "gateway": "192.168.110.1"}
}
```

### Action endpoint
```
POST /action
{
  "action": "reboot_to_os"      // chainload back to TrueNAS / Windows
  "action": "reboot_to_sentry"  // stay in rescue on next boot
  "action": "mount_disk"        // { "device": "/dev/sda2", "mountpoint": "/mnt/host" }
  "action": "smart_check"       // { "device": "/dev/sda" } → smartctl output
  "action": "run"               // { "cmd": "lsblk -O" } → stdout (scanning level only)
  "action": "install_proxmox"   // trigger unattended Proxmox install
  "action": "sentry_install"    // install sentry on another machine reached from here
}
```

---

## Per-OS Installation

### Linux (any UEFI distro)
Already designed in 03-installer-design.md.
```bash
sudo sentry-install  # run from within booted sentry-stick
# OR remote:
ssh user@host "curl -s http://sentry-deploy-server/installer.sh | sudo bash"
```

### Windows (new design)
Sentry lives on the existing ESP, adds a UEFI boot entry.
The EFI Alpine kernel boots regardless of Windows state.

Remote deploy steps:
```powershell
# Run via WinRM or SSH on Windows target
# 1. Find and mount ESP
$esp = (Get-Partition | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' })[0]
mountvol X: /S

# 2. Copy sentry EFI files
New-Item -Path "X:\EFI\sentry" -ItemType Directory -Force
Copy-Item sentry-efi\* X:\EFI\sentry\ -Recurse

# 3. Add EFI boot entry (not in boot order — F12 only)
$disk = $esp.DiskNumber
bcdedit /create /d "Sentry rescue" /application bootsector
# OR use efibootmgr-style tool: BootNext manipulation via WMI
```

Windows-specific sentry additions:
- Probe Windows BCD to find Windows boot entries → expose in /boot_envs
- Allow `"action": "reboot_to_windows"` → sets BootNext, reboots
- Allow reading Windows event logs from mounted NTFS (offline analysis)

### ESXi / VMware VMs
- Add a second virtual disk to the VM with a FAT32 EFI partition
- Configure VM boot order to try this disk first
- Sentry sees the VM's virtual disks, can snapshot/clone via VMware Tools

### Proxmox VMs
- Same as ESXi: add small virtio disk with EFI + sentry
- Or: directly add as EFI disk (`--efidisk0` with sentry content)

---

## sentry-deploy.py — Subnet Deployer

```python
#!/usr/bin/env python3
"""
sentry-deploy.py — deploy sentry rescue partition to every UEFI machine on subnet.

Usage:
  python sentry-deploy.py --subnet 192.168.110.0/24
  python sentry-deploy.py --host 192.168.110.185 --os linux
  python sentry-deploy.py --subnet 192.168.110.0/24 --dry-run

What it does per host:
  1. Port scan (22/tcp, 5985/tcp WinRM) to determine reachability + OS hint
  2. SSH (Linux) or WinRM (Windows) in
  3. Detect UEFI + ESP
  4. Copy sentry EFI bundle to ESP
  5. Add non-default EFI boot entry
  6. Write registration record
  7. Report to UAI broker: "sentry/hostname is available"
"""
```

Full implementation: `sentry-stick/sentry-deploy.py` (see code file)

---

## UAI Integration — New MCP Tools

Add to uai_mcp.py:

```python
# Fleet overview
uai_sentry_fleet()           # list all machines with sentry installed + current mode
uai_sentry_state(hostname)   # full state of one machine
uai_sentry_disks(hostname)   # disk inventory + SMART status
uai_sentry_boot_envs(hostname)  # available boot entries

# Control
uai_sentry_action(hostname, action, **kwargs)  # send action to agent
uai_sentry_reboot_os(hostname)   # boot back to main OS
uai_sentry_reboot_rescue(hostname)  # boot into sentry rescue
uai_sentry_mount(hostname, device, mountpoint)

# Deployment
uai_sentry_deploy(hostname, os_type)  # remote-deploy sentry to a new machine
uai_sentry_remove(hostname)           # uninstall sentry from a machine
```

---

## MSP Application (Conduit)

This becomes a Conduit skill:

```
POST /skills/sentry/deploy
{
  "client_id": "abc-corp",
  "subnet": "10.1.5.0/24",
  "credentials": { "ssh_key": "...", "winrm_user": "..." }
}
```

Conduit field agent (burr.py / agent.py) can:
1. Deploy sentry to every machine in a client's environment
2. Register all machines to client's UAI broker
3. Give the MSP "hardware-level eyes" on every machine without impacting users
4. Recovery path: if a machine breaks, reboot to sentry, fix remotely, reboot back

This is the **zero-touch remote repair** capability from the AI Helpdesk vision —
extended to work even when the main OS is dead.

---

## Build Order

| Step | What | Status |
|------|------|--------|
| M1 | USB builds + SSH lands | Code written, needs test |
| M2 | TrueNAS ESP install design | Done (docs/02 + 03) |
| M3 | `sentry-install` script | Designed, not coded |
| M4 | `sentry-agent` HTTP server | Designed here, not coded |
| M5 | UAI sentry driver | Designed here, not coded |
| M6 | `sentry-deploy.py` subnet deployer | Designed here, not coded |
| M7 | Windows remote installer | Designed here, not coded |
| M8 | Conduit skill | Deferred (needs M3-M6 first) |

**Immediate priority when hardware is back:**
1. Test M1 on TrueNAS (boot USB, SSH in)
2. Fix SSD visibility issue from sentry-stick SSH session
3. Code M3 (sentry-install) — needed for Proxmox migration path
4. Code M4 (sentry-agent) — needed for UAI integration
5. Add UAI sentry driver (M5) — extends fleet view

---

## What Changes in the Bigger Picture

Before sentry:
- AI controls what's running on machines it's explicitly connected to
- Machine breaks → need physical access

After sentry:
- AI has hardware-level access to every UEFI machine on the network
- Machine breaks → reboot to sentry, SSH in, fix, reboot back
- No physical access needed for any recovery scenario
- Every new machine added to network → one command to give AI control
- MSP scenario → AI controls client machines at hardware level, not just app level
