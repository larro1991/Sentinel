# Proxmox Migration Plan

## Why

TrueNAS SCALE has no driver for NVIDIA Blackwell (RTX 5060 Ti).
Running Proxmox as the bare-metal hypervisor solves this:

- GPU passthrough to a Linux VM → Ollama at 40+ tok/s (currently 6-8 tok/s on CPU)
- TrueNAS runs as a Proxmox VM with ZFS disk passthrough → all 48 containers survive intact
- GPU also available for Emby NVENC hardware transcoding in TrueNAS VM (or dedicated VM)

This is the **end goal**. Everything in sentry-stick is the means to execute it headlessly
(no video output — RTX 5060 Ti has no TrueNAS driver, motherboard has no iGPU).

---

## Server Hardware

| Component | Detail |
|-----------|--------|
| CPU | AMD Ryzen 5 3600 (6c/12t, AM4) |
| RAM | 62 GB |
| MB | ASUS TUF Gaming B550-PLUS WiFi II |
| GPU | RTX 5060 Ti 16GB GDDR7 (Blackwell, no TrueNAS driver) |
| PSU | 750W modular (new, replaced dead Thermaltake 500W) |
| NIC | Realtek 2.5Gb (onboard, `r8169` driver) |
| LAN IP | 192.168.110.185 (DHCP reservation — keep this) |

---

## Phase 0 — Fix BIOS / SSD Visibility (physical, before anything else)

BIOS cannot see the boot SSD after MB swap. Do this first:

1. Power off. Open case.
2. Check SSD connection:
   - If SATA SSD: reseat both ends of SATA data cable. Check power connector.
   - If M.2/NVMe: reseat the card, re-tighten screw.
3. Power on. Enter BIOS (Del or F2 on ASUS).
4. Navigate to Advanced → Storage:
   - SATA mode must be **AHCI** (not RAID, not IDE).
   - M.2 slot must be enabled (check if PCIe mode/slot is stealing M.2 lanes).
5. Check Boot → Boot Order — SSD should appear.
6. If SSD appears: save + exit. TrueNAS should boot normally.
7. If SSD still invisible: drive may have failed. Continue with Phase 1 anyway
   (sentry-stick can diagnose from within Linux even if BIOS can't see it).

---

## Phase 1 — Boot Sentry-Stick (headless access)

### 1a. Build the image (already done — see below)

```bash
# Run on GamingPC from C:\Dev\active\sentry-stick\
docker run --rm --privileged \
  -v "$(pwd)/sentry-stick":/work -w /work \
  alpine:3.21 sh -c \
  'apk add --no-cache bash parted dosfstools e2fsprogs grub grub-efi efibootmgr mtools rsync && bash /work/build.sh'
```

Output: `sentry-stick/usb.img`

### 1b. Flash to USB

**Windows (PowerShell as admin):**
```powershell
# Find the USB disk number
Get-Disk | Where-Object BusType -eq USB | Select-Object Number, Size, FriendlyName

# Flash (replace DiskNumber with actual number — double-check before running)
$disk = 1   # CHANGE THIS
$img  = "C:\Dev\active\sentry-stick\sentry-stick\usb.img"
& "C:\Program Files\Git\usr\bin\dd.exe" if=$img of="\\.\PhysicalDrive$disk" bs=4M
# OR use Rufus / balenaEtcher — write usb.img in DD mode (not ISO mode)
```

**Verify after flash:** Eject + replug. Windows should show a FAT32 drive labelled `SENTRYBOOT`.
Open it — you should see `vmlinuz-lts`, `initramfs-lts`, `engagement.yaml`, `authorized_keys`.

### 1c. Boot server from USB

1. Plug USB into TrueNAS server.
2. Power on. Tap **F8** (ASUS boot menu) or **F2** (BIOS) to select boot device.
3. Select the USB drive (shows as "UEFI: <USB name>").
4. No video needed after this point — sentry-init runs, gets DHCP, starts sshd.

### 1d. Find the IP

Options (in order of preference):
- Check router DHCP table for hostname `truenas-rescue`
- Scan: `nmap -sn 192.168.110.0/24 | grep -A1 truenas-rescue`
- STATUS.TXT on the USB FAT partition (written at boot — eject+replug USB to read on another machine)

### 1e. SSH in

```bash
ssh sentry@192.168.110.XXX
# Uses ~/.ssh/id_ed25519 automatically (key is in authorized_keys on the stick)
```

---

## Phase 2 — Diagnose from Sentry-Stick

Once SSH'd in, run these immediately:

```bash
# What does Linux see for storage?
lsblk -O
blkid

# Is the TrueNAS boot SSD visible (even if BIOS couldn't boot from it)?
# Look for /dev/sda or /dev/nvme0n1 with partitions matching TrueNAS layout:
#   p1 = 1MB BIOS boot
#   p2 = ~524MB FAT32 ESP
#   p3 = 16GB swap
#   p4 = ZFS member (boot-pool)

# ZFS pool status (userland only — no zpool import without kernel module)
zpool status 2>/dev/null || echo "ZFS kmod not loaded (expected in MVP)"

# Hardware inventory
sudo sentry-exec smart scan-disks
sudo sentry-exec scan-disks
lspci | grep -E 'SATA|NVMe|VGA|Storage'

# NIC name (may not be eth0 — ASUS B550 Realtek might be enp4s0 or enp3s0)
ip addr
```

### Decision tree after lsblk:

| What lsblk shows | Action |
|-----------------|--------|
| TrueNAS SSD visible with all 4 partitions | Boot order issue only. Fix in BIOS. TrueNAS intact. |
| SSD visible but ZFS partition looks wrong | Possible partial overwrite from Debian attempt. See recovery section. |
| SSD not visible at all | Reseat again. Check smartctl. May need replacement SSD. |

---

## Phase 3 — Proxmox Install (no video required)

### Method: Proxmox Unattended Install via Answer File

Proxmox VE 8.1+ supports fully automated installation using an `answer.toml` file.
No interaction required — boots ISO, reads file, installs, reboots.

### 3a. Download Proxmox ISO to sentry-stick (from server's SSH session)

```bash
# From inside sentry SSH session on the server:
cd /tmp
wget https://enterprise.proxmox.com/iso/proxmox-ve_8.3-1.iso
# ~1.2GB — takes a few minutes on 2.5Gb LAN
```

### 3b. Write ISO to a SECOND USB stick

Plug a second USB into the server (from the machine room or remotely via someone on-site).
```bash
# From sentry SSH session:
lsblk  # identify the second USB — it WON'T have SENTRYBOOT label
# Assume it's /dev/sdb (verify first!)
sudo sentry-exec dd if=/tmp/proxmox-ve_8.3-1.iso of=/dev/sdb bs=4M
sync
```

### 3c. Create answer.toml on the Proxmox USB

```bash
# Mount the Proxmox USB FAT partition
mkdir -p /mnt/proxmox-usb
mount /dev/sdb2 /mnt/proxmox-usb  # partition varies — check blkid

# Write the answer file
cat > /mnt/proxmox-usb/answer.toml << 'EOF'
[global]
keyboard = "en-us"
country = "us"
fqdn = "proxmox.lan"
mailto = "larro91@gmail.com"
timezone = "America/Chicago"
root_password = "CHANGE_THIS_BEFORE_BOOT"
root_ssh_keys = [
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPkGcfwFFRzidQCBjtVkRw2zrF2OyQVCyWFlCuKUwQym larro@GamingPC"
]

[network]
source = "from-dhcp"

[disk-setup]
filesystem = "ext4"
disk_list = ["sda"]   # CHANGE to actual boot disk device name

[EOF]
umount /mnt/proxmox-usb
```

**IMPORTANT**: Change `root_password` before booting. Change `disk_list` to match the actual
TrueNAS boot SSD device name (from Phase 2 lsblk output).

### 3d. Boot from Proxmox USB

1. From sentry SSH session: `sudo reboot`  (or power cycle if no IPMI)
2. At boot, select Proxmox USB from boot menu (F8 on ASUS)
3. Proxmox installer detects `answer.toml`, installs automatically (~5-10 min)
4. Server reboots into Proxmox

### 3e. SSH into Proxmox

```bash
# Proxmox should get the same DHCP reservation (192.168.110.185)
# or check router for new hostname "proxmox.lan"
ssh root@192.168.110.185
```

---

## Phase 4 — Proxmox Configuration

### 4a. Enable IOMMU for GPU passthrough (AMD Ryzen)

```bash
# Edit GRUB
nano /etc/default/grub
# Change: GRUB_CMDLINE_LINUX_DEFAULT="quiet"
# To:     GRUB_CMDLINE_LINUX_DEFAULT="quiet amd_iommu=on iommu=pt"

update-grub
reboot
```

After reboot, verify:
```bash
dmesg | grep -i iommu
find /sys/kernel/iommu_groups/ -type l | sort -V | head -20
```

### 4b. Bind RTX 5060 Ti to VFIO

```bash
# Find RTX 5060 Ti PCI ID
lspci | grep -i nvidia
# Example output: 01:00.0 VGA compatible controller: NVIDIA RTX 5060 Ti

# Get vendor:device ID
lspci -n | grep 01:00
# Example: 01:00.0 0300: 10de:2803 (NVIDIA vendor 10de, device 2803 — get actual IDs)

# Add VFIO for the GPU (and its audio function 01:00.1)
echo "options vfio-pci ids=10de:XXXX,10de:YYYY" > /etc/modprobe.d/vfio.conf
echo "vfio-pci" >> /etc/modules
echo "vfio_iommu_type1" >> /etc/modules
update-initramfs -u
reboot
```

Verify GPU bound to vfio-pci:
```bash
lspci -k | grep -A3 NVIDIA
# Should show "Kernel driver in use: vfio-pci"
```

### 4c. Create TrueNAS VM (ZFS disk passthrough)

TrueNAS needs direct access to the data drives to manage ZFS pools.
Pass through the physical disks (not Proxmox virtual disks).

```bash
# Find data disk serial numbers (NOT the boot SSD — that's now Proxmox)
ls /dev/disk/by-id/ | grep -v part | grep -v wwn

# Create TrueNAS VM (via Proxmox web UI at https://192.168.110.185:8006)
# Or via CLI:
qm create 100 --name truenas \
  --memory 32768 --cores 4 --cpu host \
  --net0 virtio,bridge=vmbr0 \
  --bios ovmf --efidisk0 local-lvm:1 \
  --machine q35 \
  --ostype l26

# Add TrueNAS install ISO (download from truenas.com)
# Add passthrough disks (replace sdX with actual data drive IDs):
qm set 100 --scsi1 /dev/disk/by-id/ata-XXXXXXXXX,backup=no
qm set 100 --scsi2 /dev/disk/by-id/ata-XXXXXXXXX,backup=no
# ... repeat for all data drives

# Download TrueNAS SCALE ISO and boot from it to install fresh
# OR: if TrueNAS ZFS data pool is intact, import it after fresh TrueNAS VM install
```

### 4d. Create Ollama Linux VM (GPU passthrough)

```bash
# Create Ubuntu 24.04 VM
qm create 101 --name ollama-gpu \
  --memory 16384 --cores 4 --cpu host \
  --net0 virtio,bridge=vmbr0 \
  --bios ovmf --efidisk0 local-lvm:1 \
  --machine q35

# Add RTX 5060 Ti passthrough
qm set 101 --hostpci0 01:00,allFunctions=1,pcie=1,x-vga=1

# Boot Ubuntu, install NVIDIA drivers + Ollama
# Then configure PM agent → http://192.168.110.185:11434 (or new IP)
```

---

## Phase 5 — Service Recovery

After TrueNAS VM is running with data drives passed through:

1. ZFS pool `Main` auto-imports → all appdata intact
2. Docker services restart automatically (restart: unless-stopped)
3. Verify key services:
   ```bash
   docker ps | grep -E 'pm-telegram|nullclaw|crucible|traefik'
   ```
4. PM agent should come back on its own — verify via Telegram bot
5. Update Ollama endpoint in all services to point at the GPU VM's IP

---

## Key Risks

| Risk | Mitigation |
|------|------------|
| Proxmox overwrites TrueNAS data drives | answer.toml `disk_list` targets boot SSD only — verify device name before running |
| ZFS pool lost in migration | Data drives are passed through raw, not touched by Proxmox |
| TrueNAS containers need reconfiguration | All config in /mnt/Main/appdata/ — survives on the ZFS pool |
| IOMMU groups bundle GPU with other devices | Check iommu_groups before binding — may need ACS patch kernel |
| RTX 5060 Ti Blackwell driver in Proxmox host | Host only needs vfio-pci; VM gets full NVIDIA driver |

---

## Reference: Current TrueNAS Container Inventory

Critical services to verify after migration:
- pm-telegram (PM agent, Telegram bot)
- crucible (MCP server :8090)
- nullclaw (Discord bot :5081)
- traefik (reverse proxy)
- ops-monitor (:5079)
- media pipeline (video-pipeline, library-intake, handbrake, whisper)
- adguard (DNS :3030)
- radarr/sonarr/bazarr/emby (media)
- paperless-ngx (documents)
- audiobookshelf, kavita, calibre (library)
- home-assistant, n8n (automation)
- local-ai-ollama (:11434) — will move to GPU VM
