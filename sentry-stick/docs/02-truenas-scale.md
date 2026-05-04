# Target: TrueNAS Scale

The target server profile is TrueNAS Scale. This is the biggest input
to design and changes some assumptions we made earlier when planning
for "any modern Linux ext4 host." This doc captures what we know about
TrueNAS Scale and what that means for our installer.

## What TrueNAS Scale is

* Linux distribution based on Debian (Bookworm in 23.10+, "Cobia" /
  "Dragonfish" / "ElectricEel" releases).
* Boot drive is fully managed as a ZFS pool named `boot-pool`.
* User data lives on separate physical drives in their own zpools
  (e.g. `tank`).
* Web UI on :80/:443 (Angular SPA + Python middleware on the backend).
* Workloads: SMB/NFS/iSCSI shares, Docker apps (k3s under the hood),
  bhyve/KVM VMs.
* Boot environments: TrueNAS uses ZFS snapshots of the boot dataset as
  named "boot environments" — selectable at GRUB time. Upgrades clone
  a new BE; you can roll back from GRUB.

## Boot drive layout (typical, single drive)

```
/dev/sdX  (boot drive — usually a small SSD or USB)
├── p1   1 MiB           BIOS boot partition (for legacy GRUB)
├── p2   ~524 MiB         EFI System Partition (FAT32, ESP)
├── p3   16 GiB           swap (created on first boot, optional)
└── p4   rest             ZFS member — boot-pool (the TrueNAS root)
```

The ESP holds GRUB's `BOOTX64.EFI` plus a small `grub.cfg`. Real boot
configuration lives inside the ZFS boot environment. Only ~50 MB of
the ESP is used. **~470 MB free** on a default install.

If the operator chose **mirrored boot drives** at install time, every
boot drive has an identical partition layout and is a member of the
mirrored `boot-pool`. Each drive has its own ESP — they are
independent FAT32 filesystems, not a software-mirror at that level.

## Why this changes the installer plan

Original plan (for a generic ext4 Linux host) was:

> Carve a new GPT partition out of free space or by shrinking the
> root ext4. Put the rescue rootfs there. Add an EFI entry pointing
> at it.

That plan **does not work on TrueNAS Scale** because:

1. There is no "ext4 root" to shrink. The root is ZFS.
2. ZFS does not support shrinking a vdev. To reduce `boot-pool` size,
   you would have to destroy the pool and recreate it = effectively
   reinstall TrueNAS.
3. There is typically no unallocated GPT space on the boot drive.
4. The data drives (`tank`, etc.) hold user data and are off limits.

## Revised plan: ESP-resident rescue (E4 in 01-decisions.md)

We do not create a new partition. The rescue lives entirely in a
subdirectory of the existing ESP:

```
/dev/sdX  (TrueNAS boot drive — UNCHANGED partition table)
├── p1   1 MiB            BIOS boot partition  (untouched)
├── p2   ~524 MiB ESP     ── EFI/  ── BOOT/   ── BOOTX64.EFI    (TrueNAS GRUB)
│                                  ── debian/ ── grubx64.efi    (TrueNAS GRUB)
│                                  ── sentry/ ── BOOTX64.EFI    ← OUR grub
│                                              ── grubx64.efi
│                                              ── grub.cfg
│                                              ── vmlinuz
│                                              ── initramfs     (with rootfs baked in)
│                                              ── engagement.yaml
│                                              ── authorized_keys
│                                              ── STATUS.TXT    (written each boot)
│                                              ── install-record.json
│                                              ── logs/         (per-boot directories)
├── p3   16 GiB            swap  (untouched)
└── p4   rest              boot-pool ZFS  (UNTOUCHED)
```

What the installer does:

1. Find the ESP that GRUB booted from (via `findmnt /boot/efi`).
2. Verify ≥ 200 MB free on the ESP.
3. Create `/EFI/sentry/`.
4. Copy our `grubx64.efi` + `grub.cfg` + `vmlinuz` + `initramfs` (~80–150 MB).
5. Copy the USB's `engagement.yaml` + `authorized_keys` into the new dir.
6. `efibootmgr -c -d <disk> -p 2 -L "Sentry rescue (DO NOT CHANGE)" -l '\EFI\sentry\BOOTX64.EFI'`.
7. Recompute `BootOrder` to keep the new entry **out** of it (= F12-only).
8. If host has a mirrored boot pool: do steps 3–6 on the **second** ESP too. Both EFI entries get the same label with `(mirror N)` suffix.
9. Write install record to `/EFI/sentry/install-record.json` and back to the USB.

What the installer does **not** do:

* It does not touch the BIOS boot partition.
* It does not touch swap.
* It does not touch `boot-pool` or any ZFS pool.
* It does not touch any user data drive (`/dev/sda`, `tank`, etc.) — auto-excluded.
* It does not modify TrueNAS's `grub.cfg` (TrueNAS regenerates it on
  upgrades and would clobber our edits). EFI boot menu is the supported
  entry point. We do, however, write a host-side menu fragment to
  `/EFI/sentry/grub-host-entry.cfg` that an operator can `configfile`
  from TrueNAS's GRUB if they want — but we do not auto-wire it.

## What the rescue can reach when it boots

When the operator selects "Sentry rescue" from F12:

* Our kernel boots from the ESP, initramfs unpacks (rootfs is baked in,
  so no separate root partition needed).
* sentry-init runs, just like on the USB. It finds the ESP that
  contains `/EFI/sentry/`, mounts it at `/boot/cfg`, reads
  `engagement.yaml` and `authorized_keys` from there.
* DHCP comes up.
* sshd starts.
* From SSH, the operator can:
  * `lsblk` and see the host's ZFS member (`/dev/sdXp4`).
  * `sudo sentry-exec mount` (won't work on ZFS — ext4 only via the
    standard `mount -t`); but **`zpool import -fR /mnt boot-pool`** is
    available because we ship `zfs` tooling (added to packages.list as
    part of M3).
  * Inspect `/mnt/etc/`, `/mnt/var/log/`, etc.
  * Roll back the boot environment with `zfs rollback`.
  * Repair network configs, restart services after reboot, etc.

## Things to add to packages.list for TrueNAS support (M3)

```
zfs                    # zpool, zfs CLI tools (OpenZFS userland)
zfs-utils              # auxiliary
ipmitool               # frequent on TrueNAS hardware (BMC interaction)
ethtool
```

Note that the ZFS kernel module is huge and licensing-tricky on
Alpine. Two paths:

* (a) Use OpenZFS DKMS-built into the initramfs. Costs build complexity.
* (b) Don't ship the ZFS kernel module on the rescue; only ship the
  userland CLI. The operator can still inspect ext4/xfs/btrfs/swap
  partitions and the ESP. ZFS pool import requires the kernel module,
  which we won't have. **Recommendation: ship userland only for MVP**
  and document this limitation. M6 picks up DKMS or a ZFS-blessed
  rescue distro.

If we don't have the ZFS kernel module, we still cover most TrueNAS
fix scenarios:

* Network broken → fix `/EFI/sentry/engagement.yaml`, reboot rescue.
* TrueNAS web UI hung → SSH into rescue, `nsenter` into the host… no,
  can't do that without ZFS-mounting the host root. Limitation.
* Boot environment corrupt → can list ZFS pools (no), need ZFS kmod.

For TrueNAS fix scenarios where ZFS kmod is **not** required, the
rescue is still very useful:

* Diagnose hardware (smartctl on data drives, ipmitool, lspci, dmesg).
* Investigate network config from the perspective of an outside Linux box.
* Wipe and reflash if the goal is reinstall.

For the ones where ZFS kmod IS required, the operator falls back to a
TrueNAS install USB (which has the kmod). We document this in the
README so there are no surprises.

## Mirrored boot drive considerations

If the user has a mirrored boot pool, our installer should:

1. Detect both drives via `zpool status boot-pool` parsing.
2. Find each drive's ESP (`p2` typically).
3. Install to **both** ESPs.
4. Create **two** EFI boot entries, one per drive — same label, with
   `(disk1)` / `(disk2)` suffix. This way if the firmware decides only
   one drive is bootable that day, the rescue is still reachable.

Implementation: add an `--all-boot-drives` flag (default true on TrueNAS)
that walks the boot-pool members.

## Open question: kernel modules / firmware

TrueNAS hardware is varied. Common NICs include:

* Intel (i210, i350, X550, X710 — `e1000e`, `igb`, `ixgbe`, `i40e`)
* Realtek (`r8169`)
* Broadcom (`bnx2`, `bnxt_en`)
* Mellanox (`mlx4_en`, `mlx5_core`) on some pro builds
* Chelsio (`cxgb4`) on some pro builds

We currently ship `linux-firmware-intel`, `linux-firmware-realtek`,
`linux-firmware-other`. That covers the first two. For Broadcom we
should add `linux-firmware-bnx2` and `linux-firmware-brcm`. Mellanox
firmware is in `linux-firmware-mellanox`. Chelsio in `linux-firmware-chelsio`.

Recommendation: **ship them all on the USB image** (firmware adds maybe
20–30 MB total). For the installed rescue (initramfs-baked), trim to
whatever NIC the install host actually has — `lspci` at install time
tells us, and the installer can pick the matching firmware.

## What we lose by going ESP-resident

* No persistent state outside the FAT32 ESP. Logs land on FAT, which
  has no journaling. Acceptable for diagnostic logs but worth
  documenting.
* No swap available in the rescue (we don't make one). Rescue runs
  entirely from RAM with the initramfs as rootfs (~150–250 MB).
* `/var/log` bind-mount to a real ext4 partition is no longer possible
  in installed mode. Logs go to a directory inside the FAT ESP.
