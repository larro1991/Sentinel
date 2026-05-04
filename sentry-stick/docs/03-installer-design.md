# M3 — `sentry-install` (ESP-resident installer)

> Status: designed, not coded. Replaces the earlier "carve a new GPT
> partition" plan because the target is TrueNAS Scale with a ZFS boot
> pool. See `02-truenas-scale.md` for context.

## Goal

From inside an SSH session on the booted USB, the operator runs
`sudo sentry-install`. When it returns successfully, the host's
existing ESP contains a hidden subdirectory `/EFI/sentry/` with a
bootable rescue kernel + initramfs + config; the firmware has a new
boot entry "Sentry rescue (DO NOT CHANGE)" that is **not in the
default boot order**; the host's main OS still boots normally on
the next reboot. `sudo sentry-install --uninstall` reverses every
change.

## Inputs the installer reads

| Source | What |
|--------|------|
| `/etc/sentry/auth.level`               | must be `scanning` (refuse if `passive`) |
| `/etc/sentry/scope.env`                | for the same `allowed_devices` enforcement we already have |
| `/usr/local/share/sentry/rescue-payload/` | the prebaked kernel/initramfs/grub.cfg that gets copied to the ESP. Built by `build.sh` and placed on the USB during build. |
| `/boot/cfg/engagement.yaml` (the USB's) | source for the rescue's engagement.yaml |
| `/boot/cfg/authorized_keys` (the USB's) | source for the rescue's authorized_keys |
| Host disks (read-only first)           | discovered via lsblk, sgdisk, blkid, zpool |
| Optional flags                         | overrides for size, label, paths |

## Phases

Each phase logs every action with elapsed-ms + rc into
`/var/lib/sentry/logs/current/install-<install-id>.log` and a
structured JSONL into `install-<install-id>.jsonl`. A flock on
`/var/run/sentry-install.lock` prevents concurrent installs.

### Phase 1 — discover

* Confirm we are running with `auth.max_level=scanning`.
* Enumerate disks with `lsblk -J -o NAME,SIZE,TYPE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINT,VENDOR,MODEL,SERIAL`.
* Drop disks that are in `/etc/sentry/excluded_devices` (= the USB).
* For each remaining disk:
  * `sgdisk -p <disk>` — verify GPT.
  * Find ESP: partition with `EF00` type or `esp` flag set.
  * Find ZFS members: partitions with type `BF01`/`BF07` or partlabel `*-zfs*`.
  * Identify if this disk is part of a `boot-pool` mirror (parse `zpool import` even though we may not have ZFS kmod — we have the userland which can parse pool metadata).
* Pick "the" target disk: the disk whose ESP holds the bootloader the
  current firmware would use (we can read this from `efibootmgr -v` —
  the active `BootCurrent` if we were chainloaded, otherwise the
  highest-priority entry that points at a disk we can see).

  > Note: when running from the USB, `BootCurrent` points to the USB.
  > To find the host's expected boot disk, we walk the saved-pre-USB
  > order from `efibootmgr -v` and pick the first entry that resolves
  > to a non-USB disk's ESP. This is a heuristic; always show the
  > result to the operator and require confirmation.

* Detect mirrored boot drives: parse `zpool import -d /dev/disk/by-id` output for `boot-pool`.

### Phase 2 — propose + confirm

* Render the plan in human-readable form. Example:

  ```
  Proposed install
  ----------------
  Host:                   <hostname-from-resolv-or-uname>
  Target disk(s):         /dev/sda  (mirror /dev/sdb)
  ESP path:               /dev/sda2  (mounted at /mnt/host-esp)
  ESP free space:         473 MiB  (need ≥ 200 MiB)
  Payload size:           ~140 MiB  (kernel 8 MiB, initramfs 132 MiB)
  Sentry subdirectory:    /EFI/sentry/
  EFI boot entry label:   "Sentry rescue (DO NOT CHANGE)"
  Boot order behaviour:   keep new entry OUT of BootOrder (F12-only)
  Mirror handling:        install to both /dev/sda2 AND /dev/sdb2
  Engagement source:      /boot/cfg/engagement.yaml  (this USB)
  Authorized keys source: /boot/cfg/authorized_keys  (this USB, 1 key)

  Items NOT touched:
    /dev/sda1  (BIOS boot)
    /dev/sda3  (swap)
    /dev/sda4  (boot-pool ZFS) ← TrueNAS lives here
    /dev/sdb*  (mirror)
    All data drives: /dev/sdc, /dev/sdd, /dev/sde

  Reversal command:       sudo sentry-install --uninstall
  Install record:         /EFI/sentry/install-record.json
                          + /var/lib/sentry/installs/<host-id>.json
  ```

* Save the plan as JSON.
* `sgdisk --backup=<logdir>/<disk>-pt-pre.bin <disk>` for **each** target disk — partition table snapshot. We do not modify the GPT in the ESP-resident design, but we save it anyway so we can detect drift after the install.
* `efibootmgr -v > <logdir>/efi-pre.txt`.
* Hash the existing ESP contents (`find /mnt/host-esp -type f -exec sha256sum {} \;`) into `<logdir>/esp-pre-hashes.txt`. This lets us detect that we did not corrupt the existing TrueNAS bootloader files.
* Require explicit confirmation typed in full: operator must type
  `yes-install-on-/dev/sda` (substituting the actual target disk).

### Phase 3 — execute

Each step recorded with its inverse for rollback.

| Step | Action | Inverse for rollback |
|------|--------|----------------------|
| 3a   | `mount -o ro /dev/sdXp2 /mnt/host-esp` then verify ESP is FAT32 + has `EFI/BOOT/BOOTX64.EFI` (= TrueNAS bootloader) | `umount /mnt/host-esp` |
| 3b   | Remount read-write | revert to ro |
| 3c   | Verify free space ≥ 200 MiB on the ESP | n/a |
| 3d   | `mkdir /mnt/host-esp/EFI/sentry` | `rmdir` |
| 3e   | Copy `/usr/local/share/sentry/rescue-payload/*` into `/EFI/sentry/`. Files: `BOOTX64.EFI`, `grubx64.efi`, `grub.cfg`, `vmlinuz`, `initramfs` | `rm -rf /EFI/sentry` |
| 3f   | Copy USB's `engagement.yaml` and `authorized_keys` into `/EFI/sentry/` | `rm` |
| 3g   | `mkdir /EFI/sentry/logs` (rescue will write here) | `rm -rf /EFI/sentry/logs` |
| 3h   | Compute SHA256 of every file we placed; write `manifest.json` | n/a |
| 3i   | If host has mirrored boot drives, repeat 3a–3h for the second ESP | mirror rollback |
| 3j   | `efibootmgr -c -d /dev/sdX -p 2 -L "Sentry rescue (DO NOT CHANGE)" -l '\EFI\sentry\BOOTX64.EFI'` → returns `BootNNNN` | `efibootmgr -B -b NNNN` |
| 3k   | (mirror) repeat 3j against second drive with label `(mirror 2)` suffix | rollback both |
| 3l   | Get current `BootOrder`; remove the new `NNNN` from it; `efibootmgr -o <order-without-new>` | restore from `efi-pre.txt` |
| 3m   | Verify: re-list `efibootmgr -v` and confirm entry exists; re-hash ESP and confirm only files under `/EFI/sentry/` differ from `esp-pre-hashes.txt` | n/a |
| 3n   | Write `install-record.json` to `/EFI/sentry/` (and copy to `/var/lib/sentry/installs/<host-id>.json` on the USB's P3) | n/a |
| 3o   | `umount /mnt/host-esp` (and mirror) | n/a |

### Phase 4 — rollback

Triggered on any non-zero step return code. Walks the recorded steps
in reverse using their `inverse` tag. Logs every undo. At the end,
emits one of:

* `rollback: clean — no changes remain on host`
* `rollback: partial — manual review needed for: <list>`

The latter only happens if EFI variable manipulation went sideways
(rare) or if the ESP filesystem has a corruption error mid-write
(extremely rare). We log the failure mode in detail.

### Phase 5 — report

```
Sentry rescue installed on <hostname>.
  Boot entry:            Sentry rescue (DO NOT CHANGE)  (BootNNNN)
  Boot order:            kept out of default order (use F12 to invoke)
  Mirror copies:         2 (sda2, sdb2)
  Payload SHA256:        a3f9...e2 (manifest.json)
  Install record:        /EFI/sentry/install-record.json
  Reversal command:      sudo sentry-install --uninstall

Reboot the host now WITHOUT removing the USB to verify host's main OS
still boots; then remove the USB; then reboot once more, press F12,
select "Sentry rescue", and verify SSH access.
```

## `sentry-install --uninstall`

* Read the most recent install record.
* Show what will be removed (subset of phase 5 report).
* Require confirmation typed in full: `yes-uninstall-<install-id>`.
* For each EFI entry created: `efibootmgr -B -b NNNN`.
* For each ESP touched: mount rw, `rm -rf /EFI/sentry`, umount.
* Restore EFI `BootOrder` from the saved file (idempotent).
* Verify clean: re-hash ESP against `esp-pre-hashes.txt`; abort with
  diagnostic if anything other than `/EFI/sentry/` differs.
* Update install record on USB to `status: uninstalled`.

## Flags

```
sentry-install [options]

  --dry-run                  run phases 1+2 only; print plan; touch nothing
  --disk <path>              override target disk discovery
  --esp-mountpoint <path>    override ESP discovery (default: auto)
  --no-mirror                install to one ESP only even if pool is mirrored
  --keep-in-boot-order       (default: removed) leave new entry in BootOrder
  --boot-label <string>      override the EFI entry label
  --engagement <file>        use this engagement.yaml instead of USB's
  --keys <file>              use this authorized_keys instead of USB's
  --payload <dir>            use this rescue payload instead of /usr/local/share/sentry/rescue-payload
  --min-esp-free MIB         abort if ESP free < this many MiB (default 200)
  --uninstall [--id <id>]    reverse a previous install (default: most recent)
  --list                     list past installs known to this USB
  --verify <id>              re-hash ESP files against the install's manifest
  --yes                      bypass interactive confirmation (must still type the matching string on stdin)
  --json                     machine-readable output
```

## Open implementation questions (will revisit before coding)

1. **The rescue payload itself.** `build.sh` currently builds the USB
   only. We need to extend it to also produce
   `/usr/local/share/sentry/rescue-payload/`. Specifically:
   * Build a *second* initramfs that is the rootfs (or contains a
     squashfs of the rootfs that the initramfs mounts via overlayfs).
   * Stage it alongside a `grub.cfg` that searches by ESP file
     marker rather than by partition label.
   * Stage a `BOOTX64.EFI` and `grubx64.efi` from `grub-mkimage`.

2. **NIC firmware in the rescue payload.** Including all firmware
   bloats the initramfs. Two options:
   * (a) Include all major-vendor firmware (Intel + Realtek + Broadcom + Mellanox) → ~30 MB extra.
   * (b) `lspci` at install time, pick matching firmware. Smaller payload but installer needs to know about firmware-package mapping.
   * Recommendation: (a). Predictable, small enough.

3. **Concurrent ESP access.** TrueNAS's GRUB is loaded from the same
   ESP we're writing to. If the operator triggers a TrueNAS GRUB
   upgrade mid-install (unlikely but possible), conflict. The flock
   protects us from another `sentry-install` but not from TrueNAS's
   own update. Mitigation: complete in seconds, copy-then-rename for
   atomic-ish writes, recommend the operator does not trigger a
   TrueNAS upgrade in the same window.

4. **Mirror discovery without ZFS kernel module.** `zpool import` can
   parse pool metadata using only the userland tools, but only if it
   can read the disk. We have read access. Need to verify in QEMU
   that `zpool import` (no kmod) lists the pool name and member
   devices. If it doesn't, fall back to "find all disks with an ESP
   and a partition typed as ZFS" heuristic.

5. **What if the operator's USB is the only thing booting and the
   firmware does not show a boot menu?** We can configure the new EFI
   entry as `Active = false` and surface an `--enable-boot-entry`
   subcommand. But that's M6.
