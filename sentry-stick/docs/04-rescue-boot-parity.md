# M4 — rescue boot parity

> When the operator selects "Sentry rescue" from F12, the experience
> should be indistinguishable from booting the USB: same SSH lifeline,
> same logs, same auth model. This doc lists the specific changes to
> existing code needed to support both modes from one codebase.

## Boot mode detection

Add a stanza at the very top of `sentry-init` (after the early-log
setup, before mounting partitions):

```sh
detect_mode() {
    if   blkid -L SENTRYBOOT          >/dev/null 2>&1; then echo usb
    elif [ -d /boot/efi/EFI/sentry ]   ;                 then echo installed
    elif [ -d /sys/firmware/efi/efivars ] && \
         find /boot -name "EFI/sentry" -maxdepth 3 -type d \
              2>/dev/null | grep -q .; then echo installed
    else echo unknown
    fi
}
SENTRY_MODE=$(detect_mode)
echo "[mode] SENTRY_MODE=$SENTRY_MODE"
```

The detection is conservative: USB takes priority because USB is
ephemeral and we never want to mistake an installed boot for a USB
boot.

## Mount-point divergence

| | USB mode | Installed mode |
|---|---|---|
| Boot config | `mount -L SENTRYBOOT /boot/cfg` (FAT) | mount the host's ESP at `/boot/cfg` (FAT). The ESP is identified by walking GPT for `EF00` partitions and picking the one that contains `/EFI/sentry/`. |
| State (logs, host keys) | `mount -L sentry-state /var/lib/sentry` (ext4 on USB P3) | the rootfs (initramfs-as-tmpfs) at `/var/lib/sentry/` — but tmpfs is volatile. So instead: a subdirectory of the host's ESP at `/boot/cfg/logs/` is bind-mounted to `/var/lib/sentry/logs/`. Host keys persisted at `/boot/cfg/ssh-host-keys/`. |
| `/var/log` bind | bind to `/var/lib/sentry/logs/current/var-log/` (ext4) | bind to `/boot/cfg/logs/current/var-log/` (FAT — no journal but writes work) |

`sentry-init` becomes mode-aware:

```sh
case "$SENTRY_MODE" in
    usb)
        BOOT_LABEL="SENTRYBOOT"
        STATE_LABEL="sentry-state"
        STATE_MOUNT=/var/lib/sentry
        ;;
    installed)
        BOOT_DEV=$(find_host_esp_with_sentry)   # new helper
        STATE_MOUNT=/boot/cfg                   # we write logs INTO the boot dir
        ;;
esac
```

## Engagement.yaml location

Same path inside `sentry-init` (`$P1_MOUNT/engagement.yaml`), but
the partition mounted at `$P1_MOUNT` differs by mode:

| Mode | What `/boot/cfg/engagement.yaml` actually is |
|------|---------------------------------------------|
| USB  | `<USB-FAT>/engagement.yaml` |
| Installed | `<host-ESP>/EFI/sentry/engagement.yaml` |

So sentry-init code does not change here — only the mount target does.

## STATUS.TXT location

| Mode | STATUS.TXT path |
|------|-----------------|
| USB  | `<USB-FAT>/STATUS.TXT` |
| Installed | `<host-ESP>/EFI/sentry/STATUS.TXT` |

Operator can pull the boot drive (or just look at the ESP from another
boot) and read it.

## Authorized keys

In both modes, sentry-init copies `<boot>/authorized_keys` to
`/home/sentry/.ssh/authorized_keys`. No code change needed.

## Host SSH keys

* **USB mode**: persisted at `/var/lib/sentry/ssh-host-keys/` on the
  ext4 P3.
* **Installed mode**: persisted at `/boot/cfg/ssh-host-keys/` on the
  ESP (FAT). Permission semantics on FAT differ — we explicitly chmod
  the keys post-restore even though FAT may not honour it. SSH on
  Alpine accepts FAT-stored host keys when `StrictModes no`. We will
  need either (a) `StrictModes no` in installed mode, or (b) copy
  host keys to a tmpfs mount and chmod there.

  Recommendation (b): copy host keys from the ESP to `/etc/ssh/` (which
  is in tmpfs after initramfs unpack), chmod 600 there, sshd reads
  from /etc/ssh. The ESP just stores the persisted copy.

## Initramfs-as-rootfs

USB mode boots `root=LABEL=sentry-root rootfstype=ext4 rw` and the
initramfs hands off to the ext4 rootfs. Installed mode boots with no
`root=` parameter (or `root=tmpfs`); the initramfs **is** the rootfs.

Two implementation paths:

### (i) Big initramfs (recommended)

Pack the entire Alpine rootfs into the initramfs cpio. Boot kernel
boots, initramfs unpacks (~150–250 MB into RAM as tmpfs), `/init`
inside the initramfs is sentry's PID 1. We never `switch_root`.

Pros: simplest, no overlay magic, well-supported.
Cons: uses the full rootfs's worth of RAM forever.

### (ii) Initramfs + squashfs + overlayfs

Pack a tiny initramfs that knows how to: find a `rootfs.sqfs` on the
ESP, mount it on `/lower`, mount tmpfs on `/upper`, mount overlayfs
combining them on `/sysroot`, `switch_root` to `/sysroot`.

Pros: lower RAM, immutable lower layer.
Cons: more bootstrap code, overlayfs quirks.

**MVP picks (i).** TrueNAS hardware has many GB of RAM; 250 MB is
nothing. Iterate to (ii) in M6 if anyone cares.

## grub.cfg variants

Two configs, both shipped in the `rescue-payload/` directory and
copied to the ESP:

`grub.cfg` (USB mode, used today):
```
search --no-floppy --label SENTRYBOOT --set=root
linux  /vmlinuz-lts root=LABEL=sentry-root rootfstype=ext4 rw \
       console=tty0 console=ttyS0,115200 sentry.boot=usb
initrd /initramfs-lts
```

`grub.cfg` (installed mode, lives in `/EFI/sentry/grub.cfg`):
```
# Loaded by the firmware via /EFI/sentry/BOOTX64.EFI.
# We are already on the ESP that contains us; no search needed.
set root='(hd0,gpt2)'                # placeholder, we use $prefix instead
set prefix=$prefix                   # GRUB sets this to /EFI/sentry
linux  $prefix/vmlinuz \
       console=tty0 console=ttyS0,115200 \
       rdinit=/sbin/init sentry.boot=installed
initrd $prefix/initramfs
```

The kernel cmdline `sentry.boot=installed` is read by sentry-init via
`/proc/cmdline` to *confirm* the mode detection.

## What sentry-init does differently in installed mode

| Step | USB mode | Installed mode |
|------|----------|----------------|
| Mount boot config | `mount -L SENTRYBOOT /boot/cfg` | discover host ESP containing `/EFI/sentry/`, mount that. |
| Mount state | `mount -L sentry-state /var/lib/sentry` | `mkdir -p /boot/cfg/logs && ln -s /boot/cfg/logs /var/lib/sentry/logs` |
| Bind /var/log | `mount --bind /var/lib/sentry/logs/current/var-log /var/log` | `mount --bind /boot/cfg/logs/current/var-log /var/log` |
| Persist host keys | to `/var/lib/sentry/ssh-host-keys/` (ext4) | to `/boot/cfg/ssh-host-keys/` (FAT). Copy to `/etc/ssh/` (tmpfs) and chmod there. |
| STATUS.TXT | `/boot/cfg/STATUS.TXT` (FAT) | `/boot/cfg/STATUS.TXT` (FAT) — same code path |
| excluded_devices | auto-add USB device | auto-add the disk holding the host ESP (= the boot drive). The operator can still write to data disks via sentry-exec; the boot drive is sacred. |

## Acceptance test for M4

After sentry-install completes and the host has rebooted:

1. Power on, no USB inserted.
2. Press F12 (or vendor equivalent).
3. Boot menu lists "Sentry rescue (DO NOT CHANGE)" and the normal
   TrueNAS entry. The rescue is not the default.
4. Select rescue. Kernel boots within ~10 s.
5. tty1 shows IP, fingerprint, banner — same content as USB mode.
6. SSH from laptop succeeds with same key.
7. Inside the SSH session:
   * `cat /etc/sentry/auth.level` → `scanning`
   * `lsblk` shows the host's drives.
   * `/proc/cmdline` includes `sentry.boot=installed`.
   * `/var/lib/sentry/logs/current/` exists and has `boot.log` etc.
8. `sudo reboot` brings TrueNAS back up normally on the next boot
   (because the rescue was not added to BootOrder).

## Acceptance for the dual-mode codebase

```
USB mode boot   → identical experience to current implementation
Installed boot  → all the above checks pass
Same code       → no fork in sentry-init, just mode-aware paths
```
