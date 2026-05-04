# sentry-stick

Bootable UEFI x86_64 USB image whose only job is to come up on the LAN
with a key-only SSH lifeline plus a full Linux rescue toolkit, and to
**record everything it does** to a persistent partition for after-the-fact
inspection.

> Status: blind first build. The intended workflow is:
> build → flash → boot on a real machine → bring USB back → read logs
> from `/var/lib/sentry/logs/` on the third partition → fix what broke.

This subdirectory is staged for extraction into its own repository once
the design stabilises. It does not depend on Sentinel's Rust source —
only on the engagement-YAML protocol vocabulary (id / name / scope /
authorization / network / ssh / audit).

## What you get on a successful boot

* Alpine 3.21 minimal rootfs on an ext4 partition.
* An SSH daemon on port 22 (configurable), key-only, no password,
  no root, single user `sentry`.
* The user `sentry` lands in either:
  * `/bin/bash` if `engagement.yaml` says `max_level: scanning`
  * `/usr/local/bin/sentry-rsh` (restricted, read-only) for `passive`.
* `sudo /sbin/sentry-exec <op> [args...]` is the only way to run
  privileged operations (mount, mkfs, parted, dd, cryptsetup, lvm,
  mdadm, grub-install, …). Every invocation is checked against
  `scope.allowed_devices` / `scope.excluded_devices` and against the
  current auth level, then logged.
* The boot device is **always** auto-added to `excluded_devices` —
  you cannot accidentally wipe the stick you booted from.
* `STATUS.TXT` is written to the FAT partition at every boot showing
  IP, SSH command, ed25519 fingerprint, auth level, and key count.
* tty1 displays the same banner.

## What gets logged

Everything below ends up under
`/var/lib/sentry/logs/<timestamp>-<bootid>/` on the ext4 state
partition. A symlink `/var/lib/sentry/logs/current` always points at
the active boot's directory.

| File | What |
|------|------|
| `boot.log`            | sentry-init's own narration (set -x trace) |
| `dmesg-live.log`      | live kernel ring buffer for the whole uptime |
| `snapshot-*.txt`      | one-shot snapshots: lspci, lsusb, lsblk, dmidecode, ip addr/route/link, ss, ps, lsmod, mounts, dmesg, apk-info, rc-status, /proc/cmdline, /etc/os-release |
| `exec.jsonl`          | every `sentry-exec` decision (allow + deny) |
| `boots.jsonl`         | one line per boot (parent dir) |
| `sessions/*.typescript` | full input/output of every interactive shell session |
| `sessions/*.history`  | timestamped bash history per session |
| `sessions/*.meta`     | session metadata (user, tty, ssh_conn, level) |
| `sudo.log`            | text sudo log |
| `sudo-io/<user>/...`  | full sudo I/O recording (replay with `sudoreplay`) |
| `var-log/`            | bind-mounted `/var/log` — sshd, syslog, cron, messages, auth.log |

## Layout produced on the USB

```
P1  ESP / FAT32          1 MiB  →   257 MiB     bootloader, kernel, initramfs,
                                                engagement.yaml, authorized_keys,
                                                STATUS.TXT (written each boot)
P2  ext4 sentry-root     257   →   1537 MiB     rootfs (mounted rw)
P3  ext4 sentry-state    1537  →   end          host SSH keys, all logs
```

GPT, partition labels stable across rebuilds. Filesystem labels
`SENTRYBOOT`, `sentry-root`, `sentry-state` — those are what GRUB and
sentry-init look for.

## Build

Inside an Alpine container with loop-device access:

```sh
docker run --rm --privileged \
    -v "$PWD":/work -w /work \
    alpine:3.21 sh -c \
    'apk add --no-cache bash parted dosfstools e2fsprogs grub grub-efi efibootmgr mtools rsync && \
     bash /work/sentry-stick/build.sh'
```

Output: `./usb.img` (~2 GiB).

## Flash

```sh
lsblk                                     # confirm device
sudo dd if=usb.img of=/dev/sdX bs=4M status=progress conv=fsync
sudo sync
```

## Configure (on any laptop after flashing)

The first partition mounts as `SENTRYBOOT` (FAT32). Edit:

* `authorized_keys` — paste your SSH pubkey
* `engagement.yaml` — scope, auth level, hostname, ssh port

Eject. Plug into the target. Boot from USB (BIOS/UEFI menu, F12/F2).
tty1 will show the IP and ed25519 fingerprint within ~30 s.

## QEMU smoke test

```sh
qemu-system-x86_64 \
    -bios /usr/share/OVMF/OVMF_CODE.fd \
    -drive format=raw,file=usb.img \
    -m 1G \
    -netdev user,id=n,hostfwd=tcp::2222-:22 \
    -device virtio-net,netdev=n

# elsewhere:
ssh -p 2222 sentry@localhost
```

## After bringing the USB back

Mount the third partition read-only on a host:

```sh
sudo mount -o ro /dev/disk/by-label/sentry-state /mnt/sentry
ls /mnt/sentry/logs/
cat /mnt/sentry/logs/current/boot.log
cat /mnt/sentry/logs/current/exec.jsonl | jq .
sudoreplay -d /mnt/sentry/logs/current/sudo-io <session-id>
cat /mnt/sentry/logs/current/sessions/sentry-*.typescript | less
```

## What's deliberately NOT in this MVP

Legacy BIOS · arm64 · Wi-Fi · reverse tunnel (Tailscale, autossh) ·
LUKS on P3 · auth levels above `scanning` · honeypot side-channel ·
overlayfs immutable rootfs · web dashboard · per-key user routing.

## File map

```
sentry-stick/
├── README.md                                this file
├── build.sh                                 image builder
├── packages.list                            apk packages
├── boot-overlay/                            files placed on P1 ESP
│   ├── grub.cfg
│   ├── engagement.yaml                      example, edit on stick
│   ├── authorized_keys                      placeholder, edit on stick
│   └── README.txt                           user-facing notes
└── rootfs-overlay/                          files copied into rootfs
    ├── etc/
    │   ├── init.d/sentry-init               OpenRC service
    │   ├── profile.d/sentry-record.sh       wrap shells with script(1)
    │   ├── ssh/sshd_config.template         rendered at boot
    │   └── sudoers.d/sentry                 NOPASSWD on sentry-exec only
    ├── sbin/
    │   ├── sentry-init                      boot-time orchestrator
    │   └── sentry-exec                      device/auth guard
    └── usr/local/bin/
        └── sentry-rsh                       passive read-only shell
```
