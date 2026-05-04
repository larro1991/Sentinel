# sentry-stick — overview

A bootable USB image plus, eventually, an installer that lays down the
same SSH-rescue capability **on a target server's existing boot drive**
so emergency access remains possible even when the server's main OS
fails.

This document is the entry point. The detailed design lives alongside
in this `docs/` folder.

## Use case (locked)

> Target server: TrueNAS Scale (Debian-based, ZFS boot pool, x86_64
> UEFI). The operator boots the USB to install a *hidden* rescue
> capability on the server's existing boot drive. If the server's main
> OS later fails to boot or becomes unreachable, the operator selects a
> non-default firmware boot entry to drop into the rescue, SSH-es in,
> and repairs the server.

## End-to-end flow

```
1. Build         build.sh inside an Alpine container         →  usb.img
2. Flash         dd usb.img → real USB stick
3. Configure     edit engagement.yaml + authorized_keys on the USB
4. Boot 1st time plug into TrueNAS server, boot from USB
5. SSH in        ssh sentry@<ip>
6. Install       sudo sentry-install                          →  rescue lives on host ESP
7. Reboot        host's main OS still boots normally
8. (later) emergency:  F12 at boot → "Sentry rescue" → SSH    →  same lifeline, no USB
9. Uninstall     sudo sentry-install --uninstall              →  fully reversible
```

## Milestones

| ID | Title | Status |
|----|-------|--------|
| M1 | USB builds and boots; SSH lands on a shell                            | ✅ code written, ⬜ untested on hardware |
| M2 | Define rescue layout on TrueNAS Scale                                  | ✅ designed (see 02-truenas-scale.md, 03-installer-design.md) |
| M3 | `sentry-install` — ESP-resident installer, fully reversible            | ⬜ designed, ⬜ not coded |
| M4 | Rescue-mode boot parity — same sshd, same logging, same auth model     | ⬜ designed, ⬜ not coded |
| M5 | Real-hardware shakedown + log analysis loop                            | ⬜ blocked on M1+M3 + USB returning |
| M6 | Hardening (LUKS, Secure Boot signed shim, TrueNAS BE integration, mesh VPN, auto-failover) | ⬜ deferred |

## Doc index

| File | What it covers |
|------|----------------|
| [`00-overview.md`](00-overview.md)              | this file |
| [`01-decisions.md`](01-decisions.md)            | locked decisions + rejected alternatives |
| [`02-truenas-scale.md`](02-truenas-scale.md)    | what changes because the target is TrueNAS Scale |
| [`03-installer-design.md`](03-installer-design.md) | `sentry-install` step-by-step, including rollback |
| [`04-rescue-boot-parity.md`](04-rescue-boot-parity.md) | how the installed rescue differs from the USB |
| [`05-test-plan.md`](05-test-plan.md)            | what to look for in the logs you bring back |
| [`06-open-questions.md`](06-open-questions.md)  | what I still need from you to keep going |

## Code state today (commit `0001e6c`)

```
sentry-stick/
├── build.sh                                     produces usb.img (Alpine 3.21, UEFI x86_64)
├── packages.list                                64 apk packages
├── boot-overlay/                                files placed on the FAT32 partition
│   ├── grub.cfg                                 USB boot menu
│   ├── engagement.yaml                          example config
│   ├── authorized_keys                          placeholder
│   └── README.txt                               user-facing notes
└── rootfs-overlay/                              files copied into the rootfs
    ├── etc/init.d/sentry-init                   OpenRC service
    ├── etc/profile.d/sentry-record.sh           wraps shells with script(1) for full I/O recording
    ├── etc/ssh/sshd_config.template             rendered at boot
    ├── etc/sudoers.d/sentry                     NOPASSWD on sentry-exec only, sudo I/O logging
    ├── sbin/sentry-init                         boot-time orchestrator (~430 lines, set -x throughout)
    ├── sbin/sentry-exec                         device/auth guard, JSONL audit
    └── usr/local/bin/sentry-rsh                 passive read-only shell
```

## What "everything is logged" means in practice

Per boot, on the `sentry-state` ext4 partition (USB) or in
`/EFI/sentry/logs/` (installed rescue):

```
<bootid>/
├── boot.log                set -x trace of sentry-init
├── boots.jsonl             one JSON line per boot (parent dir)
├── exec.jsonl              every sentry-exec decision (allow + deny)
├── dmesg-live.log          live kernel ring buffer for the whole uptime
├── snapshot-lspci.txt      one of 16 system snapshots taken at boot
├── snapshot-lsblk.txt      ...
├── snapshot-ip-addr.txt
├── snapshot-listening.txt
├── snapshot-dmidecode.txt
├── snapshot-rc-status.txt
├── snapshot-...
├── sessions/
│   ├── sentry-<ts>-<pid>.typescript    full I/O of every interactive shell
│   ├── sentry-<ts>-<pid>.history       timestamped bash history
│   └── sentry-<ts>-<pid>.meta          session metadata
├── sudo.log                text sudo log
├── sudo-io/<user>/...      replayable sudo I/O (sudoreplay)
└── var-log/                bind-mounted /var/log (sshd, auth.log, syslog)
```

If `sentry-init` itself fails, the trap copies what it has so far to
the persistent partition and paints the failure on tty1 with the last
40 lines of the boot log.
