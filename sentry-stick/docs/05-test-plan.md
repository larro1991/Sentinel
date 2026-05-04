# M5 — test plan + log diagnostic checklist

> When you bring the USB back, this is what I'll go through, in order.
> The intent is that you don't need to interpret anything; just bring
> the USB and we work from the logs.

## What to do with the USB before bringing it to me

1. **Don't write to it.** No need to mount it on a laptop first.
2. If you have multiple USB sticks (one for each test boot), label them
   so we know which is which.
3. If you took photos of the screen during boot (e.g. the tty1 banner
   or a kernel panic), bring those too.

## What I look at

### Tier 1 — did the kernel boot at all?

Mount the third partition read-only:
```
mount -o ro /dev/disk/by-label/sentry-state /mnt/sentry
ls /mnt/sentry/logs/
```

Outcomes:

| Observation | Interpretation |
|------|----------------|
| `/mnt/sentry/logs/` exists and has ≥ one boot directory | kernel booted, sentry-init ran. Proceed to Tier 2. |
| `/mnt/sentry/` exists but `logs/` is empty | sentry-init never ran or crashed before the log dir was created. The early log lives in tmpfs and was lost. Look at the FAT partition's `STATUS.TXT` — was it updated? |
| `/mnt/sentry/` is unmountable / blkid sees no `sentry-state` label | P3 was not formatted, or partition table wrong. Re-check `parted -l` of the USB on a host. |
| The USB does not appear in `lsblk` at all | Flash failed; reflash with `dd ... conv=fsync`. |

### Tier 2 — what does boot.log say?

```
ls -la /mnt/sentry/logs/
cat /mnt/sentry/logs/current/boot.log
```

Walk it numbered-step by numbered-step:

| sentry-init step | `boot.log` line(s) | What "good" looks like |
|---|---|---|
| `[1] mounting boot partition` | `mount -t vfat ...` | no fail_soft warnings about SENTRYBOOT |
| `[1] mounting state partition` | `mount -t ext4 ...` | did not fall back to tmpfs |
| `[2] boot partition=...` | non-empty values | `BOOT_DEV` resolves to a real device |
| `[3] config: id=...` | reflects `engagement.yaml` values | not the built-in defaults (which mean YAML was unreadable) |
| `[4] writing scope env` | `/etc/sentry/{allowed,excluded}_devices` populated | boot device is in excluded_devices |
| `[6] preparing SSH host keys` | either "restoring" or "generating fresh" | `ssh-keygen` returned 0; fingerprint printed |
| `[7] rendering sshd_config` | sed completes | `/etc/ssh/sshd_config` exists and contains the port we configured |
| `[8] configuring sentry user` | adduser, key install | `installed N authorized key(s)` where N > 0 |
| `[9] bringing up eth0` | `udhcpc` returns success | "lease of <ip> obtained" appears; final IP is non-empty |
| `[10] snapshotting state` | 16 snap calls | `snapshot-*.txt` files appear in log dir |
| `[11] writing STATUS.TXT` | `mount -o remount,rw` succeeds | STATUS.TXT exists on FAT |
| `[done]` line at end | `[done] sentry-init OK ip=X fp=Y level=Z keys=N` | this is the success indicator |

If we see a step start but never finish, that step is the failure point.

### Tier 3 — snapshots tell us about hardware

Look in `/mnt/sentry/logs/current/`:

| File | What it shows |
|------|---------------|
| `snapshot-cmdline.txt` | what GRUB passed to the kernel — verifies grub.cfg actually loaded |
| `snapshot-os-release.txt` | `Alpine Linux 3.21` confirms our rootfs booted |
| `snapshot-lspci.txt` | every PCI device including the NIC (search for "Ethernet controller") |
| `snapshot-lsusb.txt` | USB devices including the boot stick |
| `snapshot-lsblk.txt` | every block device; we expect the USB and the host's TrueNAS drives |
| `snapshot-dmidecode.txt` | server make/model/BIOS — useful for known-issue lookup |
| `snapshot-ip-link.txt` | network interfaces present |
| `snapshot-ip-addr.txt` | IPs assigned (this is what tty1 prints from) |
| `snapshot-ip-route.txt` | default gateway present? |
| `snapshot-listening.txt` | confirms `:22` is bound |
| `snapshot-mounts.txt` | every mount including our P1/P2/P3 |
| `snapshot-modules.txt` | loaded kernel modules — diagnoses missing NIC driver |
| `snapshot-rc-status.txt` | every OpenRC service and its state |
| `snapshot-dmesg.txt` | one-shot kernel messages from the boot |
| `snapshot-apk-info.txt` | package list verification |
| `snapshot-ps.txt` | process tree at end of init |

### Tier 4 — did anyone SSH in?

```
ls /mnt/sentry/logs/current/sessions/
cat /mnt/sentry/logs/current/sessions/sentry-*.meta
cat /mnt/sentry/logs/current/sessions/sentry-*.history
less /mnt/sentry/logs/current/sessions/sentry-*.typescript
```

* `.meta`       — when, from where (SSH_CONNECTION), tty.
* `.history`    — timestamped command list.
* `.typescript` — full input/output recording. Use `less -R` to render colours.

### Tier 5 — sudo / sentry-exec activity

```
cat /mnt/sentry/logs/current/sudo.log
cat /mnt/sentry/logs/current/exec.jsonl | jq .
ls /mnt/sentry/logs/current/sudo-io/sentry/
```

* `sudo.log`         — text log of every sudo invocation (success + denial).
* `exec.jsonl`       — one JSON line per sentry-exec call: timestamp, decision, reason, op, args, level. Search for `"decision":"deny"` to see refused operations.
* `sudo-io/sentry/*` — replayable I/O. From the build host:
  ```
  sudoreplay -d /mnt/sentry/logs/current/sudo-io <session-id>
  ```

### Tier 6 — sshd / system logs

```
ls /mnt/sentry/logs/current/var-log/
cat /mnt/sentry/logs/current/var-log/messages
cat /mnt/sentry/logs/current/var-log/auth.log
```

* `messages` is busybox-syslog's catch-all.
* `auth.log` is sshd's auth records (since sshd is configured with
  `LogLevel VERBOSE`, every key fingerprint used and every PTY
  allocation is logged).

### Tier 7 — kernel ring buffer (live)

`dmesg-live.log` is appended to for the entire uptime. Useful for:
* Late-arriving USB devices (operator inserted something after boot).
* Disk errors during operations.
* Network link state changes.
* Out-of-memory events.

## Common failure patterns and what they look like

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| No log dir at all, no STATUS.TXT, server doesn't appear on network | Kernel didn't boot (firmware did not chainload our GRUB) or panicked early | Check tty1 photo. Look at `parted -l` of USB on host — partition table should be GPT with three partitions. Verify `BOOTX64.EFI` exists at `/EFI/BOOT/`. May need to flip Secure Boot off. |
| `boot.log` exists but stops at `[1]` mount fails | FAT or ext4 partition didn't form correctly | `parted -l` on host. Re-flash. |
| `[3]` falls back to defaults | `engagement.yaml` malformed or absent | Look at the file on the FAT partition. `yq` parse fail typically means a YAML indent/quote issue. |
| `[6]` keeps regenerating host keys every boot | P3 mount is failing (state went to tmpfs) | Look at `[1]` for the warning line; check `dmesg` for ext4 errors. |
| `[8]` reports `installed 0 authorized key(s)` | `authorized_keys` empty or absent on FAT | Add a key on the FAT partition. |
| `[9]` udhcpc fails, no IP | NIC not detected, no link, no DHCP server | Check `snapshot-lspci.txt` for the NIC. If unrecognised, missing kernel module. Check `snapshot-ip-link.txt` for link state. |
| `[done]` shows success but you couldn't SSH | Network was up briefly but lost lease, or sshd didn't start | Look at `var-log/messages` for sshd, `var-log/auth.log` for the connection attempt. |
| You SSH'd in and got an error | Look at the most recent `.typescript` for what went wrong |

## What to send back if you want async help

Tar up the whole log dir of the most recent boot:

```
tar czf sentry-logs-<date>.tgz -C /mnt/sentry/logs current/
```

That is everything I need. Don't redact for IP addresses, MAC
addresses, or hostnames unless they are sensitive — they help
diagnose. If they are sensitive, redact via:

```
tar czf sentry-logs-<date>-redacted.tgz \
    --transform='s/[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+/X.X.X.X/g' \
    -C /mnt/sentry/logs current/
```
