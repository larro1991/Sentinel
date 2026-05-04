# Decision log

Every locked-in decision and the reasoning. If you want to revisit
one, edit the row and add a note about why we changed.

## Architecture

| # | Decision | Why | Rejected alternatives |
|---|----------|-----|------------------------|
| A1 | Alpine Linux 3.21, x86_64 | Tiny, simple, OpenRC, well-documented build path; Sentinel inspiration is Rust but Alpine is a Rust-friendly host too | Debian-live (heavy), NixOS (learning tax), Buildroot (DIY everything), Yocto (industrial complexity) |
| A2 | UEFI x86_64 only for MVP | Almost all post-~2014 servers; defer BIOS + arm64 to phase 2 | Hybrid BIOS+UEFI image (more bootloader complexity for first cut) |
| A3 | ext4 root partition (USB), not squashfs | Stock Alpine initramfs supports ext4 out of the box; squashfs needs custom init hooks | squashfs (immutable but needs init plumbing); writable ext4 + later overlayfs |
| A4 | Engagement YAML mirrors Sentinel's schema verbatim, plus `scope.allowed_devices` / `excluded_devices` and an `install:` section | Reuses Sentinel's protocol vocabulary so a Sentinel-aware operator already knows the shape | Custom unrelated schema (loses the protocol alignment that motivated picking Sentinel) |
| A5 | Shell scripts (POSIX + bash), not Rust | User explicitly said "keep it simple, ship a demo" | Rust binary importing Sentinel's `config.rs`/`auth.rs` (cleaner long-term, slower MVP) |

## SSH access

| # | Decision | Why | Rejected |
|---|----------|-----|----------|
| B1 | Single `sentry` user, login shell determined by `authorization.max_level` | Maps the auth ladder onto something concrete without per-key user routing | Per-key user routing (more flexible, more state to manage) |
| B2 | Pre-baked authorized_keys on the FAT partition | User explicitly said "lax, we are testing" | First-boot enrollment, QR scan |
| B3 | Key-only auth, no password, no root login, single AllowUsers, LogLevel VERBOSE | Standard hardening; verbose log captures fingerprints used | Password auth (terrible for an SSH lifeline) |
| B4 | Same VLAN / DHCP only for MVP | Simplest reach; defer reverse tunnel / Tailscale to M6 | Mesh VPN (Tailscale, WireGuard); reverse SSH to a bastion |

## Privilege model

| # | Decision | Why | Rejected |
|---|----------|-----|----------|
| C1 | Two auth rungs implemented for MVP: `passive`, `scanning`. Higher rungs reserved | User said "start with shell mapping; ship a demo" | Implementing all five Sentinel rungs upfront |
| C2 | All privileged ops route through `sudo /sbin/sentry-exec <op>` — direct sudo of mount/mkfs/dd/parted/cryptsetup/lvm/mdadm is denied by sudoers | Single audit/policy chokepoint; trivially extensible | Per-binary sudoers entries (logging would scatter; policy would diverge) |
| C3 | `sentry-exec` enforces both auth-level **and** `/dev/*` device-scope; boot device is auto-added to `excluded_devices` so the operator cannot wipe the stick they booted from | Cheap, high-value safety; matches Sentinel's "scope" idea extended to block devices | Trust the operator (we are testing — but cheap to enforce) |
| C4 | Default posture toward host disks is **read-only** unless `max_level >= scanning` and disk is in `allowed_devices` | Belt and suspenders for "just want to look first" | Default-RW with manual ro flag (one slip and you wipe data) |

## Discoverability + persistence

| # | Decision | Why | Rejected |
|---|----------|-----|----------|
| D1 | At boot, paint IP + ed25519 fingerprint to tty1, write `STATUS.TXT` to the FAT partition, and announce mDNS | Three independent ways to find the box | One channel only |
| D2 | SSH host keys persist on P3 (USB) so client TOFU prompts only fire on first boot | Operator quality of life | Generate fresh keys every boot (annoying TOFU re-prompt) |
| D3 | Bind-mount `/var/log` to the persistent partition | sshd / auth.log / syslog persist with zero extra plumbing | Periodic log copy (lossy on crash) |

## Hidden-rescue install

| # | Decision | Why | Rejected |
|---|----------|-----|----------|
| E1 | "Hidden" = (a) discreet only for MVP — custom GPT type GUID + GPT attribute bits 60+62 + EFI entry kept out of `BootOrder` | User chose recommendation (a). LUKS + Secure Boot signed shim deferred to M6 | (b) encrypted (LUKS now), (c) steganographic |
| E2 | Boot integration = (a) firmware boot menu (F12) **and** (b) host's GRUB if detectable | Belt and suspenders. F12 always works; GRUB is convenience | One only |
| E3 | engagement.yaml + authorized_keys for installed rescue = copied from USB at install time | Whoever has the USB controls the rescue. Editable later via the ESP from any laptop | Generate new keys at install; prompt at install |
| E4 | Host filesystem support = Linux ext4 root for original plan; **revised to ESP-resident for TrueNAS Scale** (no host-fs touching at all) | TrueNAS Scale's boot drive is ZFS-claimed; carving a partition would require boot-pool destroy/recreate (= reinstall TrueNAS) | Touching ZFS (huge complexity, wrecks the appliance), or only-on-data-disk (pollutes user data drives) |
| E5 | Reversibility (`sentry-install --uninstall`) is a hard requirement for MVP | User confirmed. ESP-resident design makes this trivial: `rm -rf /EFI/sentry; efibootmgr -B <n>` | Optional / deferred |
| E6 | Shrink-existing-partition path is **not in MVP scope** under the ESP-resident design | We don't touch any filesystem on the host besides reading and writing files inside `/EFI/sentry/` on the ESP | Was being designed for ext4 hosts; mooted by E4 |
| E7 | Auto-uninstall on partial-install failure: **no**. Installer's own rollback handles failure; if rollback fails, the operator should diagnose, not the box | Better to leave a known-bad state visible than to silently delete it | Auto-cleanup on next boot |
| E8 | Install record is written to **both** the host ESP (`/EFI/sentry/install-record.json`) and the USB's P3 (`/var/lib/sentry/installs/<host-id>.json`) | The rescue knows about itself; a different USB can also uninstall the rescue without booting the rescue | One location only |
| E9 | Initramfs-with-embedded-rootfs (no separate rootfs partition) for the installed rescue | Avoids needing a new GPT partition, fits in the existing ESP, ~100-200 MB compressed = within typical free space | Separate rootfs partition (requires GPT modification) |

## Logging

| # | Decision | Why | Rejected |
|---|----------|-----|----------|
| F1 | Log everything with `set -x` from the very first line of `sentry-init` | User explicitly requested "no guessing what worked or didn't" | Selective logging |
| F2 | 16 system snapshots at every boot (lspci, lsusb, lsblk, dmidecode, ip addr/route/link, ss, ps, lsmod, mounts, dmesg, apk-info, rc-status, /proc/cmdline, /etc/os-release) | Diagnoses 90% of "why didn't it work?" without needing additional probes | On-demand (slower for the operator who's bringing the USB back) |
| F3 | Every interactive SSH session wrapped with `script(1)` for full input/output capture | Forensic-grade record of what the operator actually did | bash history only (loses output, loses TUI interactions) |
| F4 | sudo I/O recorded for replay with `sudoreplay` | Same — replay any sudo session step by step | sudo log only |
| F5 | Per-boot directory + symlink `current` → most recent | Easy to find the latest, easy to keep history | Single rolling log dir |

## Repo / process

| # | Decision | Why |
|---|----------|-----|
| G1 | Everything under `sentry-stick/` subdirectory of Sentinel; never touch Sentinel's source; never push to `master` | User wants this isolated as it will likely become its own project. Easy to extract via `git filter-repo` later |
| G2 | Branch: `claude/bootable-ssh-thumbdrive-B6mYB` | Feature branch; pre-existing |
| G3 | Plans live in `sentry-stick/docs/` so they survive context loss and can be read/edited from any machine | User explicitly requested |
