# Open questions

> Things I want your input on before continuing. None block the next
> code step (M3 implementation), but each one would change the shape
> of the answer if you have a strong preference.

## TrueNAS-specific

### Q1. ZFS kernel module on the rescue?

We can ship the OpenZFS userland (`zpool`, `zfs` commands) without the
kernel module. Without the kmod we can:

* enumerate ZFS pools and read pool metadata,
* see all member devices,
* read smartctl, hardware info, etc.

We **cannot**:

* `zpool import` any pool (which means we can't mount the TrueNAS root
  to fix configs from inside the rescue).

Adding the ZFS kmod requires either DKMS at build time (heavy) or
shipping a kernel built with ZFS. Three options:

| Option | Build complexity | Rescue capability | Image size impact |
|--------|------------------|--------------------|--------------------|
| (A) userland only | low | inspect, but not import | +5 MB |
| (B) DKMS in initramfs | high | full ZFS access | +50 MB |
| (C) skip ZFS entirely | none | no ZFS at all | 0 |

My recommendation: (A) for MVP. (B) for M6 if usage shows it's needed.
(C) only if we never plan to fix ZFS pools.

**Need from you:** A / B / C.

### Q2. Mirrored boot drives — install to both?

If TrueNAS is on a mirrored boot pool, both drives have an identical
ESP. We can install the rescue to both ESPs and create two EFI boot
entries. Costs: roughly 2× the install time. Benefit: rescue still
reachable if either drive becomes unbootable.

My recommendation: **yes by default, with a `--no-mirror` opt-out.**

**Need from you:** confirm yes/no.

### Q3. Should the installer touch TrueNAS's GRUB?

Two paths:

* (a) **EFI menu only.** Operator presses F12 to invoke the rescue.
  We never edit any TrueNAS file. Cleanest, survives TrueNAS upgrades.
* (b) **EFI menu + add an entry to TrueNAS's GRUB** so it appears in
  the GRUB boot environment list at every boot. More visible. But
  TrueNAS regenerates `grub.cfg` on every BE update, so the entry
  would need to be re-added (could be a script + cron, fragile).

My recommendation: **(a) only for MVP.** Document that (b) is on the
table but defer to M6.

**Need from you:** confirm (a) only.

## SSH access topology

### Q4. Reach beyond the LAN?

Right now the rescue listens on `0.0.0.0:22` and you reach it from
the same VLAN. If the server is in a remote rack and you want to SSH
in from elsewhere:

* (a) **Tailscale** — small daemon, runs on the rescue, connects to a
  pre-shared Tailnet. Works behind NAT. Adds a Go binary (~30 MB).
* (b) **Reverse SSH tunnel** to a fixed bastion host — uses our
  authorized_keys. ~0 MB extra.
* (c) **WireGuard** with a pre-shared peer config — built into modern
  kernels. ~5 MB.
* (d) **Just LAN.** Out-of-LAN reach is not a goal.

My recommendation: **(d) for MVP.** (a) or (c) for M6. Skip (b)
because the bastion becomes a single point of failure.

**Need from you:** confirm (d).

### Q5. Auto-failover (rescue boots automatically if main OS fails)?

UEFI doesn't support "boot N then fall back to M" natively, but you
can fake it: the rescue can be set as the primary boot, and the
rescue's first action is to chainload the host's main bootloader,
*unless* it sees a marker that says "main boot failed last time"
(written by an OS-level service or by failing N attempts).

This is genuinely useful for unattended servers but adds:

* Extra boot latency for the chainload path.
* A second piece of state on the ESP (the failure marker).
* Two more scripts: one to flip the boot marker, one to read it.

My recommendation: **defer to M6.** Manually-triggered F12 path is
fine for MVP and matches the "emergency access" framing.

**Need from you:** confirm defer.

## Workflow / UX

### Q6. Install from USB only, or also from inside TrueNAS?

A future variant: rather than booting USB to install, the operator
SSH-es into TrueNAS itself, runs `sentry-install` (which is a
container or static binary), and the install happens online. Avoids
the boot-from-USB step entirely.

Trade-offs: requires TrueNAS to be functional enough to install from,
which contradicts the "server is broken" use case. But for
*proactive* installs ("install rescue while TrueNAS is healthy so we
have it later"), this is the better UX.

My recommendation: **MVP is USB-only.** Online install is M6.

**Need from you:** confirm USB-only for now.

### Q7. Per-boot dirty marker + auto log rotation?

The rescue's logs grow forever. Each boot adds a directory with
~20 MB of snapshots and however much shell session activity. After
50 boots that's a gig.

Options:

* (a) Keep last N boots (default 30), `logrotate`-style.
* (b) Keep last N MiB total.
* (c) Don't rotate — let the operator manage.

My recommendation: **(a) keep 30 most recent boots,** plus prune any
single boot dir > 100 MB. Configurable in engagement.yaml.

**Need from you:** thumbs up or different number.

## Hardening / security

### Q8. LUKS on the rescue?

The rescue contains an authorized SSH key — the same key that lets
into the rescue. If someone steals the boot drive and reads the FAT
ESP, they get that public key (which is fine — it's a public key) and
the engagement YAML.

LUKS-encrypting the rescue payload means an attacker can read the
existence of `/EFI/sentry/` but not its contents. Costs: a passphrase
prompt at rescue boot time (or a TPM-sealed key, which is more work).

My recommendation: **no for MVP.** The threat model "an attacker has
physical access to the drive and is willing to clone it" is also a
threat to TrueNAS's own boot pool which is unencrypted.

**Need from you:** confirm no LUKS for MVP.

### Q9. Secure Boot?

If TrueNAS has Secure Boot enabled with vendor-only keys, our
unsigned `BOOTX64.EFI` won't load — firmware will refuse it. Two paths:

* (a) Document that Secure Boot must be off, and check at install
  time (`mokutil --sb-state` or `cat /sys/firmware/efi/efivars/SecureBoot-*`).
  Refuse to install if SB is on.
* (b) Ship signed shim + sign our binary against MOK (Machine Owner
  Key) — operator enrolls our key once, then SB stays on.

My recommendation: **(a) for MVP, with a clear pre-flight error
message.** (b) is M6.

**Need from you:** confirm (a).

## What I will assume if you don't reply

If you say "your call, keep moving," I'll proceed with the
recommendations above. They are all conservative MVP defaults; we
can revisit any of them later without rework that destroys data.

Summary of defaults if you punt:
* Q1: ZFS userland only.
* Q2: install to both mirror ESPs by default.
* Q3: F12-only (no TrueNAS GRUB touching).
* Q4: same-LAN only.
* Q5: no auto-failover.
* Q6: USB-only install.
* Q7: keep last 30 boot log dirs.
* Q8: no LUKS.
* Q9: Secure Boot must be off; install pre-flights this.
