Sentry — bootable SSH lifeline
==============================

This partition is FAT32 so it mounts on Windows, macOS, and Linux. Edit
the two files below on any laptop, then unmount, plug into the target
machine, and boot it from USB (BIOS/UEFI menu, usually F12 or F2).

Files you edit:
  engagement.yaml    Scope, auth level, network, SSH settings.
  authorized_keys    SSH public keys allowed to log in (one per line).

File the box writes for you:
  STATUS.TXT         Refreshed every boot. Shows the current IP address,
                     SSH host key fingerprint, and auth level so you can
                     pull the stick out and read it before SSH-ing in.

  STATUS.TXT does not exist until the first successful boot.

Logs:
  Boot logs, shell session recordings, sudo logs, and sentry-exec audit
  trail are written to the third partition (sentry-state, ext4). They
  survive reboots. To inspect them on a laptop, mount that ext4 partition
  read-only.

Default credentials:
  None. SSH is key-only. Add your pubkey to authorized_keys before boot.
