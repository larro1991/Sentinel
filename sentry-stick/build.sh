#!/bin/bash
# Sentry-stick build script.
# Produces a UEFI x86_64 bootable USB image (usb.img) from:
#   - packages.list      (Alpine apk packages)
#   - rootfs-overlay/    (files copied into the rootfs)
#   - boot-overlay/      (files placed on the FAT boot partition)
#
# Run inside an Alpine container with --privileged (loop devices required):
#
#   docker run --rm --privileged \
#     -v "$PWD":/work -w /work \
#     alpine:3.21 sh -c \
#     'apk add --no-cache bash parted dosfstools e2fsprogs grub grub-efi efibootmgr mtools rsync && bash /work/sentry-stick/build.sh'
#
# Output:  ./usb.img      flash with: dd if=usb.img of=/dev/sdX bs=4M conv=fsync

set -euo pipefail

# --- knobs -------------------------------------------------------------------
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=${WORK:-$HERE}
OUT_IMG=${OUT_IMG:-$WORK/usb.img}
IMG_SIZE_MB=${IMG_SIZE_MB:-2048}
ROOT_PART_SIZE_MB=${ROOT_PART_SIZE_MB:-1280}
ESP_SIZE_MB=${ESP_SIZE_MB:-256}
ALPINE_VER=${ALPINE_VER:-3.21}
ALPINE_REPO_BASE=${ALPINE_REPO_BASE:-https://dl-cdn.alpinelinux.org/alpine}
BUILD_DIR=${BUILD_DIR:-/tmp/sentry-build-$$}

log()   { printf '\n==> %s\n' "$*"; }
info()  { printf '    %s\n' "$*"; }
fatal() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# --- 0. preflight ------------------------------------------------------------
log "Preflight"
[ "$(id -u)" -eq 0 ] || fatal "must run as root (need losetup, mount, chroot)"
for cmd in parted mkfs.vfat mkfs.ext4 grub-install losetup truncate apk chroot rsync; do
    command -v "$cmd" >/dev/null || fatal "missing host tool: $cmd"
done
[ -r "$WORK/packages.list" ]            || fatal "missing $WORK/packages.list"
[ -d "$WORK/rootfs-overlay" ]           || fatal "missing $WORK/rootfs-overlay/"
[ -d "$WORK/boot-overlay" ]             || fatal "missing $WORK/boot-overlay/"
[ -d /usr/lib/grub/x86_64-efi ]         || fatal "GRUB EFI modules missing — apk add grub-efi"

mkdir -p "$BUILD_DIR"
P1_MNT=$BUILD_DIR/p1
P2_MNT=$BUILD_DIR/p2
P3_MNT=$BUILD_DIR/p3
LOOP=""

cleanup() {
    set +e
    for m in "$P2_MNT/dev" "$P2_MNT/proc" "$P2_MNT/sys" "$P2_MNT/run" \
             "$P1_MNT" "$P3_MNT" "$P2_MNT"; do
        mountpoint -q "$m" 2>/dev/null && umount -lf "$m"
    done
    [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null
    info "(temp dir kept at $BUILD_DIR for inspection)"
}
trap cleanup EXIT

# --- 1. create sparse image and partition ------------------------------------
log "Creating $OUT_IMG (${IMG_SIZE_MB} MiB sparse)"
rm -f "$OUT_IMG"
truncate -s "${IMG_SIZE_MB}M" "$OUT_IMG"

P1_END=$((1 + ESP_SIZE_MB))
P2_END=$((P1_END + ROOT_PART_SIZE_MB))

log "Partitioning (GPT: ESP / sentry-root / sentry-state)"
parted -s "$OUT_IMG" -- \
    mklabel gpt \
    mkpart SENTRYBOOT  fat32  1MiB        ${P1_END}MiB \
    set 1 esp on \
    mkpart sentry-root ext4   ${P1_END}MiB ${P2_END}MiB \
    mkpart sentry-state ext4  ${P2_END}MiB 100%
parted -s "$OUT_IMG" print

# --- 2. loop-mount -----------------------------------------------------------
log "Attaching loop device"
LOOP=$(losetup --show -fP "$OUT_IMG")
info "Loop: $LOOP (partitions: ${LOOP}p1 ${LOOP}p2 ${LOOP}p3)"
sleep 1

# --- 3. format ---------------------------------------------------------------
log "Formatting partitions"
mkfs.vfat -F32 -n SENTRYBOOT  "${LOOP}p1"
mkfs.ext4 -F -L sentry-root   -O '^has_journal' "${LOOP}p2"  # smaller, fine for read-mostly
mkfs.ext4 -F -L sentry-state                    "${LOOP}p3"

# --- 4. mount rootfs target --------------------------------------------------
mkdir -p "$P1_MNT" "$P2_MNT" "$P3_MNT"
mount "${LOOP}p2" "$P2_MNT"
mount "${LOOP}p1" "$P1_MNT"

# --- 5. bootstrap Alpine into rootfs ----------------------------------------
log "Bootstrapping Alpine $ALPINE_VER into rootfs"
mkdir -p "$P2_MNT/etc/apk/keys" "$P2_MNT/etc/apk/cache"
echo "$ALPINE_REPO_BASE/v$ALPINE_VER/main"      >  "$P2_MNT/etc/apk/repositories"
echo "$ALPINE_REPO_BASE/v$ALPINE_VER/community" >> "$P2_MNT/etc/apk/repositories"
cp /etc/apk/keys/* "$P2_MNT/etc/apk/keys/"

PKGS=$(grep -vE '^\s*(#|$)' "$WORK/packages.list" | tr '\n' ' ')
info "Installing: $(echo "$PKGS" | wc -w) packages"
apk --root "$P2_MNT" --initdb --update-cache --no-progress add $PKGS

# --- 6. apply rootfs overlay -------------------------------------------------
log "Applying rootfs overlay"
rsync -a "$WORK/rootfs-overlay/" "$P2_MNT/"
chmod 0755 "$P2_MNT/sbin/sentry-init" \
           "$P2_MNT/sbin/sentry-exec" \
           "$P2_MNT/usr/local/bin/sentry-rsh" \
           "$P2_MNT/etc/init.d/sentry-init"
chmod 0440 "$P2_MNT/etc/sudoers.d/sentry"
chmod 0644 "$P2_MNT/etc/profile.d/sentry-record.sh"
chmod 0644 "$P2_MNT/etc/ssh/sshd_config.template"

# --- 7. configure inside chroot ---------------------------------------------
log "Configuring system in chroot"
mount --bind /dev  "$P2_MNT/dev"
mount --bind /proc "$P2_MNT/proc"
mount --bind /sys  "$P2_MNT/sys"
mkdir -p "$P2_MNT/run"; mount -t tmpfs tmpfs "$P2_MNT/run"

chroot "$P2_MNT" /bin/sh <<'CHROOT'
set -eux

# Default hostname, overwritten at boot.
echo sentry > /etc/hostname

# /etc/hosts
cat > /etc/hosts <<EOF
127.0.0.1   localhost localhost.localdomain
::1         localhost localhost.localdomain
EOF

# Disable Alpine's default lbu / diskless trickery — we're a real installed
# system on an ext4 partition.
true

# Initramfs features for booting from USB on modern hardware.
cat > /etc/mkinitfs/mkinitfs.conf <<EOF
features="ata base ide scsi usb virtio nvme mmc kms ext4 keymap"
EOF

# Generate the initramfs (mkinitfs reads /lib/modules/*).
KVER=$(ls /lib/modules | head -1)
mkinitfs -o /boot/initramfs-lts "$KVER"

# OpenRC runlevel wiring.
rc-update add devfs        sysinit
rc-update add dmesg        sysinit
rc-update add mdev         sysinit
rc-update add hwclock      boot
rc-update add modules      boot
rc-update add sysctl       boot
rc-update add hostname     boot
rc-update add bootmisc     boot
rc-update add syslog       boot
rc-update add sentry-init  boot
rc-update add sshd         default
rc-update add chronyd      default
rc-update add avahi-daemon default
rc-update add crond        default
rc-update add killprocs    shutdown
rc-update add savecache    shutdown
rc-update add mount-ro     shutdown

# Prevent the default networking service from racing with sentry-init's udhcpc.
# We do not add 'networking' to a runlevel.

# Enable wheel-group sudo (covered by /etc/sudoers.d/sentry).
true

# Lock root account; key-only sentry user is created at boot.
passwd -l root || true

# Pre-build /etc/sentry/passive-bin for the passive shell.
mkdir -p /etc/sentry/passive-bin
for cmd in ls cat less more head tail grep awk sed cut sort uniq wc tr \
           find file stat tree which whoami id pwd date uname hostname \
           env printenv echo true false test seq tee \
           lsblk blkid lscpu free df du dmesg journalctl smartctl \
           ip ss ps top htop dig host nslookup mtr tcpdump-passive \
           lspci lsusb dmidecode hdparm cat-version; do
    name=${cmd%%:*}
    real=${cmd#*:}
    [ "$name" = "$real" ] && real=$name
    target=$(command -v "$real" 2>/dev/null || true)
    [ -n "$target" ] && ln -sf "$target" "/etc/sentry/passive-bin/$name" || true
done

# Make sure /etc/profile sources /etc/profile.d/*.sh (Alpine's default does).
grep -q 'profile.d' /etc/profile || cat >> /etc/profile <<'EOF'
for _f in /etc/profile.d/*.sh; do [ -r "$_f" ] && . "$_f"; done; unset _f
EOF

# busybox udhcpc default script must be executable.
chmod +x /usr/share/udhcpc/default.script 2>/dev/null || true

# avahi: publish the system hostname (default config does this).
true

# Empty /etc/motd; we paint /etc/issue at boot.
: > /etc/motd
CHROOT

# --- 8. stage P1 (boot partition) -------------------------------------------
log "Staging boot partition"
cp -f "$P2_MNT/boot/vmlinuz-lts"   "$P1_MNT/vmlinuz-lts"
cp -f "$P2_MNT/boot/initramfs-lts" "$P1_MNT/initramfs-lts"

# Drop boot-overlay files (engagement.yaml, authorized_keys, README, grub.cfg)
rsync -a "$WORK/boot-overlay/" "$P1_MNT/"

# --- 9. install GRUB (UEFI, removable) --------------------------------------
log "Installing GRUB (x86_64-efi, removable)"
mkdir -p "$P1_MNT/EFI/BOOT" "$P1_MNT/grub"
grub-install \
    --target=x86_64-efi \
    --efi-directory="$P1_MNT" \
    --boot-directory="$P1_MNT" \
    --removable \
    --no-nvram \
    --modules="part_gpt fat ext2 search search_label normal linux echo configfile chain" \
    --recheck

# Override grub.cfg with ours (grub-install writes a stub).
cp -f "$WORK/boot-overlay/grub.cfg" "$P1_MNT/grub/grub.cfg"

# --- 10. cleanup -------------------------------------------------------------
log "Syncing and unmounting"
sync
umount "$P2_MNT/run"
umount "$P2_MNT/dev"
umount "$P2_MNT/proc"
umount "$P2_MNT/sys"
umount "$P1_MNT"
umount "$P2_MNT"
losetup -d "$LOOP"
LOOP=

log "Build complete: $OUT_IMG"
ls -lh "$OUT_IMG"

cat <<EOF

Next steps:

  # 1) Smoke-test in QEMU (UEFI) before flashing real hardware:
  qemu-system-x86_64 \\
      -bios /usr/share/OVMF/OVMF_CODE.fd \\
      -drive format=raw,file=$OUT_IMG \\
      -m 1G \\
      -netdev user,id=n,hostfwd=tcp::2222-:22 \\
      -device virtio-net,netdev=n
  # then from another terminal:
  ssh -p 2222 sentry@localhost

  # 2) Flash to a real USB stick (REPLACE sdX with your device):
  lsblk
  sudo dd if=$OUT_IMG of=/dev/sdX bs=4M status=progress conv=fsync
  sudo sync

  # 3) On the laptop, mount the FAT partition (SENTRYBOOT) and edit:
  #      authorized_keys      <- paste your SSH pubkey
  #      engagement.yaml      <- adjust scope / hostname / port
  #    Eject. Plug into target. Boot from USB.

EOF
