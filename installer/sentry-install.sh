#!/bin/sh
# sentry-install.sh — M3 installer for m2-agent (embedded UAI bridge)
# Deploys m2-agent as a system service and optionally writes /EFI/Sentry/ to the host ESP.
#
# Usage:
#   ./sentry-install.sh --broker http://192.168.110.25:7700/broker/heartbeat [OPTIONS]
#   curl -sfL https://raw.githubusercontent.com/.../sentry-install.sh | sh -s -- --broker URL
#
# Options:
#   --broker URL       Full broker heartbeat URL (required)
#   --token TOKEN      Org token passed to agent (optional)
#   --name  NAME       Agent name (default: hostname)
#   --port  PORT       Local agent listen port (default: 7800)
#   --binary PATH      Use local binary instead of downloading
#   --efi              Also write /EFI/Sentry/ to host ESP
#   --uninstall        Remove agent service (and /EFI/Sentry/ if present)
#   --dry-run          Print plan, touch nothing

set -e

BINARY_URL_AMD64="https://github.com/larro1991/bedrock/releases/latest/download/m2-agent-linux-amd64"
BINARY_URL_ARM64="https://github.com/larro1991/bedrock/releases/latest/download/m2-agent-linux-arm64"
INSTALL_BIN="/usr/local/bin/m2-agent"
SERVICE_NAME="m2-agent"
SERVICE_FILE="/etc/systemd/system/m2-agent.service"
OPENRC_FILE="/etc/init.d/m2-agent"
EFI_DIR="/EFI/Sentry"

BROKER_URL=""
ORG_TOKEN=""
AGENT_NAME=""
AGENT_PORT="7800"
LOCAL_BINARY=""
DO_EFI=0
UNINSTALL=0
DRY_RUN=0

# ── arg parse ────────────────────────────────────────────────────────────────
while [ $# -gt 0 ]; do
  case "$1" in
    --broker)  BROKER_URL="$2";    shift 2 ;;
    --token)   ORG_TOKEN="$2";     shift 2 ;;
    --name)    AGENT_NAME="$2";    shift 2 ;;
    --port)    AGENT_PORT="$2";    shift 2 ;;
    --binary)  LOCAL_BINARY="$2";  shift 2 ;;
    --efi)     DO_EFI=1;           shift   ;;
    --uninstall) UNINSTALL=1;      shift   ;;
    --dry-run) DRY_RUN=1;          shift   ;;
    *) echo "Unknown option: $1" >&2; exit 1 ;;
  esac
done

[ -z "$AGENT_NAME" ] && AGENT_NAME="$(hostname -s 2>/dev/null || echo unknown)"

# ── helpers ──────────────────────────────────────────────────────────────────
log()  { printf '[sentry] %s\n' "$*"; }
die()  { printf '[sentry] ERROR: %s\n' "$*" >&2; exit 1; }
run()  {
  if [ "$DRY_RUN" -eq 1 ]; then
    printf '[dry-run] %s\n' "$*"
  else
    eval "$@"
  fi
}

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Must run as root (sudo $0 $*)"
}

detect_init() {
  if command -v systemctl >/dev/null 2>&1 && systemctl is-system-running >/dev/null 2>&1; then
    echo systemd
  elif command -v rc-service >/dev/null 2>&1; then
    echo openrc
  else
    echo sysv
  fi
}

detect_arch() {
  MACHINE="$(uname -m)"
  case "$MACHINE" in
    x86_64)  echo amd64 ;;
    aarch64) echo arm64 ;;
    *) die "Unsupported architecture: $MACHINE" ;;
  esac
}

# ── uninstall ────────────────────────────────────────────────────────────────
do_uninstall() {
  INIT="$(detect_init)"
  log "Uninstalling m2-agent (init: $INIT)"

  case "$INIT" in
    systemd)
      if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        run systemctl stop "$SERVICE_NAME"
      fi
      if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        run systemctl disable "$SERVICE_NAME"
      fi
      run rm -f "$SERVICE_FILE"
      run systemctl daemon-reload
      ;;
    openrc)
      run rc-service "$SERVICE_NAME" stop 2>/dev/null || true
      run rc-update del "$SERVICE_NAME" default 2>/dev/null || true
      run rm -f "$OPENRC_FILE"
      ;;
  esac

  run rm -f "$INSTALL_BIN"
  log "Agent removed."

  # Remove /EFI/Sentry/ if present (find the mounted ESP)
  ESP_MOUNT="$(find_esp_mount)" || true
  if [ -n "$ESP_MOUNT" ] && [ -d "${ESP_MOUNT}${EFI_DIR}" ]; then
    log "Removing ${ESP_MOUNT}${EFI_DIR}"
    run mount -o remount,rw "$ESP_MOUNT" 2>/dev/null || true
    run rm -rf "${ESP_MOUNT}${EFI_DIR}"
    # Remove EFI boot entries labelled Sentry
    if command -v efibootmgr >/dev/null 2>&1; then
      efibootmgr -v | grep -i 'sentry' | awk -F'Boot' '{print $2}' | cut -c1-4 | while read BNUM; do
        [ -n "$BNUM" ] && run efibootmgr -B -b "$BNUM"
      done
    fi
  fi

  log "Uninstall complete."
}

# ── ESP helpers ───────────────────────────────────────────────────────────────
find_esp_device() {
  # Try lsblk first
  if command -v lsblk >/dev/null 2>&1; then
    lsblk -no NAME,PARTTYPE,FSTYPE 2>/dev/null \
      | awk '$2=="c12a7328-f81f-11d2-ba4b-00a0c93ec93b" || $3=="vfat" {print "/dev/"$1}' \
      | head -1
  fi
}

find_esp_mount() {
  # Check if ESP already mounted
  ESP_DEV="$(find_esp_device)"
  [ -z "$ESP_DEV" ] && return 1
  findmnt -n -o TARGET "$ESP_DEV" 2>/dev/null || echo ""
}

write_efi_sentry() {
  ESP_DEV="$(find_esp_device)"
  [ -z "$ESP_DEV" ] && die "Could not locate ESP device. Use a system with UEFI + GPT."

  ESP_MOUNT="/mnt/sentry-esp-$$"
  MOUNTED_EXTERNALLY=0

  EXISTING_MOUNT="$(findmnt -n -o TARGET "$ESP_DEV" 2>/dev/null || true)"
  if [ -n "$EXISTING_MOUNT" ]; then
    ESP_MOUNT="$EXISTING_MOUNT"
    MOUNTED_EXTERNALLY=1
  else
    run mkdir -p "$ESP_MOUNT"
    run mount -t vfat "$ESP_DEV" "$ESP_MOUNT"
  fi

  FREE_KIB="$(df -k "$ESP_MOUNT" | awk 'NR==2{print $4}')"
  FREE_MIB=$((FREE_KIB / 1024))
  log "ESP: $ESP_DEV mounted at $ESP_MOUNT (${FREE_MIB} MiB free)"
  [ "$FREE_MIB" -lt 5 ] && die "ESP has < 5 MiB free. Cannot write /EFI/Sentry/."

  SENTRY_EFI="${ESP_MOUNT}/EFI/Sentry"
  run mkdir -p "$SENTRY_EFI"

  # Write engagement stub (full payload goes here in M4)
  cat > /tmp/sentry-engagement-$$.yaml <<EOF
broker: ${BROKER_URL}
agent_name: ${AGENT_NAME}
org_token: ${ORG_TOKEN}
installed_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
  run cp /tmp/sentry-engagement-$$.yaml "${SENTRY_EFI}/engagement.yaml"
  rm -f /tmp/sentry-engagement-$$.yaml

  # Manifest placeholder — M4 adds kernel/initramfs here
  cat > /tmp/sentry-manifest-$$.json <<EOF
{
  "version": "m3",
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "agent_name": "${AGENT_NAME}",
  "note": "M4 will add vmlinuz + initramfs + grub.cfg to this directory"
}
EOF
  run cp /tmp/sentry-manifest-$$.json "${SENTRY_EFI}/manifest.json"
  rm -f /tmp/sentry-manifest-$$.json

  log "/EFI/Sentry/ written to $ESP_DEV"
  log "M4 will populate kernel + initramfs — EFI boot entry not created yet."

  if [ "$MOUNTED_EXTERNALLY" -eq 0 ]; then
    run umount "$ESP_MOUNT"
    run rmdir "$ESP_MOUNT"
  fi
}

# ── install ───────────────────────────────────────────────────────────────────
do_install() {
  [ -z "$BROKER_URL" ] && die "--broker URL is required"
  require_root

  INIT="$(detect_init)"
  ARCH="$(detect_arch)"
  log "Installing m2-agent on $(hostname) (arch: $ARCH, init: $INIT)"

  # Download or copy binary
  if [ -n "$LOCAL_BINARY" ]; then
    log "Using local binary: $LOCAL_BINARY"
    run cp "$LOCAL_BINARY" "$INSTALL_BIN"
  else
    case "$ARCH" in
      amd64) BINARY_URL="$BINARY_URL_AMD64" ;;
      arm64) BINARY_URL="$BINARY_URL_ARM64" ;;
    esac
    log "Downloading $BINARY_URL"
    if command -v curl >/dev/null 2>&1; then
      run curl -sfL -o "$INSTALL_BIN" "$BINARY_URL"
    elif command -v wget >/dev/null 2>&1; then
      run wget -qO "$INSTALL_BIN" "$BINARY_URL"
    else
      die "Need curl or wget to download binary. Use --binary PATH instead."
    fi
  fi

  run chmod 755 "$INSTALL_BIN"

  # Write service
  case "$INIT" in
    systemd)
      log "Writing $SERVICE_FILE"
      if [ "$DRY_RUN" -eq 0 ]; then
        cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=M2 Embedded Agent -- UAI broker bridge
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=${INSTALL_BIN}
Restart=always
RestartSec=10
Environment=M2_BROKER_URL=${BROKER_URL}
Environment=M2_AGENT_PORT=${AGENT_PORT}
Environment=M2_AGENT_NAME=${AGENT_NAME}
$([ -n "$ORG_TOKEN" ] && printf 'Environment=M2_ORG_TOKEN=%s\n' "$ORG_TOKEN")
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
      fi
      run systemctl daemon-reload
      run systemctl enable --now "$SERVICE_NAME"
      ;;
    openrc)
      log "Writing $OPENRC_FILE"
      if [ "$DRY_RUN" -eq 0 ]; then
        cat > "$OPENRC_FILE" <<EOF
#!/sbin/openrc-run
description="M2 Embedded Agent -- UAI broker bridge"
command="${INSTALL_BIN}"
command_background=true
pidfile="/run/m2-agent.pid"
export M2_BROKER_URL="${BROKER_URL}"
export M2_AGENT_PORT="${AGENT_PORT}"
export M2_AGENT_NAME="${AGENT_NAME}"
$([ -n "$ORG_TOKEN" ] && printf 'export M2_ORG_TOKEN="%s"\n' "$ORG_TOKEN")
depend() { need net; }
EOF
        chmod 755 "$OPENRC_FILE"
      fi
      run rc-update add "$SERVICE_NAME" default
      run rc-service "$SERVICE_NAME" start
      ;;
    *)
      die "Unsupported init system. Install binary manually at $INSTALL_BIN and configure startup."
      ;;
  esac

  log "m2-agent installed and started."
  log "  Broker:     $BROKER_URL"
  log "  Agent name: $AGENT_NAME"
  log "  Port:       $AGENT_PORT"
  log "  Binary:     $INSTALL_BIN"

  if [ "$DO_EFI" -eq 1 ]; then
    log ""
    log "Writing /EFI/Sentry/ to ESP..."
    write_efi_sentry
  fi

  log ""
  log "Done. Verify with: journalctl -u m2-agent -f"
}

# ── main ──────────────────────────────────────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
  require_root
  do_uninstall
else
  do_install
fi
