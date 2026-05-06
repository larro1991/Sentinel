#!/usr/bin/env bash
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Run as root." >&2
  exit 1
fi

id sentry &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin sentry

install -m 0755 m2-agent /usr/local/bin/m2-agent

SUDOERS_FILE=/etc/sudoers.d/m2-agent
printf 'sentry ALL=(ALL) NOPASSWD: /usr/sbin/efibootmgr, /sbin/reboot, /sbin/poweroff\n' > "$SUDOERS_FILE"
chmod 0440 "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE"

install -m 0644 m2-agent.service /etc/systemd/system/m2-agent.service

systemctl daemon-reload
systemctl enable --now m2-agent
