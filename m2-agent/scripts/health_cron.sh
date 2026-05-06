#!/usr/bin/env bash
# Scheduled health monitor — runs full_suite.sh, alerts Telegram on failure.
# Cron: */30 * * * * /usr/local/sbin/bedrock-health-cron.sh

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUITE="${SCRIPT_DIR}/full_suite.sh"
BOT_TOKEN="${TELEGRAM_BOT_TOKEN:?TELEGRAM_BOT_TOKEN env var required}"
CHAT_ID="${TELEGRAM_CHAT_ID:?TELEGRAM_CHAT_ID env var required}"
LOG="/var/log/bedrock-health.log"

tg_alert() {
    local msg="$1"
    curl -s --max-time 10 \
        -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
        -H "Content-Type: application/json" \
        -d "{\"chat_id\":\"${CHAT_ID}\",\"text\":\"${msg}\"}" \
        > /dev/null 2>&1
}

ts() { date '+%Y-%m-%d %H:%M:%S'; }

echo "$(ts) [HEALTH] starting run" >> "$LOG"

output=$(bash "$SUITE" 2>&1)
exit_code=$?

pass=$(echo "$output" | grep -c '\[PASS\]' || true)
fail=$(echo "$output" | grep -c '\[FAIL\]' || true)

echo "$(ts) [HEALTH] pass=$pass fail=$fail exit=$exit_code" >> "$LOG"

if [ "$exit_code" -ne 0 ] || [ "${fail:-0}" -gt 0 ]; then
    # Collect failing lines
    failures=$(echo "$output" | grep '\[FAIL\]' | head -10 | sed 's/^  //')
    msg="⚠ Proxmox health: ${fail} FAIL / $((pass+fail)) checks$(printf '\n')${failures}"
    tg_alert "$msg"
    echo "$(ts) [HEALTH] alert sent" >> "$LOG"
else
    echo "$(ts) [HEALTH] all ${pass} checks passed" >> "$LOG"
fi
