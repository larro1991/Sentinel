#!/usr/bin/env bash
# Full cross-system smoke test — run on Windows via Git Bash or from Proxmox
set -uo pipefail

AGENT="${BEDROCK_AGENT:-http://192.168.110.185:7800}"
BROKER="${BEDROCK_BROKER:-http://192.168.110.25:7700}"
PM="${BEDROCK_PM:-http://192.168.110.185:3000}"
PM_TOKEN="${BEDROCK_PM_TOKEN:-tZuGme-gu_8n3KMFg3kU-8EQPp2KaXZhmO0VbHJ2Rhs}"

PASS=0; FAIL=0

ok()   { echo "  [PASS] $1"; PASS=$((PASS+1)); }
fail() { echo "  [FAIL] $1"; FAIL=$((FAIL+1)); }
hdr()  { echo; echo "=== $1 ==="; }

check_http() {
    local label="$1" url="$2" expect="${3:-200}"
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "$url" 2>/dev/null; true)
    [ "$code" = "$expect" ] && ok "$label ($code)" || fail "$label (got $code, want $expect)"
}

check_contains() {
    local label="$1" url="$2" needle="$3"
    body=$(curl -s --max-time 8 "$url" 2>/dev/null || true)
    echo "$body" | grep -q "$needle" && ok "$label" || fail "$label (needle: $needle not in response)"
}

hdr "m2-agent endpoints"
check_http    "GET /health"  "$AGENT/health"
check_contains "health.ok=true"  "$AGENT/health"  '"ok":true'
check_http    "GET /info"   "$AGENT/info"

hdr "m2-agent shell"
result=$(curl -s --max-time 10 -X POST "$AGENT/shell" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"echo bedrock-ok"}')
echo "$result" | grep -q "bedrock-ok" && ok "shell echo" || fail "shell echo (got: $result)"

gpu_result=$(curl -s --max-time 10 -X POST "$AGENT/shell" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"nvidia-smi --query-gpu=name --format=csv,noheader"}')
[ -n "$(echo "$gpu_result" | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("stdout","").strip())')" ] \
  && ok "GPU nvidia-smi" || fail "GPU nvidia-smi (response: $gpu_result)"

hdr "UAI broker"
check_http    "GET /broker/agents"     "$BROKER/broker/agents"
check_contains "sentry-proxmox alive"  "$BROKER/broker/agents"  '"alive":true'

hdr "PM agent"
check_http "GET /health"             "$PM/health"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 \
  -H "Authorization: Bearer $PM_TOKEN" "$PM/api/program/status")
[ "$code" = "200" ] && ok "GET /api/program/status" || fail "GET /api/program/status ($code)"

hdr "Restart resilience"
enabled=$(curl -s --max-time 10 -X POST "$AGENT/shell" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"systemctl is-enabled m2-agent"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("stdout","").strip())' 2>/dev/null || true)
[ "$enabled" = "enabled" ] && ok "m2-agent systemctl enabled" || fail "m2-agent not enabled: $enabled"

containers=$(curl -s --max-time 10 -X POST "$AGENT/shell" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"docker ps -q | wc -l"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("stdout","0").strip())' 2>/dev/null || true)
[ "${containers:-0}" -ge 30 ] 2>/dev/null \
  && ok "container count $containers (≥30)" \
  || fail "container count too low: $containers"

ollama=$(curl -s --max-time 10 -X POST "$AGENT/shell" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"curl -s -o /dev/null -w \"%{http_code}\" http://localhost:11434/api/tags"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("stdout","").strip())' 2>/dev/null || true)
[ "$ollama" = "200" ] && ok "Ollama API responding" || fail "Ollama not responding (got: $ollama)"

hdr "PM memory"
lines=$(curl -s --max-time 10 -X POST "$AGENT/shell" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"cat /mnt/Main/appdata/pm-agent/pm_memory.md | wc -l"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("stdout","0").strip())' 2>/dev/null || true)
[ "${lines:-0}" -gt 5 ] 2>/dev/null \
  && ok "pm_memory.md populated ($lines lines)" \
  || fail "pm_memory.md missing or empty"

english=$(curl -s --max-time 10 -X POST "$AGENT/shell" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"grep -c \"ALWAYS respond in English\" /Main/appdata/pm-agent/pm_agent.py"}' \
  | python3 -c 'import sys,json; print(json.load(sys.stdin).get("stdout","0").strip())' 2>/dev/null || true)
[ "${english:-0}" -ge 1 ] 2>/dev/null \
  && ok "English-only instruction present" \
  || fail "English-only instruction MISSING"

echo
echo "======================================="
echo "  PASS: $PASS   FAIL: $FAIL"
echo "======================================="
[ "$FAIL" -eq 0 ]
