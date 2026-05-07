#!/usr/bin/env python3
"""PM Agent — autonomous portfolio manager."""

import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
import zipfile
from datetime import date, datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

BURR_API    = os.environ.get("BURR_API",  "http://192.168.110.185:5079")
PROGRAM_FILE = os.environ.get("PM_PROGRAM", "/mnt/pm-data/program.md")
LOG_FILE    = os.environ.get("PM_LOG", "/mnt/pm-data/pm_agent.log")
STATE_FILE  = os.environ.get("PM_STATE", "/mnt/pm-data/pm_state.json")

AUDIT_FILE = os.environ.get("PM_AUDIT", "/mnt/pm-data/pm_audit.jsonl")

_DESTRUCTIVE_RE = re.compile(
    r'\b(delete|drop|rm|remove|wipe|format|truncate|purge|nuke|destroy'
    r'|rollback|revert|reset)\b'
    r'|\brm\s+-rf\b'
    r'|\bkill\s+all\b'
    r'|\bdrop\s+(table|database|db|volume)\b',
    re.IGNORECASE,
)

_PENDING_CONFIRMS: dict[str, dict] = {}
_PENDING_LOCK = threading.Lock()
_proactive_blocked: list = []
_BLOCKED_RE = re.compile(r'\[BLOCKED:\s*(.+?)\]', re.IGNORECASE | re.DOTALL)

LOCAL_OLLAMA_URL = os.environ.get("LOCAL_OLLAMA_URL", "http://192.168.110.185:11434")
PM_LOCAL_MODEL   = os.environ.get("PM_LOCAL_MODEL", "qwen2.5:14b")

_CODE_RE = re.compile(
    r'(write|create|generate|implement|build|script|debug|fix|refactor'
    r'|function|class|module|endpoint|sql|bash|python|powershell|javascript'
    r'|dockerfile|compose'
    r'|change|update|modify|edit|set|configure|enable|disable|restart|deploy'
    r'|install|remove|delete|add|rename)',
    re.IGNORECASE,
)

PM_HTTP_TOKEN = os.environ.get("PM_HTTP_TOKEN", "tZuGme-gu_8n3KMFg3kU-8EQPp2KaXZhmO0VbHJ2Rhs")
PM_HTTP_PORT  = int(os.environ.get("PM_HTTP_PORT", "3000"))

INFRA_STATIC = """
ALWAYS respond in English only. Never use any other language.

## Infrastructure Knowledge
You are running ON Proxmox VE 9.1 at 192.168.110.185 (migrated from TrueNAS 2026-05-06).
Docker commands work directly. You have access to nvidia-smi for GPU monitoring.
Owner: Larry. Location: Minneapolis MN CDT (UTC-5).

Hardware:
- Proxmox: AMD Ryzen 5 3600 (6c/12t), 62GB RAM, RTX 5060 Ti 16GB (CUDA 13.2)
- Desktop (larro-desktop): Intel i5-13400F, 32GB RAM, RTX 4060 8GB
- Storage: ZFS Main pool 31T (/Main), NVMe root 49G
- Ollama: qwen2.5:14b (9GB, preferred) + llama3:8b

Core services (container -> host port):
  emby              -> :8096/:8920   (media server)
  sonarr            -> :8989         (TV shows)
  radarr            -> :7878         (movies)
  bazarr            -> :6767         (subtitles, healthy)
  handbrake         -> :30089        (GPU encode, healthy)
  audiobookshelf    -> :30067        (audiobooks)
  kavita            -> :5000         (comics/manga, healthy)
  paperless-ngx     -> :8000         (documents, healthy)
  n8n               -> :5678         (automation)
  adguard           -> :3030         (DNS/ad-block)
  nginx-proxy-mgr   -> :80/:81/:443  (reverse proxy)
  wg-easy           -> :51821/:51820 (VPN, healthy)
  calibre-web       -> :8083         (ebooks)
  whisper-asr       -> :9000         (speech-to-text GPU, healthy)
  ollama            -> :11434        (local LLM, GPU)
  crucible          -> :8090         (MCP server, SSE)
  nullclaw          -> :5081         (Discord bot, healthy)
  pm-telegram       -> :3000         (THIS agent)
  ops-monitor       -> :5079         (health monitor, healthy)
  postgres-shared   -> :5432         (shared PostgreSQL)
  rustdesk-hbbr     -> :21117        (remote desktop relay)
  rustdesk-hbbs     -> :21115-21116

Automation pipeline (all healthy unless noted):
  media-intake:5077  audiobook-pipeline:5070  audiobook-automation:5057
  music-pipeline:5073  conversion-queue:5076  document-automation:5061
  emby-automation:5053  infra-dashboard:5090  media-organizer:5055
  media-intelligence:5075  notification-hub:5060  unified-controller:5080
  video-pipeline:5071  subtitle-automation-v2:5056  backup-agent:5078
  ai-load-balancer:5082  server-automation  smart-router

Paths: media=/mnt/Main/Media  appdata=/mnt/Main/appdata  services=/mnt/Main/services
Total running: 42 containers. Boot: sentry USB -> Proxmox -> ZFS -> Docker -> compose-stacks

ACTION CAPABILITY -- use [ACTION:cmd] to run commands inline.
Allowed prefixes:
  docker ps, docker logs, docker restart, docker inspect, docker stats, docker exec
  docker compose up, docker compose down (down requires YES/NO confirm)
  df -h, free -h, uptime, zpool status, nvidia-smi
  systemctl status, journalctl -u
  curl -s http://localhost, curl -s http://192.168.110.185

Example: "Checking Emby: [ACTION:docker ps --filter name=emby --format '{{.Names}}	{{.Status}}']"
## File Write Capability — MANDATORY FORMAT
CRITICAL: You have NO ABILITY to modify files directly. The ONLY mechanism is [WRITE:] tags.
NEVER say a file was changed/updated/fixed unless you emitted [WRITE:] in THIS response.
Claiming success without [WRITE:] is hallucination. The tag triggers a confirm gate Larry approves.

WRONG — NEVER do this (hallucination):
  "✓ Done. HandBrake stop_grace_period changed to 60s." (without [WRITE:])
  "I will change stop_grace_period to 60s. Proceed? YES/NO"

RIGHT — always do this (read file first, then emit full modified content):
  [ACTION:cat /mnt/services/handbrake/docker-compose.yml]
  ...then in same response after seeing the content...
  [WRITE:/mnt/services/handbrake/docker-compose.yml]
  ...full modified file content...
  [/WRITE]

Whitelisted paths (others blocked, escalate to Claude):
- /mnt/services/  (compose files — auto-restarts container after YES)
- /mnt/pm-data/pm_memory.md
- /mnt/scripts/

A .bak backup is created before every write. Compose files auto-restart on YES.
After execution, results are injected and you give a plain-English answer.
Escalate to Claude Code (tell Larry: 'needs Claude session') for: code changes, architecture decisions, root-cause debugging.
""".strip()

EXPECTED_CONTAINERS = {
    "adguard", "ai-load-balancer", "audiobook-automation", "audiobook-pipeline",
    "audiobookshelf", "backup-agent", "bazarr", "calibre-web",
    "conversion-queue", "crucible", "document-automation", "emby",
    "emby-automation", "handbrake", "infra-dashboard", "kavita",
    "media-intake", "media-intelligence", "media-organizer", "music-pipeline",
    "n8n", "nginx-proxy-manager", "notification-hub", "nullclaw",
    "ollama", "ops-monitor", "paperless-ngx", "paperless-pg",
    "paperless-redis", "pm-telegram", "postgres-shared", "radarr",
    "rustdesk-hbbr", "rustdesk-hbbs", "server-automation", "smart-router",
    "sonarr", "subtitle-automation-v2", "unified-controller",
    "video-pipeline", "wg-easy", "whisper-asr",
}

_CMD_WHITELIST = [
    "docker ps", "docker logs", "docker restart", "docker inspect",
    "docker stats", "docker exec", "docker compose up", "docker compose down",
    "df -h", "free -h", "uptime", "zpool status", "nvidia-smi",
    "systemctl status", "systemctl is-enabled", "systemctl is-active",
    "journalctl -u",
    "curl -s http://localhost", "curl -s http://192.168.110.185",
    "cat /Main/", "cat /mnt/services/", "cat /mnt/scripts/", "cat /etc/",
    "ls /Main/", "ls /mnt/services/", "ls /mnt/scripts/", "ls /etc/",
    "head /Main/", "tail /Main/", "head /mnt/", "tail /mnt/",
    "grep ",
    "ollama list", "ollama ps",
]

_ACTION_RE = re.compile(r'\[ACTION:([^\]]+)\]')
MEMORY_FILE = os.environ.get("PM_MEMORY_FILE", "/mnt/pm-data/pm_memory.md")

def _load_pm_memory() -> str:
    try:
        return open(MEMORY_FILE, encoding="utf-8").read().strip()
    except Exception:
        return ""

def _save_pm_memory(fact: str):
    try:
        with open(MEMORY_FILE, "a", encoding="utf-8") as f:
            f.write(f"\n- {fact.strip()}")
        log(f"[MEMORY] saved: {fact[:80]}")
    except Exception as e:
        log(f"[MEMORY] save failed: {e}", "WARN")

_REMEMBER_RE = re.compile(r'\[REMEMBER:\s*(.+?)\]', re.IGNORECASE | re.DOTALL)
_WRITE_WHITELIST = [
    "/mnt/services/",
    "/mnt/pm-data/pm_memory.md",
    "/mnt/scripts/",
]

_WRITE_RE = re.compile(r'\[WRITE:([^\]]+)\](.*?)\[/WRITE\]', re.IGNORECASE | re.DOTALL)

def _handle_write(path: str, content: str) -> str:
    path = path.strip()
    if not any(path.startswith(w) for w in _WRITE_WHITELIST):
        log(f"[WRITE] BLOCKED: {path}", "WARN")
        return f"[write blocked — {path} not in whitelist; ask Claude to make this change]"
    try:
        content = re.sub(r'^```[a-z]*\n?', '', content.strip())
        content = re.sub(r'\n?```$', '', content).strip() + "\n"
        if os.path.exists(path):
            shutil.copy2(path, path + ".bak")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(content)
        log(f"[WRITE] {len(content)}b → {path}")
        return f"[write ok: {path}]"
    except Exception as e:
        log(f"[WRITE] failed {path}: {e}", "WARN")
        return f"[write failed: {e}]"




def audit_log(entry_type: str, content: str, chat_id: str = "", extra: dict | None = None):
    """Append one audit entry to pm_audit.jsonl."""
    import hashlib
    record = {
        "ts":      datetime.utcnow().isoformat() + "Z",
        "type":    entry_type,
        "chat_id": chat_id,
        "content": content[:2000],
        "hash":    hashlib.sha256(content.encode()).hexdigest()[:16],
    }
    if extra:
        record.update(extra)
    try:
        with open(AUDIT_FILE, "a", encoding="utf-8") as af:
            af.write(json.dumps(record) + "\n")
    except Exception as e:
        log(f"[AUDIT] write failed: {e}", "WARN")


CONV_FILE   = os.environ.get("PM_CONV",  "/mnt/pm-data/pm_conversations.json")
LOG_MAX_KB  = 512
CONV_INJECT = 20

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID", "8626879596")

_CONV: dict[str, list[dict]] = {}
_CONV_LOCK = threading.Lock()


def _conv_load():
    global _CONV
    try:
        _CONV = json.loads(Path(CONV_FILE).read_text(encoding="utf-8"))
    except Exception:
        _CONV = {}


def _conv_save():
    try:
        Path(CONV_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(CONV_FILE).write_text(json.dumps(_CONV, indent=2), encoding="utf-8")
    except Exception:
        pass


def conv_add(chat_id: str, role: str, content: str):
    with _CONV_LOCK:
        _CONV.setdefault(chat_id, []).append({
            "role": role,
            "content": content,
            "ts": datetime.now().isoformat(),
        })
        _conv_save()


def conv_get(chat_id: str) -> list[dict]:
    with _CONV_LOCK:
        return list(_CONV.get(chat_id, []))


BURR_MACHINES = {"GamingPC": "burr-cab270e3014c843c"}

VERIFIABLE_BLOCKERS = [
    ("LAX", "DolphinTool", {"type": "process", "host": "GamingPC", "process": "DolphinTool.exe"}),
    ("LAX", "Dolphin.exe", {"type": "process", "host": "GamingPC", "process": "Dolphin.exe"}),
    ("INFRA", "Twingate", {"type": "docker_log", "container": "twingate-connector", "pattern": "State: Online", "clears_when": "found"}),
]

RESOURCE_CLAIMS = [
    ("LAX",    "n:\\launchbox\\games",            "read/write", "library"),
    ("LAX",    "c:\\launchbox",                   "read/write", "app"),
    ("LAX",    "f:\\launchbox",                   "read",       "Phase1-2 source"),
    ("LAX",    "f:\\launchbox",                   "write",      "Phase3 backup dest"),
    ("STREAM", "n:\\launchbox\\games",            "read",       "streaming source"),
    ("EMB",    "/mnt/main/appdata/ember",         "read/write", "source+data"),
    ("EMB",    "/mnt/main/appdata/ember/scripts", "read/write", "scripts"),
    ("PMA",    "/mnt/main/appdata/pm-agent",      "read/write", "agent source"),
    ("PMA",    "/mnt/main/appdata/ember/scripts", "read/write", "log+state"),
    ("INFRA",  "/mnt/main",                       "read/write", "TrueNAS pool"),
]


def log(msg: str, level: str = "INFO"):
    now  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{now}] [{level}] {msg}\n"
    sys.stdout.write(line)
    try:
        path = Path(LOG_FILE)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
        if path.stat().st_size > LOG_MAX_KB * 1024:
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
            path.write_text("".join(lines[-(len(lines) // 2):]), encoding="utf-8")
    except Exception:
        pass


def log_section(title: str):
    log("─" * 60)
    log(f"  {title}")
    log("─" * 60)


def load_state() -> dict:
    try:
        return json.loads(Path(STATE_FILE).read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_state(state: dict):
    try:
        Path(STATE_FILE).parent.mkdir(parents=True, exist_ok=True)
        Path(STATE_FILE).write_text(json.dumps(state, indent=2), encoding="utf-8")
    except Exception:
        pass


def ember_get(path: str) -> dict | None:
    try:
        r = subprocess.run(
            ["curl", "-s", f"{BURR_API}{path}"],
            capture_output=True, text=True, timeout=15
        )
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:
        return None


def ember_post(path: str, body: dict) -> dict | None:
    try:
        r = subprocess.run(
            ["curl", "-s", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", json.dumps(body),
             f"{BURR_API}{path}"],
            capture_output=True, text=True, timeout=15
        )
        return json.loads(r.stdout) if r.returncode == 0 else None
    except Exception:
        return None


def parse_program_md() -> dict:
    try:
        src = Path(PROGRAM_FILE).read_text(encoding="utf-8")
    except Exception as e:
        log(f"Cannot read program.md: {e}", "ERROR")
        return {"projects": [], "summary": {}}
    projects = []
    today = date.today()
    blocks = re.split(r"\n(?=### \[)", src)
    for block in blocks:
        m = re.match(r"### \[(\w+)\]\s+(.+)", block)
        if not m:
            continue
        pid = m.group(1)
        def field(name, b=block):
            fm = re.search(rf"\*\*{re.escape(name)}\*\*:\s*(.+)", b)
            return fm.group(1).strip() if fm else "—"
        status = field("Status")
        priority = field("Priority")
        phase = field("Phase")
        target_str = field("Target")
        last_active_str = field("Last Active")
        blocked_by = field("Blocked By")
        days_since_active = None
        if last_active_str and last_active_str != "—":
            try:
                la = date.fromisoformat(last_active_str)
                days_since_active = (today - la).days
            except Exception:
                pass
        days_until_target = None
        if target_str and target_str not in ("—", "Ongoing"):
            try:
                t = date.fromisoformat(target_str)
                days_until_target = (t - today).days
            except Exception:
                pass
        projects.append({
            "id": pid, "status": status, "priority": priority,
            "phase": phase, "target": target_str,
            "last_active": last_active_str, "blocked_by": blocked_by,
            "days_since_active": days_since_active,
            "days_until_target": days_until_target,
        })
    active = [p for p in projects if p["status"] == "Active"]
    summary = {
        "active_p1": sum(1 for p in active if p["priority"] == "P1"),
        "active_p2": sum(1 for p in active if p["priority"] == "P2"),
        "active_p3": sum(1 for p in active if p["priority"] == "P3"),
        "blocked": sum(1 for p in projects if p.get("blocked_by", "—") not in ("—", "", None)),
        "total": len(projects),
    }
    return {"projects": projects, "summary": summary}


def program_status() -> dict | None:
    try:
        return parse_program_md()
    except Exception as e:
        log(f"program_status error: {e}", "ERROR")
        return None


def update_program_field(project_id: str, field: str, value: str) -> dict | None:
    try:
        src = Path(PROGRAM_FILE).read_text(encoding="utf-8")
        pattern = rf"(### \[{re.escape(project_id)}\].*?)(?=\n### |\n---|\Z)"
        block_match = re.search(pattern, src, re.DOTALL)
        if not block_match:
            log(f"Project {project_id} not found in program.md", "WARN")
            return None
        old_block = block_match.group(1)
        field_pattern = rf"(\*\*{re.escape(field)}\*\*:\s*)(.+)"
        new_block = re.sub(field_pattern, rf"\g<1>{value}", old_block)
        if new_block == old_block:
            log(f"Field '{field}' not found in [{project_id}]", "WARN")
            return None
        new_src = src[:block_match.start()] + new_block + src[block_match.end():]
        Path(PROGRAM_FILE).write_text(new_src, encoding="utf-8")
        log(f"[{project_id}] {field} = {value!r}")
        return {"status": "updated", "project_id": project_id, "field": field, "value": value}
    except Exception as e:
        log(f"update_program_field error: {e}", "ERROR")
        return None


def tg_send_document(content: str, filename: str, chat_id: str = "") -> bool:
    cid = chat_id or TELEGRAM_CHAT_ID
    if not TELEGRAM_BOT_TOKEN or not cid:
        return False
    tmp = Path(f"/mnt/pm-data/{filename}")
    try:
        tmp.write_text(content, encoding="utf-8")
        r = subprocess.run(
            ["curl", "-s", "-X", "POST",
             "-F", f"chat_id={cid}",
             "-F", f"document=@{tmp}",
             "-F", f"caption={filename}",
             f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"],
            capture_output=True, text=True, timeout=20
        )
        return r.returncode == 0
    except Exception:
        return False
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def tg_send(text: str, chat_id: str = "") -> bool:
    cid = chat_id or TELEGRAM_CHAT_ID
    if not TELEGRAM_BOT_TOKEN or not cid:
        return False
    try:
        r = subprocess.run(
            ["curl", "-s", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", json.dumps({"chat_id": cid, "text": text}),
             f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"],
            capture_output=True, text=True, timeout=15
        )
        return r.returncode == 0
    except Exception:
        return False


def tg_poll(offset: int = 0) -> list[dict]:
    if not TELEGRAM_BOT_TOKEN:
        return []
    try:
        r = subprocess.run(
            ["curl", "-s",
             f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates?offset={offset}&timeout=25"],
            capture_output=True, text=True, timeout=35
        )
        if r.returncode != 0:
            log(f"[POLL] curl rc={r.returncode} stderr={r.stderr[:100]!r}", "WARN")
            return []
        if not r.stdout.strip():
            log("[POLL] empty response from Telegram", "WARN")
            return []
        data = json.loads(r.stdout)
        if not data.get("ok"):
            log(f"[POLL] Telegram error: {data.get('description','?')}", "WARN")
            return []
        results = data.get("result", [])
        if results:
            log(f"[POLL] {len(results)} updates received")
        return results
    except Exception as e:
        log(f"[POLL] exception: {e}", "WARN")
        return []


def tg_download_file_bytes(file_id: str) -> bytes | None:
    """Download a Telegram file by file_id, return raw bytes or None."""
    try:
        r = subprocess.run(
            ["curl", "-s",
             f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getFile?file_id={file_id}"],
            capture_output=True, text=True, timeout=15
        )
        if r.returncode != 0:
            log(f"[TG] getFile curl failed rc={r.returncode}", "WARN")
            return None
        data = json.loads(r.stdout)
        if not data.get("ok"):
            log(f"[TG] getFile not ok: {data.get('description', data)}", "WARN")
            return None
        file_path = data["result"]["file_path"]
        file_size = data["result"].get("file_size", "?")
        log(f"[TG] downloading {file_path} size={file_size}")
        r2 = subprocess.run(
            ["curl", "-s",
             f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"],
            capture_output=True, timeout=30
        )
        if r2.returncode != 0:
            log(f"[TG] file download failed rc={r2.returncode}", "WARN")
            return None
        return r2.stdout
    except Exception as e:
        log(f"[TG] tg_download_file_bytes exception: {e}", "WARN")
        return None


def extract_docx_text(raw: bytes) -> str | None:
    """Extract plain text from a .docx using stdlib zipfile + XML — no dependencies."""
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            with zf.open("word/document.xml") as f:
                tree = ET.parse(f)
        ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
        parts = []
        for para in tree.findall(".//w:p", ns):
            texts = [t.text or "" for t in para.findall(".//w:t", ns)]
            parts.append("".join(texts))
        return "\n".join(parts)
    except Exception as e:
        log(f"[TG] docx extraction failed: {e}", "WARN")
        return None



def extract_zip_text(raw: bytes) -> str | None:
    """List zip contents and extract readable text files (up to 8 KB each, 20 KB total)."""
    TEXT_EXTS = {".txt", ".md", ".csv", ".json", ".py", ".js", ".ts", ".log", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".xml", ".html"}
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            names = zf.namelist()
            parts = [f"Zip contains {len(names)} file(s):\n" + "\n".join(f"  {n}" for n in names[:50])]
            total = 0
            for name in names:
                ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
                if ext not in TEXT_EXTS:
                    continue
                info = zf.getinfo(name)
                if info.file_size > 200_000:
                    parts.append(f"\n[{name}] — too large ({info.file_size} bytes), skipped")
                    continue
                try:
                    data = zf.read(name)
                    text = data.decode("utf-8", errors="replace")[:8000]
                    parts.append(f"\n--- {name} ---\n{text}")
                    total += len(text)
                    if total >= 20000:
                        parts.append("\n[truncated — content limit reached]")
                        break
                except Exception as e:
                    parts.append(f"\n[{name}] read error: {e}")
        return "\n".join(parts)
    except Exception as e:
        log(f"[TG] zip extraction failed: {e}", "WARN")
        return None

def burr_exec(machine_id: str, cmd: str, timeout: int = 30) -> str | None:
    resp = ember_post(f"/burr/send/{machine_id}", {
        "command": "exec", "payload": {"cmd": cmd}, "timeout_seconds": timeout,
    })
    if not resp or not resp.get("queued"):
        return None
    command_id = resp.get("command_id")
    deadline   = time.time() + timeout
    while time.time() < deadline:
        time.sleep(5)
        detail = ember_get(f"/burr/machines/{machine_id}")
        if not detail:
            continue
        for c in detail.get("recent_commands", []):
            if c["id"] == command_id and c["status"] in ("success", "error"):
                return c.get("result_output", "")
    return None


def check_process_running(host: str, process: str) -> bool | None:
    machine_id = BURR_MACHINES.get(host)
    if not machine_id:
        log(f"No Burr machine registered for host '{host}'", "WARN")
        return None
    cmd    = f'tasklist /FI "IMAGENAME eq {process}" /NH 2>nul'
    output = burr_exec(machine_id, cmd, timeout=30)
    if output is None:
        log(f"Burr exec timed out for {host}:{process}", "WARN")
        return None
    return process.lower() in output.lower() and "no tasks" not in output.lower()


def check_docker_log(container: str, pattern: str) -> bool | None:
    try:
        r = subprocess.run(
            ["docker", "logs", container, "--tail", "20"],
            capture_output=True, text=True, timeout=15
        )
        output = r.stdout + r.stderr
        return pattern.lower() in output.lower()
    except Exception as e:
        log(f"check_docker_log({container}): {e}", "WARN")
        return None


def verify_blockers(projects: list, state: dict) -> list[dict]:
    actions = []
    for project in projects:
        pid        = project["id"]
        blocked_by = project.get("blocked_by", "—")
        if not blocked_by or blocked_by == "—":
            continue
        for proj_id, pattern, spec in VERIFIABLE_BLOCKERS:
            if proj_id != pid or pattern.lower() not in blocked_by.lower():
                continue
            state_key  = f"{pid}.blocker"
            last_check = state.get(state_key, {})
            last_ts    = last_check.get("verified_at", "")
            if last_check.get("result") == "running" and last_ts:
                try:
                    age = (datetime.now() - datetime.fromisoformat(last_ts)).total_seconds()
                    if age < 7200:
                        log(f"[{pid}] Blocker '{pattern}' — checked {int(age/60)}min ago, skip")
                        continue
                except Exception:
                    pass
            log(f"[{pid}] Verifying blocker: '{pattern}' on {spec['host']}")
            if spec["type"] == "process":
                running = check_process_running(spec["host"], spec["process"])
                state[state_key] = {
                    "verified_at": datetime.now().isoformat(),
                    "blocker_text": blocked_by,
                    "result": "running" if running else ("not_running" if running is False else "check_failed"),
                }
                if running is None:
                    log(f"[{pid}] Could not verify — Burr check failed", "WARN")
                elif running:
                    log(f"[{pid}] {spec['process']} still running — blocker stands")
                else:
                    log(f"[{pid}] {spec['process']} not running — clearing blocker")
                    result = update_program_field(pid, "Blocked By", "—")
                    if result and result.get("status") == "updated":
                        log(f"[{pid}] Blocked By cleared (was: {blocked_by})")
                        state[state_key]["cleared_at"] = date.today().isoformat()
                        actions.append({"project": pid, "action": "blocker_cleared", "was": blocked_by,
                                        "why": f"{spec['process']} not found on {spec['host']} via Burr exec"})
                    else:
                        log(f"[{pid}] Failed to clear blocker in program.md", "WARN")
            elif spec["type"] == "docker_log":
                found = check_docker_log(spec["container"], spec["pattern"])
                clears_when_found = spec.get("clears_when", "not_found") == "found"
                state[state_key] = {
                    "verified_at": datetime.now().isoformat(),
                    "blocker_text": blocked_by,
                    "result": "found" if found else ("not_found" if found is False else "check_failed"),
                }
                if found is None:
                    log(f"[{pid}] docker_log check failed for {spec['container']}", "WARN")
                elif found == clears_when_found:
                    log(f"[{pid}] '{spec['pattern']}' found in {spec['container']} logs — clearing blocker")
                    result = update_program_field(pid, "Blocked By", "—")
                    if result and result.get("status") == "updated":
                        log(f"[{pid}] Blocked By cleared (was: {blocked_by})")
                        state[state_key]["cleared_at"] = date.today().isoformat()
                        actions.append({"project": pid, "action": "blocker_cleared", "was": blocked_by,
                                        "why": f"'{spec['pattern']}' found in {spec['container']} logs"})
                    else:
                        log(f"[{pid}] Failed to clear blocker in program.md", "WARN")
                else:
                    log(f"[{pid}] '{spec['pattern']}' not found in {spec['container']} — blocker stands")
    return actions


def detect_resource_conflicts(projects: list) -> list[dict]:
    active_ids   = {p["id"] for p in projects if p.get("status") == "Active"}
    resource_map: dict[str, list[tuple]] = {}
    for pid, path, mode, phase in RESOURCE_CLAIMS:
        if pid not in active_ids:
            continue
        key = path.lower().rstrip("/\\")
        resource_map.setdefault(key, []).append((pid, mode, phase))
    findings = []
    for path, claims in resource_map.items():
        if len(claims) > 1:
            desc = ", ".join(f"{pid}({mode}|{phase})" for pid, mode, phase in claims)
            findings.append({"resource": path, "projects": [c[0] for c in claims],
                             "finding": f"Shared resource: {path}", "detail": desc})
    return findings


def analyze_projects(projects: list) -> list[dict]:
    findings = []
    for p in projects:
        pid        = p["id"]
        status     = p["status"]
        prio       = p["priority"]
        days_since = p.get("days_since_active")
        days_until_target = p.get("days_until_target")
        days_until_resume = p.get("days_until_resume")
        blocked_by = p.get("blocked_by", "—")
        if status == "On Hold":
            if days_until_resume is not None and 0 <= days_until_resume <= 3:
                findings.append({"level": "INFO", "project": pid,
                                 "finding": f"Coming off hold in {days_until_resume} day(s)",
                                 "why": f"Hold reason: {p.get('hold_reason', '—')}"})
            continue
        if status != "Active":
            continue
        if prio == "P1" and days_since is not None and days_since >= 3:
            findings.append({"level": "WARN", "project": pid,
                             "finding": f"P1 idle {days_since} days",
                             "why": f"Last active: {p['last_active']}. Blocked by: {blocked_by}"})
        if days_since is not None and days_since > 14:
            findings.append({"level": "WARN", "project": pid,
                             "finding": f"Stale — {days_since} days without activity",
                             "why": f"Active project, no session activity. Blocked by: {blocked_by}"})
        if days_until_target is not None and 0 <= days_until_target <= 7:
            findings.append({"level": "WARN", "project": pid,
                             "finding": f"Deadline in {days_until_target} day(s): {p['target']}",
                             "why": f"Phase: {p['phase']}"})
    return findings


HELP_TEXT = (
    "PM commands:\n"
    "  status   — portfolio overview\n"
    "  p1       — P1 projects\n"
    "  blocked  — blocked projects\n"
    "  upcoming — deadlines this week\n"
    "  [ID]     — project detail (ITG, CON, LAX, ...)\n"
    "  help     — this message\n"
    "  (send a file) — PM reads it and responds"
)


def fmt_status(data: dict) -> str:
    projects = data.get("projects", [])
    summary  = data.get("summary", {})
    findings = analyze_projects(projects)
    total    = sum(summary.get(k, 0) for k in ("active_p1", "active_p2", "active_p3"))
    lines = [
        f"PM Status — {datetime.now().strftime('%Y-%m-%d %H:%M')} CDT",
        f"Active: {total} | P1={summary.get('active_p1',0)} P2={summary.get('active_p2',0)} P3={summary.get('active_p3',0)}",
        f"Blocked: {summary.get('blocked', 0)}",
    ]
    if findings:
        lines.append("")
        for f in findings:
            lines.append(f"[{f['level']}] {f['project']}: {f['finding']}")
    else:
        lines.append("No warnings.")
    return "\n".join(lines)


def fmt_project(p: dict) -> str:
    lines = [
        f"[{p['id']}] Priority: {p['priority']}",
        f"Status: {p['status']}",
        f"Phase: {p.get('phase', '—')}",
    ]
    if p.get("target"):
        days   = p.get("days_until_target")
        suffix = f" ({days}d)" if days is not None else ""
        lines.append(f"Target: {p['target']}{suffix}")
    blocked  = p.get("blocked_by", "—")
    if blocked and blocked != "—":
        lines.append(f"Blocked: {blocked}")
    last     = p.get("last_active", "—")
    days_ago = p.get("days_since_active")
    suffix   = f" ({days_ago}d ago)" if days_ago is not None else ""
    lines.append(f"Last Active: {last}{suffix}")
    return "\n".join(lines)


def handle_tg_message(text: str, chat_id: str):
    cmd  = text.strip().lower()
    data = program_status()
    if not data:
        tg_send("Program register unavailable. Try again later.", chat_id)
        return
    projects = data.get("projects", [])

    if cmd in ("status", "s", "pm", ""):
        tg_send(fmt_status(data), chat_id)
    elif cmd == "p1":
        p1s = [p for p in projects if p.get("priority") == "P1" and p.get("status") == "Active"]
        tg_send("\n\n".join(fmt_project(p) for p in p1s) if p1s else "No active P1 projects.", chat_id)
    elif cmd == "blocked":
        bl = [p for p in projects if p.get("blocked_by", "—") not in ("—", "", None)]
        if not bl:
            tg_send("No blocked projects.", chat_id)
        else:
            lines = [f"[{p['id']}] {p['priority']} — {p.get('blocked_by','')}" for p in bl]
            tg_send(f"Blocked ({len(bl)}):\n" + "\n".join(lines), chat_id)
    elif cmd in ("upcoming", "deadlines"):
        up = [p for p in projects if p.get("days_until_target") is not None and 0 <= p["days_until_target"] <= 7]
        if not up:
            tg_send("No deadlines in next 7 days.", chat_id)
        else:
            lines = [f"[{p['id']}] {p['target']} ({p['days_until_target']}d)" for p in up]
            tg_send("Upcoming deadlines:\n" + "\n".join(lines), chat_id)
    elif cmd in ("help", "?"):
        tg_send(HELP_TEXT, chat_id)
    else:
        match = next((p for p in projects if p["id"].lower() == cmd), None)
        if match:
            tg_send(fmt_project(match), chat_id)
        elif text.strip().upper() in ("YES", "Y", "GO", "CONFIRM"):
            with _PENDING_LOCK:
                pending = _PENDING_CONFIRMS.pop(chat_id, None)
            if pending and (time.time() - pending["ts"]) < 300:
                if pending.get("type") == "write":
                    w_path = pending["path"]
                    w_content = pending["content"]
                    audit_log("write_approved", w_path, chat_id)
                    result = _handle_write(w_path, w_content)
                    tg_send(f"Written: {result}", chat_id)
                    if w_path.startswith("/mnt/services/") and "docker-compose" in w_path:
                        svc_dir = str(Path(w_path).parent)
                        r = subprocess.run(
                            ["docker", "compose", "-f", w_path, "up", "-d"],
                            capture_output=True, text=True, timeout=60
                        )
                        out = (r.stdout + r.stderr).strip()[:500]
                        tg_send(f"Restarted: {out or 'done'}", chat_id)
                else:
                    audit_log("confirm_approved", pending["task"], chat_id)
                    conv_add(chat_id, "user", pending["task"])
                    tg_send("Confirmed. On it.", chat_id)
                    threading.Thread(target=orchestrate, args=(pending["task"], chat_id), daemon=True).start()
            else:
                tg_send("Nothing pending to confirm (timed out or already handled).", chat_id)
        elif text.strip().upper() in ("NO", "N", "CANCEL", "ABORT"):
            with _PENDING_LOCK:
                had = _PENDING_CONFIRMS.pop(chat_id, None)
            if had:
                audit_log("confirm_cancelled", had["task"], chat_id)
                tg_send("Cancelled.", chat_id)
            else:
                tg_send("Nothing pending to cancel.", chat_id)
        else:
            m = _DESTRUCTIVE_RE.search(text)
            if m:
                audit_log("destructive_gate", text, chat_id, {"matched": m.group(0)})
                with _PENDING_LOCK:
                    _PENDING_CONFIRMS[chat_id] = {"task": text, "ts": time.time()}
                tg_send(
                    f"⚠️ Destructive keyword detected: `{m.group(0)}`\n\n"
                    f"Task: {text[:200]}\n\n"
                    "Reply YES to proceed or NO to cancel (60s timeout).",
                    chat_id,
                )
            else:
                conv_add(chat_id, "user", text)
                tg_send("On it. Will reply when done.", chat_id)
                threading.Thread(target=orchestrate, args=(text, chat_id), daemon=True).start()


def _call_ollama(messages: list[dict]) -> str | None:
    """Call local Ollama. Returns text or None on failure/timeout."""
    payload = json.dumps({
        "model": PM_LOCAL_MODEL,
        "messages": messages,
        "stream": False,
        "options": {"num_predict": 2048},
    })
    try:
        r = subprocess.run(
            ["curl", "-s", "--max-time", "60",
             "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", payload,
             f"{LOCAL_OLLAMA_URL}/api/chat"],
            capture_output=True, text=True, timeout=70,
        )
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout)
        text = data.get("message", {}).get("content", "").strip()
        return text or None
    except Exception as e:
        log(f"[OLLAMA] Failed: {e}", "WARN")
        return None


def build_infra_context() -> str:
    lines = ["## Live Container State"]
    running = set()
    unhealthy = []
    try:
        r = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0 and r.stdout.strip():
            for line in r.stdout.strip().split("\n"):
                parts = line.split("\t")
                name = parts[0].strip()
                status = parts[1].strip() if len(parts) > 1 else ""
                running.add(name)
                if "(unhealthy)" in status:
                    unhealthy.append(name)
                lines.append(f"  {line}")
        else:
            lines.append("  (unavailable)")
    except Exception as e:
        lines.append(f"  (error: {e})")
    missing = EXPECTED_CONTAINERS - running
    if missing:
        lines.append(f"MISSING (not running): {', '.join(sorted(missing))}")
    if unhealthy:
        lines.append(f"UNHEALTHY: {', '.join(sorted(unhealthy))}")
        for name in unhealthy:
            log(f"[INFRA] Auto-restarting unhealthy container: {name}", "WARN")
            try:
                subprocess.run(["docker", "restart", name], timeout=30, capture_output=True)
            except Exception as e:
                log(f"[INFRA] Failed to restart {name}: {e}", "WARN")
    try:
        r = subprocess.run(["df", "-h", "/mnt/Main"], capture_output=True, text=True, timeout=5)
        if r.returncode == 0:
            parts = r.stdout.strip().split("\n")
            if len(parts) > 1:
                lines.append(f"Disk: {parts[1].split()[-2]} used of {parts[1].split()[1]}")
    except Exception:
        pass
    return "\n".join(lines)


def _is_cmd_safe(cmd: str) -> bool:
    c = cmd.strip().lower()
    return any(c.startswith(p.lower()) for p in _CMD_WHITELIST)


def execute_pm_action(cmd: str) -> str:
    if not _is_cmd_safe(cmd):
        log(f"[ACTION] blocked: {cmd!r}", "WARN")
        return f"[blocked: command not permitted: {cmd!r}]"
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        out = (r.stdout + r.stderr).strip()
        log(f"[ACTION] ran: {cmd!r} rc={r.returncode} out={out[:80]!r}")
        return out[:2000] if out else "(no output)"
    except Exception as e:
        return f"(failed: {e})"


def process_action_tags(response: str, task: str, chat_id: str) -> str:
    matches = list(_ACTION_RE.finditer(response))
    if not matches:
        return response
    results = []
    for m in matches:
        cmd = m.group(1).strip()
        out = execute_pm_action(cmd)
        results.append(f"$ {cmd}\n{out}")
    results_block = "\n\n".join(results)
    followup = (
        f"Original task: {task}\n\n"
        f"Command results:\n{results_block}\n\n"
        "Complete the task using these results. "
        "If this is a file edit, emit [WRITE:path]full modified content[/WRITE]. "
        "If it is a status query, give a plain-English answer (1-2 sentences)."
    )
    return _generate(followup, chat_id)


def build_pm_context() -> str:
    data = program_status()
    if not data:
        return "PM context unavailable (program register unreadable)."
    projects = data.get("projects", [])
    today    = date.today().isoformat()
    lines = [
        f"# PM Context — {today}",
        "You are Larry's personal AI assistant and project manager.",
        "You can answer questions about his infrastructure, projects, services, and anything else he needs.",
        "ENVIRONMENT: PRODUCTION — all actions affect live systems, not staging.",
        "To send a file via Telegram, wrap content: [SEND_FILE:filename.py]<content>[/SEND_FILE]",
        "Always include logging in any scripts you generate (use Python logging module).",
        "SAFETY RULES:",
        "  1. Before any write/delete/deploy/config action: state what you will do and WHY in one sentence, then wait.",
        "  2. If the action is irreversible (delete, drop, wipe, rm -rf): explicitly say it is irreversible and ask for confirmation.",
        "  3. If uncertain whether action is reversible: ASK before proceeding.",
        "  4. Never assume a credential mismatch or environment error means you should delete anything.",
        "",
        INFRA_STATIC + "\n\n## PM Memory\n" + _load_pm_memory(),
        "",
        build_infra_context(),
        "",
        "## Active Projects",
    ]
    for p in (p for p in projects if p.get("status") == "Active"):
        blocked      = p.get("blocked_by", "—")
        blocked_note = f" [BLOCKED: {blocked}]" if blocked and blocked != "—" else ""
        days         = p.get("days_since_active")
        stale        = f" (idle {days}d)" if days and days > 3 else ""
        lines.append(
            f"- [{p['id']}] {p['priority']} | {p.get('phase','?')} | "
            f"Target: {p.get('target','—')}{stale}{blocked_note}"
        )
    on_hold = [p for p in projects if p.get("status") == "On Hold"]
    if on_hold:
        lines += ["", "## On Hold"]
        for p in on_hold:
            lines.append(f"- [{p['id']}] {p.get('hold_reason','—')}")
    lines += [
        "",
        "## Project ID Reference",
        "ITG=ITGlue Audit/MSP Toolkit (ConnectWise+ITGlue automation), CON=Conduit (MSP platform), "
        "LAX=LaunchBox/Arcade, EMB=EMBER (AI assistant), GK=GuildKeep (nonprofit CRM), "
        "INFRA=Infrastructure, PMA=PM Agent, STREAM=Game Streaming, DW=darkwatch",
    ]
    return "\n".join(lines)


_DIGEST_RE = re.compile(
    r'\b(digest|daily digest|what did i miss|catch me up|news today|news yesterday'
    r'|today.s news|yesterday.s news|what.s new today|missed (today|yesterday|this week))\b',
    re.IGNORECASE,
)
_DIGEST_DIR = Path(os.environ.get("DIGEST_DIR", "/mnt/Main/appdata/pm-agent/digests"))

def _inject_digest(task: str) -> str:
    """If task is asking about the daily digest, prepend the relevant file."""
    if not _DIGEST_RE.search(task):
        return ""
    lower = task.lower()
    if "yesterday" in lower:
        target = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    else:
        target = date.today().isoformat()
    path = _DIGEST_DIR / f"{target}.md"
    if path.exists():
        return f"\n\n[Daily Digest for {target}]\n{path.read_text('utf-8')[:6000]}\n"
    return f"\n\n[No digest found for {target}]\n"


def _generate(task: str, chat_id: str, voice: bool = False, image_b64: str | None = None) -> str:
    """AI generation — Ollama first (no image), Anthropic fallback. Shared by Telegram and HTTP."""
    context = build_pm_context()
    digest_ctx = _inject_digest(task)
    if digest_ctx:
        context += digest_ctx
    if voice:
        context += (
            "\n\nVOICE MODE: Reply in 1-2 plain sentences only. "
            "No markdown, no asterisks, no bullets, no headers, no formatting of any kind. "
            "Conversational tone. If the user wants more detail they will ask."
        )
    history = conv_get(chat_id)
    recent  = history[-(CONV_INJECT + 1):-1] if len(history) > 1 else []
    history_section = ""
    if recent:
        history_section = "\n\n## Recent Conversation\n"
        for msg in recent:
            role = "User" if msg["role"] == "user" else "PM"
            history_section += f"{role}: {msg['content']}\n"
    full_task = f"{context}{history_section}\n\n---\nUser: {task}"
    _used_model = "claude-sonnet-4-6"
    response = None
    if image_b64 is None and not _CODE_RE.search(task):
        log(f"[ORCH] Routing to local model ({PM_LOCAL_MODEL})")
        response = _call_ollama([{"role": "user", "content": full_task}])
        if response:
            log(f"[ORCH] Local OK ({len(response)} chars)")
            _used_model = PM_LOCAL_MODEL
        else:
            log("[ORCH] Local unavailable, falling back to Anthropic", "WARN")
    if response is None:
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        try:
            import tempfile, os as _os
            if image_b64 is not None:
                user_content = [
                    {"type": "image", "source": {
                        "type": "base64",
                        "media_type": "image/jpeg",
                        "data": image_b64,
                    }},
                    {"type": "text", "text": full_task},
                ]
            else:
                user_content = full_task
            payload = json.dumps({
                "model": "claude-sonnet-4-6",
                "max_tokens": 4096,
                "messages": [{"role": "user", "content": user_content}],
            })
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tf:
                tf.write(payload)
                tf_path = tf.name
            try:
                r = subprocess.run(
                    ["curl", "-s", "--max-time", "120", "-X", "POST",
                     "https://api.anthropic.com/v1/messages",
                     "-H", f"x-api-key: {api_key}",
                     "-H", "anthropic-version: 2023-06-01",
                     "-H", "content-type: application/json",
                     "-d", f"@{tf_path}"],
                    capture_output=True, text=True, timeout=130,
                )
            finally:
                _os.unlink(tf_path)
            if r.returncode == 0:
                data = json.loads(r.stdout)
                if data.get("type") == "error":
                    response = f"API error: {data.get('error', {}).get('message', r.stdout[:200])}"
                else:
                    response = data["content"][0]["text"]
            else:
                response = f"API call failed (rc={r.returncode}): {r.stderr[:200]}"
        except subprocess.TimeoutExpired:
            response = "Task timed out (2 min limit)."
        except Exception as e:
            response = f"Orchestration failed: {e}"
    log(f"[ORCH] Done ({_used_model}): {(response or '')[:100]!r}")
    if response and _ACTION_RE.search(response):
        log("[ORCH] Action tags found — executing")
        response = process_action_tags(response, task, chat_id)
        log(f"[ORCH] Post-action response: {response[:100]!r}")
    # Catch hallucinated "done" responses: model claims success without [WRITE:]
    _DONE_CLAIM_RE = re.compile(
        r"(done|complete[d]?|applied|updated|changed|fixed|set|modified)",
        re.IGNORECASE,
    )
    if (response
            and _DONE_CLAIM_RE.search(response)
            and not _WRITE_RE.search(response)
            and _CODE_RE.search(task)):
        log("[ORCH] Hallucination detected: claimed done without [WRITE:] -- retrying", "WARN")
        retry_prompt = (
            "Previous task: " + task + ". "
            "You claimed the task was done but NO [WRITE:] tag was emitted. "
            "You cannot modify files without [WRITE:]. "
            "Read the file with [ACTION:cat <path>] then emit "
            "[WRITE:path]full-modified-content[/WRITE]. Do this now."
        )
        response = _generate(retry_prompt, chat_id)
        if response and _ACTION_RE.search(response):
            response = process_action_tags(response, task, chat_id)
        log(f"[ORCH] Retry response: {(response or '')[:100]!r}")
    audit_log("response", response or "", chat_id, {"model": _used_model})
    return response or "No response generated."


def orchestrate(task: str, chat_id: str):
    log(f"[ORCH] Task: {task[:80]!r}")
    audit_log("intent", task, chat_id)
    response = _generate(task, chat_id)
    conv_add(chat_id, "assistant", response)

    def _strip_fences(s: str) -> str:
        s = re.sub(r'^```[a-z]*\n?', '', s.strip())
        s = re.sub(r'\n?```$', '', s)
        return s.strip()

    clean = response
    sent_files = False

    # Format 1: [SEND_FILE:name]content[/SEND_FILE]
    tagged = re.compile(r'\[SEND_FILE:([^\]]+)\](.*?)\[/SEND_FILE\]', re.DOTALL)
    for m in tagged.finditer(response):
        fname   = m.group(1).strip()
        content = _strip_fences(m.group(2))
        ok = tg_send_document(content, fname, chat_id)
        log(f"[ORCH] File sent (tagged): {fname} ok={ok}")
        clean = clean.replace(m.group(0), f"[sent file: {fname}]")
        sent_files = True

    # Format 2: response STARTS with [SEND_FILE:name] but no closing tag (model forgot it)
    if not sent_files:
        m2 = re.match(r'\[SEND_FILE:([^\]]+)\]\s*(.*)', response, re.DOTALL)
        if m2:
            fname   = m2.group(1).strip()
            content = _strip_fences(m2.group(2))
            ok = tg_send_document(content, fname, chat_id)
            log(f"[ORCH] File sent (no-close tag): {fname} ok={ok}")
            clean = f"[sent file: {fname}]"
            sent_files = True

    for m in _REMEMBER_RE.finditer(clean):
        _save_pm_memory(m.group(1))
    clean = _REMEMBER_RE.sub("", clean).strip()
    write_matches = list(_WRITE_RE.finditer(clean))
    clean = _WRITE_RE.sub("", clean).strip()
    if write_matches and chat_id:
        wm = write_matches[0]
        w_path = wm.group(1).strip()
        w_content = wm.group(2)
        log(f"[WRITE] staging confirm for {w_path!r} ({len(w_content)} chars)")
        with _PENDING_LOCK:
            _PENDING_CONFIRMS[chat_id] = {
                "type": "write",
                "path": w_path,
                "content": w_content,
                "ts": time.time(),
            }
        preview = "\n".join(w_content.strip().splitlines()[:25])
        tg_send(
            f"Proposed write to `{w_path}`:\n\n```\n{preview}\n```\n\nReply YES to write + restart, NO to cancel (5 min timeout).",
            chat_id,
        )

    # If a write confirm is pending, suppress the remaining text — it looks like a "done" notice
    if write_matches and chat_id:
        return

    # Auto-file: plain long responses (>2000 chars, no existing file tag)
    if not sent_files and len(clean) > 2000:
        fname = "response.md"
        ok = tg_send_document(clean, fname, chat_id)
        log(f"[ORCH] Auto-file (len={len(clean)}): ok={ok}")
        if ok:
            clean = f"[sent file: {fname}]"

    if clean:
        for i in range(0, max(len(clean), 1), 4000):
            tg_send(clean[i:i + 4000], chat_id)


class _ChatHandler(BaseHTTPRequestHandler):
    """HTTP handler: POST /api/chat and GET /api/health for LFM Android."""

    def do_GET(self):
        if self.path in ("/api/health", "/health"):
            body = json.dumps({"status": "ok", "service": "pm-agent"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/digest"):
            self._serve_digest()
        elif self.path == "/api/program/status":
            data = program_status()
            body = json.dumps(data or {}).encode()
            self.send_response(200 if data else 404)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def _serve_digest(self):
        from urllib.parse import urlparse, parse_qs
        from pathlib import Path as _Path
        qs = parse_qs(urlparse(self.path).query)
        digest_dir = _Path(os.environ.get("DIGEST_DIR", "/mnt/Main/appdata/pm-agent/digests"))
        if "date" in qs:
            target = qs["date"][0]
            path = digest_dir / f"{target}.md"
        elif "days" in qs:
            n = int(qs["days"][0])
            from datetime import date as _date, timedelta as _td
            parts = []
            for i in range(n):
                d = (_date.today() - _td(days=i)).isoformat()
                p = digest_dir / f"{d}.md"
                if p.exists():
                    parts.append(p.read_text("utf-8"))
            body = ("\n\n---\n\n".join(parts) if parts else "No digests found.").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
            return
        else:
            from datetime import date as _date
            path = digest_dir / f"{_date.today().isoformat()}.md"
        if path.exists():
            body = path.read_text("utf-8").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"No digest for that date.")

    def do_POST(self):
        if self.path == "/api/proactive/ack":
            global _proactive_blocked
            cleared = list(_proactive_blocked)
            _proactive_blocked.clear()
            log(f"[PROACTIVE] ack — cleared {len(cleared)} blocked item(s)")
            resp = json.dumps({"cleared": cleared}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", len(resp))
            self.end_headers()
            self.wfile.write(resp)
            return
        if self.path == "/api/program/update":
            auth = self.headers.get("Authorization", "")
            if PM_HTTP_TOKEN and auth != f"Bearer {PM_HTTP_TOKEN}":
                self.send_error(401); return
            try:
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length))
                result = update_program_field(body["project_id"], body["field"], body["value"])
                resp = json.dumps(result or {"ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", len(resp))
                self.end_headers()
                self.wfile.write(resp)
            except Exception as e:
                self.send_error(400)
            return
        if self.path != "/api/chat":
            self.send_error(404)
            return
        auth = self.headers.get("Authorization", "")
        if PM_HTTP_TOKEN and auth != f"Bearer {PM_HTTP_TOKEN}":
            self.send_error(401)
            return
        try:
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            message = body.get("message", body.get("content", "")).strip()
            image_b64 = body.get("image_b64") or None
        except Exception:
            self.send_error(400)
            return
        if not message:
            self.send_error(400)
            return
        chat_id = "lfm-android"
        log(f"[HTTP] /api/chat message={message[:80]!r} image={'yes' if image_b64 else 'no'}")
        conv_add(chat_id, "user", message)
        response_text = _generate(message, chat_id, voice=True, image_b64=image_b64)
        conv_add(chat_id, "assistant", response_text)
        payload = json.dumps({
            "content": [{"type": "text", "text": response_text}]
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        log(f"[HTTP] {fmt % args}")


def _http_serve():
    server = HTTPServer(("0.0.0.0", PM_HTTP_PORT), _ChatHandler)
    log(f"[HTTP] Listening on :{PM_HTTP_PORT} — /api/chat + /api/health")
    server.serve_forever()



# ── Proactive Loop ────────────────────────────────────────────────────────────
import threading as _threading
import time as _time

_PROACTIVE_INTERVAL = 1200  # 20 minutes

def _proactive_tick():
    global _proactive_blocked

    if _proactive_blocked:
        log(f"[PROACTIVE] paused — {len(_proactive_blocked)} blocked item(s)")
        return

    try:
        status = program_status()
    except Exception as e:
        log(f"[PROACTIVE] program_status error: {e}", "WARN")
        return

    projects = (status or {}).get("projects", [])
    active = [p for p in projects
              if str(p.get("status","")).lower() == "active"
              and str(p.get("priority","")).upper() in ("P1","P2")]

    if not active:
        log("[PROACTIVE] no active P1/P2 projects — idle")
        return

    task_lines = "\n".join(
        f"- {p.get('id','?')}: {p.get('name','?')} | phase={p.get('phase','?')} | blocked={p.get('blocked_by','none')}"
        for p in active[:5]
    )
    log(f"[PROACTIVE] {len(active)} active projects — ticking")

    prompt = (
        "You are in autonomous work mode. Larry is not watching right now.\n"
        "Active P1/P2 projects:\n" + task_lines + "\n\n"
        "Pick the most actionable next step and execute it.\n"
        "Use [ACTION:cmd] for shell commands (whitelisted only).\n"
        "Use [WRITE:/path]content[/WRITE] for file edits (whitelisted paths only).\n"
        "Record completions with [REMEMBER: completed X for PROJECT].\n"
        "If stuck and need Larry or Claude, output exactly: [BLOCKED: PROJECT — reason]\n"
        "Do not ask questions. Act or declare blocked. Be brief."
    )

    reply = _call_ollama([{"role": "user", "content": prompt}])
    if not reply:
        log("[PROACTIVE] no reply from local model", "WARN")
        return

    log(f"[PROACTIVE] reply: {reply[:120]}")

    # BLOCKED takes priority
    for m in _BLOCKED_RE.finditer(reply):
        reason = m.group(1).strip()
        _proactive_blocked.append(reason)
        log(f"[PROACTIVE] BLOCKED: {reason}", "WARN")
        tg_send(f"PM blocked — needs input:\n• {reason}")
        return

    # Process other patterns
    processed = process_action_tags(reply, "(proactive)", "")
    for m in _REMEMBER_RE.finditer(reply):
        _save_pm_memory(m.group(1))
    write_results = []
    for m in _WRITE_RE.finditer(reply):
        write_results.append(_handle_write(m.group(1), m.group(2)))

    did_work = "[ACTION:" in reply or _REMEMBER_RE.search(reply) or _WRITE_RE.search(reply)
    if did_work:
        clean = re.sub(r"\[ACTION:[^\]]+\]", "", processed, flags=re.DOTALL)
        clean = _REMEMBER_RE.sub("", clean)
        clean = _WRITE_RE.sub("", clean).strip()
        tg_send(f"[PM Auto]\n{clean[:280]}")


def _proactive_loop():
    _time.sleep(120)  # 2-min warm-up
    while True:
        try:
            _proactive_tick()
        except Exception as e:
            log(f"[PROACTIVE] error: {e}", "WARN")
        _time.sleep(_PROACTIVE_INTERVAL)

def serve():
    threading.Thread(target=_http_serve, daemon=True).start()
    _threading.Thread(target=_proactive_loop, daemon=True).start()
    log('[PROACTIVE] loop started (20min interval)')

    _conv_load()
    log_section("PM Telegram Interface — starting")
    log(f"Bot: {TELEGRAM_BOT_TOKEN[:12]}... | Authorized: {TELEGRAM_CHAT_ID}")
    existing = len(_CONV.get(TELEGRAM_CHAT_ID, []))
    if existing:
        log(f"Conversation memory loaded: {existing} messages")
    offset = 0
    log(f"[SERVE] Starting poll loop offset={offset}")
    while True:
        try:
            updates = tg_poll(offset)
            if updates:
                log(f"[SERVE] Got {len(updates)} updates")
            for update in updates:
                offset  = update["update_id"] + 1
                log(f"[SERVE] update_id={update['update_id']} keys={list(update.keys())}")
                msg     = update.get("message", {})
                chat_id = str(msg.get("chat", {}).get("id", ""))
                if not chat_id:
                    log(f"[SERVE] no chat_id in update, skipping. msg keys={list(msg.keys())}")
                    continue
                if chat_id != TELEGRAM_CHAT_ID:
                    log(f"Ignored message from unauthorized chat {chat_id}", "WARN")
                    continue

                doc = msg.get("document")
                if doc:
                    fname   = doc.get("file_name", "file")
                    file_id = doc.get("file_id")
                    caption = msg.get("caption", "")
                    log(f"[TG] {chat_id}: file={fname!r} caption={caption[:60]!r}")

                    raw = tg_download_file_bytes(file_id)
                    if raw is None:
                        tg_send(f"Could not download {fname}. Try again.", chat_id)
                        continue

                    if fname.lower().endswith(".docx"):
                        content = extract_docx_text(raw)
                        if content is None:
                            tg_send(f"Could not parse {fname} as a Word document.", chat_id)
                            continue
                    elif fname.lower().endswith(".zip"):
                        content = extract_zip_text(raw)
                        if content is None:
                            tg_send(f"Could not read {fname} — zip extraction failed.", chat_id)
                            continue
                    else:
                        # Try UTF-8 only; reject binary (latin-1 always succeeds = garbage)
                        try:
                            content = raw.decode("utf-8")
                        except Exception:
                            tg_send(f"Unsupported file type: {fname}. Send .docx, .zip, or plain text.", chat_id)
                            continue

                    task = f"File received: {fname}\nCaption: {caption}\n\nContents:\n{content[:8000]}"
                    conv_add(chat_id, "user", task)
                    tg_send("Got the file. Looking at it now.", chat_id)
                    threading.Thread(target=orchestrate, args=(task, chat_id), daemon=True).start()
                    continue

                text = msg.get("text", "")
                if not text:
                    continue
                log(f"[TG] {chat_id}: {text[:80]!r}")
                handle_tg_message(text, chat_id)
        except Exception as e:
            log(f"Polling error: {e}", "WARN")
            time.sleep(10)


def main():
    log_section(f"PM Agent run — {date.today().isoformat()}")
    data = program_status()
    if not data:
        log("Cannot read program register. Aborting.", "ERROR")
        sys.exit(1)
    projects = data.get("projects", [])
    summary  = data.get("summary", {})
    log(f"Register: {len(projects)} projects | "
        f"P1={summary.get('active_p1',0)} P2={summary.get('active_p2',0)} "
        f"P3={summary.get('active_p3',0)} blocked={summary.get('blocked',0)}")
    state = load_state()

    log("Scanning resource claims...")
    conflicts = detect_resource_conflicts(projects)
    if not conflicts:
        log("No shared resources detected")
    else:
        log(f"{len(conflicts)} shared resource(s):")
        for c in conflicts:
            log(f"  [RESOURCE] {c['finding']} | {c['detail']}")

    log("Verifying blockers...")
    actions = verify_blockers(projects, state)
    if not actions:
        log("No blockers cleared this run")
    for a in actions:
        log(f"  ACTION [{a['project']}] {a['action']}: {a['why']}")
    save_state(state)

    data     = program_status()
    projects = data.get("projects", []) if data else projects
    findings = analyze_projects(projects)
    if not findings:
        log("No health findings")
    else:
        log(f"{len(findings)} finding(s):")
        for f in findings:
            log(f"  [{f['level']}] [{f['project']}] {f['finding']} — {f['why']}")

    log("Run complete.")
    log("")


if __name__ == "__main__":
    if "--serve" in sys.argv:
        serve()
    else:
        main()
