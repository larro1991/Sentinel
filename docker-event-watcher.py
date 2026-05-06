#!/usr/bin/env python3
"""
Docker event watcher v2 — smart alerting.
Alert ONLY when auto-recovery fails. Silence = healthy. No recovery spam.
"""
import json, subprocess, sys, time, urllib.request, os, threading
from collections import defaultdict

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")  # no hardcoded fallback
CHAT_ID   = os.environ.get("TELEGRAM_CHAT_ID",   "8626879596")

COOLDOWN = 300  # 5 min between repeat alerts per container
UNHEALTHY_GRACE = 120        # 2 min grace before alerting on unhealthy
BOOT_GRACE_SECONDS = 600     # first 10 min after watcher start: use 600s grace instead

_start_time = time.time()
_last_alert: dict[str, float] = defaultdict(float)
_alert_lock = threading.Lock()

# Containers that die normally (job completion, scheduled tasks, self-updates)
EPHEMERAL = {
    "watchtower", "backup-agent", "conversion-queue",
    "audiobook-processor", "m4b-converter",
    "handbrake",        # dies between encode jobs
    "whisper-asr",      # dies between ASR jobs
    "ebook-pipeline",   # batch job, runs and exits 0
    "media-assessment", # one-shot assessment job
    "pm-agent",         # one-shot init container (restart: no in compose)
}

# Containers where unhealthy health status is expected (GPU services, slow loaders)
SKIP_HEALTH_ALERT = {
    "whisper-asr",  # slow model load; healthcheck times out between jobs
    "handbrake",    # idle between encode jobs
}

# Track when containers first went unhealthy
_unhealthy_since: dict[str, float] = {}


def tg(msg: str):
    try:
        body = json.dumps({"chat_id": CHAT_ID, "text": msg}).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            data=body, headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        print(f"[WARN] telegram failed: {e}", flush=True)


def should_alert(container: str) -> bool:
    now = time.time()
    if now - _last_alert[container] < COOLDOWN:
        return False
    _last_alert[container] = now
    return True


def effective_grace() -> int:
    """Use longer grace during boot window."""
    elapsed = time.time() - _start_time
    return 600 if elapsed < BOOT_GRACE_SECONDS else UNHEALTHY_GRACE


def try_restart(name: str) -> bool:
    """Restart container, wait 60s, return True if running."""
    try:
        subprocess.run(["docker", "restart", name], timeout=30, capture_output=True)
        print(f"[watcher] restarted {name} — waiting 60s", flush=True)
        time.sleep(60)
        r = subprocess.run(
            ["docker", "inspect", name, "--format", "{{.State.Status}}"],
            capture_output=True, text=True, timeout=10
        )
        return r.stdout.strip() == "running"
    except Exception as e:
        print(f"[WARN] restart {name} failed: {e}", flush=True)
        return False


def _unhealthy_watcher():
    """Background thread: fire alert only if container stays unhealthy past grace period."""
    while True:
        time.sleep(30)
        now = time.time()
        grace = effective_grace()
        with _alert_lock:
            candidates = [(n, ts) for n, ts in list(_unhealthy_since.items())
                          if now - ts >= grace]

        for name, _ in candidates:
            try:
                r = subprocess.run(
                    ["docker", "inspect", name, "--format",
                     "{{.State.Health.Status}} {{.State.Status}}"],
                    capture_output=True, text=True, timeout=10
                )
                out = r.stdout.strip()
                if "unhealthy" in out or "exited" in out:
                    if should_alert(name):
                        tg(f"SUSTAINED UNHEALTHY\n{name}\nDown >{grace//60}min — needs attention")
                else:
                    print(f"[watcher] {name} recovered silently", flush=True)
            except Exception as e:
                print(f"[WARN] inspect {name}: {e}", flush=True)
            with _alert_lock:
                _unhealthy_since.pop(name, None)


def handle_event(ev: dict):
    if ev.get("Type") != "container":
        return

    action    = ev.get("Action", "")
    attrs     = ev.get("Actor", {}).get("Attributes", {})
    name      = attrs.get("name", ev.get("Actor", {}).get("ID", "?")[:12])
    exit_code = attrs.get("exitCode", "?")
    image     = attrs.get("image", "?")

    if action == "die":
        try:
            code = int(exit_code)
        except (ValueError, TypeError):
            code = -1
        if code == 0 or name in EPHEMERAL:
            return
        print(f"[watcher] crash: {name} exit={exit_code} — attempting auto-restart", flush=True)
        if try_restart(name):
            print(f"[watcher] {name} auto-recovered — silent", flush=True)
            return
        if should_alert(name):
            tg(f"CONTAINER DOWN\n{name}\nexit={exit_code}\nAuto-restart failed — needs attention")
        return

    if action == "oom":
        if should_alert(name):
            tg(f"OOM KILLED\n{name}\nimage={image}")
        return

    if action == "kill":
        sig = attrs.get("signal", "?")
        # 15=SIGTERM (Docker graceful stop), 9=SIGKILL (Docker forced stop after grace period)
        if sig in ("9", "SIGKILL", "15", "SIGTERM"):
            print(f"[watcher] {name} killed sig={sig} (Docker lifecycle)", flush=True)
            return
        if should_alert(name):
            tg(f"CONTAINER KILLED (sig={sig})\n{name}")
        return

    if action.startswith("health_status"):
        status = action.split(": ", 1)[-1] if ": " in action else action
        if status in {"unhealthy"}:
            if name in SKIP_HEALTH_ALERT:
                return
            with _alert_lock:
                if name not in _unhealthy_since:
                    _unhealthy_since[name] = time.time()
                    print(f"[watcher] {name} unhealthy — grace {effective_grace()}s", flush=True)
        elif status == "healthy":
            with _alert_lock:
                _unhealthy_since.pop(name, None)
            _last_alert[name] = 0


def main():
    print("[watcher] starting", flush=True)
    tg("Proxmox server restarted")

    t = threading.Thread(target=_unhealthy_watcher, daemon=True)
    t.start()

    while True:
        try:
            proc = subprocess.Popen(
                ["docker", "events",
                 "--filter", "type=container",
                 "--filter", "event=die",
                 "--filter", "event=oom",
                 "--filter", "event=kill",
                 "--filter", "event=health_status",
                 "--format", "{{json .}}"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            print("[watcher] stream open", flush=True)
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                    handle_event(ev)
                except json.JSONDecodeError:
                    print(f"[WARN] bad json: {line[:80]}", flush=True)
            proc.wait()
            print("[watcher] stream closed — restarting in 5s", flush=True)
        except Exception as e:
            print(f"[ERROR] {e}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    main()
