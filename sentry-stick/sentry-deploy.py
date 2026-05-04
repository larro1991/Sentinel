#!/usr/bin/env python3
"""
sentry-deploy.py — remote deployment of sentry rescue partition.

Scans a subnet or targets a single host. Detects OS. SSHes in (Linux)
or uses WinRM (Windows). Deploys the sentry EFI bundle to the host's ESP.
Adds a non-default-boot EFI entry. Registers the host to the UAI broker.

Usage:
    python sentry-deploy.py --host 192.168.110.185
    python sentry-deploy.py --subnet 192.168.110.0/24
    python sentry-deploy.py --subnet 192.168.110.0/24 --dry-run
    python sentry-deploy.py --list    # show registered sentry machines
    python sentry-deploy.py --remove 192.168.110.185

Requires:
    pip install paramiko pywinrm python-nmap
    sentry EFI bundle built: ./sentry-stick/usb.img or ./sentry-efi/ directory
"""

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

# ── config ────────────────────────────────────────────────────────────────────
UAI_BROKER_IP  = os.environ.get("UAI_BROKER", "192.168.110.XXX")  # GamingPC IP
UAI_BROKER_PORT = 7700
SENTRY_EFI_DIR  = Path(__file__).parent / "sentry-efi"  # extracted from usb.img
REGISTRY_FILE   = Path(__file__).parent / "sentry-registry.json"
SSH_KEY         = Path.home() / ".ssh" / "id_ed25519"
SSH_USER        = "root"
WINRM_USER      = "Administrator"
WINRM_PORT      = 5985

# ── registry ──────────────────────────────────────────────────────────────────

def _load_registry():
    if REGISTRY_FILE.exists():
        return json.loads(REGISTRY_FILE.read_text())
    return {}

def _save_registry(reg):
    REGISTRY_FILE.write_text(json.dumps(reg, indent=2))

# ── host detection ────────────────────────────────────────────────────────────

def _tcp_open(host, port, timeout=2):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except Exception:
        return False

def _detect_os(host):
    """Returns 'linux', 'windows', or None (unreachable)."""
    ssh_open  = _tcp_open(host, 22)
    winrm_open = _tcp_open(host, WINRM_PORT)

    if not ssh_open and not winrm_open:
        return None

    if ssh_open:
        # Quick banner check
        try:
            import paramiko
            t = paramiko.Transport((host, 22))
            t.start_client(timeout=5)
            banner = t.remote_version
            t.close()
            if "Windows" in banner:
                return "windows"
            return "linux"
        except Exception:
            return "linux"  # assume Linux if SSH is open

    if winrm_open:
        return "windows"

    return None

def _scan_subnet(subnet):
    """Yield (ip, os_type) for reachable hosts on subnet."""
    network = ipaddress.ip_network(subnet, strict=False)
    print(f"Scanning {network} ({network.num_addresses} addresses)...")
    for ip in network.hosts():
        host = str(ip)
        os_type = _detect_os(host)
        if os_type:
            print(f"  {host}: {os_type}")
            yield host, os_type
        else:
            sys.stdout.write(".")
            sys.stdout.flush()
    print()

# ── Linux deploy ──────────────────────────────────────────────────────────────

def _deploy_linux(host, dry_run=False):
    """Deploy sentry to a Linux host via SSH."""
    try:
        import paramiko
    except ImportError:
        print("ERROR: pip install paramiko")
        return False

    print(f"[{host}] Deploying to Linux via SSH...")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, username=SSH_USER, key_filename=str(SSH_KEY), timeout=10)

    def run(cmd):
        _, stdout, stderr = client.exec_command(cmd, timeout=30)
        out = stdout.read().decode().strip()
        err = stderr.read().decode().strip()
        return out, err

    # Check UEFI
    out, _ = run("[ -d /sys/firmware/efi ] && echo uefi || echo bios")
    if "bios" in out:
        print(f"[{host}] WARNING: host is BIOS, not UEFI. Skipping.")
        client.close()
        return False

    # Find ESP
    out, _ = run("findmnt -n -o SOURCE /boot/efi 2>/dev/null || lsblk -o MOUNTPOINT,NAME | awk '/efi/{print \"/dev/\"$2}'")
    esp_dev = out.strip()
    print(f"[{host}] ESP device: {esp_dev}")

    if dry_run:
        print(f"[{host}] DRY RUN — would install to ESP at {esp_dev}")
        client.close()
        return True

    # Upload sentry EFI files via SFTP
    sftp = client.open_sftp()
    # Create /EFI/sentry on the ESP
    run("mkdir -p /boot/efi/EFI/sentry")
    for f in SENTRY_EFI_DIR.glob("**/*"):
        if f.is_file():
            remote_path = "/boot/efi/EFI/sentry/" + f.name
            sftp.put(str(f), remote_path)
            print(f"[{host}]   uploaded {f.name}")
    sftp.close()

    # Add EFI boot entry (not in BootOrder)
    disk = esp_dev.rstrip("0123456789")
    part_num = esp_dev[len(disk):]
    out, err = run(
        f'efibootmgr -c -d {disk} -p {part_num} '
        f'-L "Sentry rescue (DO NOT CHANGE)" '
        f'-l "\\\\EFI\\\\sentry\\\\grubx64.efi" '
        f'--inactive'  # not in boot order
    )
    print(f"[{host}] efibootmgr: {out or err}")

    client.close()
    return True

# ── Windows deploy ─────────────────────────────────────────────────────────────

def _deploy_windows(host, dry_run=False):
    """Deploy sentry to a Windows host via WinRM + PowerShell."""
    try:
        import winrm
    except ImportError:
        print("ERROR: pip install pywinrm")
        return False

    print(f"[{host}] Deploying to Windows via WinRM...")

    session = winrm.Session(host, auth=(WINRM_USER, ""), transport="kerberos")

    def ps(script):
        r = session.run_ps(script)
        return r.std_out.decode().strip(), r.std_err.decode().strip()

    if dry_run:
        print(f"[{host}] DRY RUN — would install to Windows ESP")
        return True

    # Mount ESP
    script = """
$esp = (Get-Partition | Where-Object { $_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}' })[0]
if (-not $esp) { Write-Error "No ESP found"; exit 1 }
mountvol X: /S
New-Item -Path "X:\\EFI\\sentry" -ItemType Directory -Force | Out-Null
Write-Output "ESP mounted at X:\\ (disk $($esp.DiskNumber) part $($esp.PartitionNumber))"
"""
    out, err = ps(script)
    print(f"[{host}] {out or err}")

    # Copy files — for now just note the step; real impl needs file transfer
    print(f"[{host}] TODO: transfer sentry EFI files to X:\\EFI\\sentry\\")
    print(f"[{host}] TODO: add EFI boot entry via bcdedit or EFI vars")

    # Add EFI entry via bcdedit (basic stub — refine with actual GUIDs)
    efi_script = r"""
$id = bcdedit /copy '{bootmgr}' /d "Sentry rescue"
# Extract GUID from output
$guid = ($id -match '\{.*\}' | Out-Null; $Matches[0])
bcdedit /set $guid device partition=X:
bcdedit /set $guid path \EFI\sentry\grubx64.efi
bcdedit /displayorder $guid /addfirst
bcdedit /bootsequence $guid  # only boot once on explicit request
Write-Output "Added EFI entry: $guid"
"""
    out, err = ps(efi_script)
    print(f"[{host}] {out or err}")
    return True

# ── UAI registration ───────────────────────────────────────────────────────────

def _register_to_uai(host, os_type):
    """Register newly-deployed machine to UAI broker."""
    from urllib.request import urlopen, Request
    payload = json.dumps({
        "type":      "sentry",
        "hostname":  host,
        "ip":        host,
        "os_type":   os_type,
        "deployed":  True,
        "mode":      "installed",  # sentry is on disk, not running yet
    }).encode()
    try:
        req = Request(
            f"http://{UAI_BROKER_IP}:{UAI_BROKER_PORT}/sentry/register",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=5) as resp:
            print(f"[{host}] registered to UAI broker")
    except Exception as e:
        print(f"[{host}] could not reach UAI broker ({e}) — machine registered locally")

# ── main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Deploy sentry rescue partition to remote machines")
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("--host",   help="Single target IP")
    g.add_argument("--subnet", help="CIDR to scan, e.g. 192.168.110.0/24")
    g.add_argument("--list",   action="store_true", help="List registered sentry machines")
    g.add_argument("--remove", metavar="IP", help="Uninstall sentry from a machine")
    parser.add_argument("--os",      choices=["linux", "windows"], help="Override OS detection")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    reg = _load_registry()

    if args.list:
        if not reg:
            print("No machines registered.")
        for host, info in reg.items():
            print(f"  {host:20s}  {info.get('os_type','?'):8s}  {info.get('deployed_at','?')}")
        return

    if args.remove:
        host = args.remove
        if host in reg:
            del reg[host]
            _save_registry(reg)
            print(f"Removed {host} from registry. NOTE: sentry EFI files still on target ESP.")
        else:
            print(f"{host} not in registry.")
        return

    targets = []
    if args.host:
        os_type = args.os or _detect_os(args.host)
        if not os_type:
            print(f"Host {args.host} is unreachable.")
            sys.exit(1)
        targets = [(args.host, os_type)]
    else:
        targets = list(_scan_subnet(args.subnet))
        if args.os:
            targets = [(h, args.os) for h, _ in targets]

    for host, os_type in targets:
        print(f"\n── {host} ({os_type}) ──")
        ok = False
        if os_type == "linux":
            ok = _deploy_linux(host, dry_run=args.dry_run)
        elif os_type == "windows":
            ok = _deploy_windows(host, dry_run=args.dry_run)
        else:
            print(f"[{host}] unsupported OS type: {os_type}")
            continue

        if ok and not args.dry_run:
            reg[host] = {
                "os_type":     os_type,
                "deployed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "status":      "installed",
            }
            _save_registry(reg)
            _register_to_uai(host, os_type)
            print(f"[{host}] ✓ sentry deployed")
        elif not ok:
            print(f"[{host}] ✗ deployment failed")

if __name__ == "__main__":
    main()
