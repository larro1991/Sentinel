"""
Axiom-inspired trust engine for sentry-agent.

Identity:   Ed25519 keypair (generated once, persisted on P3 /var/lib/sentry/identity/)
Level 0:    Challenge-response handshake (GET /challenge → POST /handshake)
Level 2:    16-byte HMAC session token in Authorization: Axiom <token>
Fallback:   Authorization: Bearer <token> (pre-shared, engagement.yaml)

Wire markers are intentionally non-standard so generic scanners can't fingerprint.
"""

import hashlib
import hmac
import os
import secrets
import struct
import time
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import (
        Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key,
    )
    HAS_ED25519 = True
except ImportError:
    HAS_ED25519 = False

IDENTITY_DIR    = Path("/var/lib/sentry/identity")
PRIVKEY_FILE    = IDENTITY_DIR / "node.privkey.pem"
PUBKEY_FILE     = IDENTITY_DIR / "node.pubkey.hex"
SESSION_SECRET  = IDENTITY_DIR / "session.secret"

NONCE_TTL_SEC    = 30     # challenge expires after 30s
SESSION_TTL_SEC  = 900    # session token valid 15 min
SESSION_REFRESH  = 120    # reissue when <2 min remain

PROTO_VERSION = "axiom-sentry/1"

# ── In-memory state (per-process, reset on restart) ──────────────────────────
_nonces: dict   = {}   # nonce_hex → expiry_ts
_sessions: dict = {}   # token_hex → {"expiry": ts, "broker_id": str, "needs_refresh": bool}


# ── Hybrid clock (simplified — physical ms only) ──────────────────────────────

def _ts_ms() -> int:
    return int(time.time() * 1000)


# ── Identity ──────────────────────────────────────────────────────────────────

def load_or_generate_identity():
    """
    Returns (privkey_obj | None, pubkey_hex | None).
    Generates Ed25519 keypair on first call, persists to P3.
    Falls back gracefully if cryptography library not installed.
    """
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)

    if not HAS_ED25519:
        print("[trust] WARNING: py3-cryptography not available — "
              "Ed25519 identity disabled, falling back to bearer token only")
        return None, None

    if PRIVKEY_FILE.exists() and PUBKEY_FILE.exists():
        pem = PRIVKEY_FILE.read_bytes()
        privkey = load_pem_private_key(pem, password=None)
        pubkey_hex = PUBKEY_FILE.read_text().strip()
        print(f"[trust] Ed25519 identity loaded: {pubkey_hex[:16]}…")
        return privkey, pubkey_hex

    print("[trust] Generating Ed25519 node keypair (first boot)…")
    privkey = Ed25519PrivateKey.generate()

    pem = privkey.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    PRIVKEY_FILE.write_bytes(pem)
    PRIVKEY_FILE.chmod(0o600)

    pub_raw = privkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    pubkey_hex = pub_raw.hex()
    PUBKEY_FILE.write_text(pubkey_hex + "\n")
    PUBKEY_FILE.chmod(0o644)

    print(f"[trust] New node identity: {pubkey_hex[:16]}… (persisted to P3)")
    return privkey, pubkey_hex


def load_or_generate_session_secret() -> bytes:
    """32-byte HMAC secret for session token generation. Persisted on P3."""
    IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
    if SESSION_SECRET.exists():
        return SESSION_SECRET.read_bytes()
    s = secrets.token_bytes(32)
    SESSION_SECRET.write_bytes(s)
    SESSION_SECRET.chmod(0o600)
    return s


# ── Challenge / Handshake (Trust Level 0 → Level 2) ──────────────────────────

def issue_challenge(pubkey_hex: str | None) -> dict:
    """
    Called by GET /challenge.
    Returns a single-use nonce + agent public key.
    Broker must return this nonce in POST /handshake within NONCE_TTL_SEC seconds.
    """
    _expire_nonces()
    nonce = secrets.token_hex(32)
    _nonces[nonce] = time.time() + NONCE_TTL_SEC
    return {
        "proto":       PROTO_VERSION,
        "nonce":       nonce,
        "pubkey":      pubkey_hex or "",
        "ts_ms":       _ts_ms(),
        "expires_in":  NONCE_TTL_SEC,
        "trust_level": 0,
    }


def complete_handshake(
    nonce: str,
    broker_id: str,
    privkey,
    pubkey_hex: str | None,
    session_secret: bytes,
) -> tuple[str | None, dict]:
    """
    Called by POST /handshake.
    Verifies nonce freshness (single-use), signs it, issues session token.

    Returns (session_token_hex, response_dict).
    On failure returns (None, error_dict).

    Wire: agent signs BLAKE3/SHA256(nonce_bytes || broker_id_utf8).
    Broker stores session_token and sends it as: Authorization: Axiom <token>
    """
    _expire_nonces()

    if nonce not in _nonces:
        return None, {
            "ok": False, "error": "nonce expired or unknown",
            "code": "TRUST_DENIED", "proto": PROTO_VERSION,
        }

    del _nonces[nonce]  # single-use — consumed immediately

    # Sign: Ed25519(privkey, nonce_bytes || broker_id)
    signature = None
    if privkey and HAS_ED25519:
        msg = bytes.fromhex(nonce) + broker_id.encode("utf-8")
        sig_bytes = privkey.sign(msg)
        signature = sig_bytes.hex()

    # Session token: HMAC-SHA256(secret, nonce || broker_id || ts_ms)[0:16]
    ts_bytes = struct.pack(">Q", _ts_ms())
    mac = hmac.new(
        session_secret,
        bytes.fromhex(nonce) + broker_id.encode("utf-8") + ts_bytes,
        hashlib.sha256,
    ).digest()[:16]
    token = mac.hex()

    _sessions[token] = {
        "expiry":        time.time() + SESSION_TTL_SEC,
        "broker_id":     broker_id,
        "needs_refresh": False,
    }

    print(f"[trust] Handshake complete. broker={broker_id!r} "
          f"token={token[:8]}… trust_level=2")

    return token, {
        "ok":            True,
        "proto":         PROTO_VERSION,
        "session_token": token,
        "expires_in":    SESSION_TTL_SEC,
        "agent_pubkey":  pubkey_hex or "",
        "signature":     signature,
        "trust_level":   2,
    }


# ── Session validation ────────────────────────────────────────────────────────

def validate_session(token: str) -> tuple[bool, str]:
    """
    Returns (ok, broker_id_or_error_msg).
    Marks session for refresh if <SESSION_REFRESH seconds remain.
    """
    _expire_sessions()
    entry = _sessions.get(token)
    if not entry:
        return False, "session token invalid or expired (re-handshake required)"
    remaining = entry["expiry"] - time.time()
    if remaining < SESSION_REFRESH:
        entry["needs_refresh"] = True
    return True, entry["broker_id"]


def session_needs_refresh(token: str) -> bool:
    entry = _sessions.get(token)
    return bool(entry and entry.get("needs_refresh"))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _expire_nonces():
    now = time.time()
    dead = [k for k, v in _nonces.items() if v < now]
    for k in dead:
        del _nonces[k]


def _expire_sessions():
    now = time.time()
    dead = [k for k, v in _sessions.items() if v["expiry"] < now]
    for k in dead:
        del _sessions[k]
