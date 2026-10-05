"""ULP v1.1 — versioned extensions (backward compatible with v1).

Byte-stability rule (docs/21 §1): v1 frames/messages are UNCHANGED.
v1.1 adds:
  * FEAT_VERSIONED (bit 8) in the u16 feature mask
  * MSG_DEVICE_ID (0x11) / MSG_DEVICE_AUTH (0x12) post-AUTH_OK identity
    exchange (only when the feature is negotiated)
  * MSG_RESUME_REQ (0x0E) / MSG_RESUME_OK (0x13) session resumption
  * structured MSG_ERROR body (message flag 0x01) with stable error codes

The transcript binding: MACs over identity/resume messages cover the
exact wire bytes (headers + payloads, both directions, in local
observation order) observed since the TCP connection opened — the
handshake is strictly sequential, so both sides observe identical
bytes. ulp_link.Link records these in `link.transcript`.
"""
import hashlib
import hmac
import os
import time

from reference_framing import (
    HKDF_INFO, hkdf_sha256, x25519, x25519_public,
)

FEAT_VERSIONED = 1 << 8

MSG_DEVICE_ID = 0x11
MSG_DEVICE_AUTH = 0x12
MSG_RESUME_REQ = 0x0E  # v1 reserved slot; wire format finalized by v1.1
MSG_RESUME_OK = 0x13

# capability bits (device fabric, docs/25 §6)
CAP_NETWORK = 1 << 0
CAP_DISPLAY = 1 << 1
CAP_CAMERA = 1 << 2
CAP_MIC = 1 << 3
CAP_AUDIO = 1 << 4
CAP_INPUT = 1 << 5
CAP_STORAGE = 1 << 6
CAP_MESSAGING = 1 << 7
CAP_NOTIFICATIONS = 1 << 8
CAP_AUTOMATION = 1 << 9

# MSG_ERROR codes (structured body, message flag 0x01)
ERR_AUTH = 0x0001
ERR_CIPHER = 0x0002
ERR_VERSION = 0x0003
ERR_FORMAT = 0x0004
ERR_LIMIT = 0x0005
ERR_TIMEOUT = 0x0006
ERR_IDENTITY_REQUIRED = 0x0007
ERR_THROTTLED = 0x0008
ERR_REVOKED = 0x0009
ERR_RESUME_INVALID = 0x000A
ERR_UPGRADE_REQUIRED = 0x000B

ERROR_FLAG = 0x01

# trust decisions
DECISION_TRUSTED = 0
DECISION_TRUSTED_NEW = 1
DECISION_REVOKED = 2
DECISION_THROTTLED = 3

# resume policy defaults (configurable)
RESUME_TTL_S = 600
RESUME_MAX_ATTEMPTS = 50

# pairing rate limit (per source)
PAIR_MAX_FAILURES = 5
PAIR_WINDOW_S = 60


# ------------------------------------------------------------- identity
def new_identity(priv: bytes = None) -> dict:
    """Long-lived device identity: X25519 keypair + derived device id."""
    priv = priv or os.urandom(32)
    pub = x25519_public(priv)
    return {"priv": priv, "pub": pub, "device_id": device_id_from_pub(pub)}


def device_id_from_pub(identity_pub: bytes) -> bytes:
    """Stable device id = SHA256('unilink-dev-id-v1' || identity_pub)[:16]."""
    return hashlib.sha256(b"unilink-dev-id-v1" + identity_pub).digest()[:16]


def device_id_body(device_id: bytes, identity_pub: bytes, name: str,
                   platform: str, app_ver: str, caps: int,
                   transcript: bytes, key_mac: bytes) -> bytes:
    """164 B: id(16) pub(32) name(64) platform(16) app_ver(16) caps(u32) mac(16)."""
    name_b = name.encode("utf-8")[:64].ljust(64, b"\x00")
    plat_b = platform.encode("utf-8")[:16].ljust(16, b"\x00")
    ver_b = app_ver.encode("utf-8")[:16].ljust(16, b"\x00")
    pre = device_id + identity_pub + name_b + plat_b + ver_b \
        + caps.to_bytes(4, "big")
    mac = hmac.new(key_mac, b"unilink-dev-id-v1" + transcript + pre,
                   hashlib.sha256).digest()[:16]
    return pre + mac


def device_id_parse(body: bytes, transcript: bytes, key_mac: bytes) -> dict:
    if len(body) != 164:
        raise ValueError(f"device_id: bad length {len(body)}")
    pre, mac = body[:148], body[148:]
    expect = hmac.new(key_mac, b"unilink-dev-id-v1" + transcript + pre,
                      hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac, expect):
        raise ValueError("device_id: mac mismatch")
    name = body[48:112].rstrip(b"\x00").decode("utf-8", "replace")
    platform = body[112:128].rstrip(b"\x00").decode("utf-8", "replace")
    app_ver = body[128:144].rstrip(b"\x00").decode("utf-8", "replace")
    return {
        "device_id": body[:16],
        "identity_pub": body[16:48],
        "name": name,
        "platform": platform,
        "app_ver": app_ver,
        "caps": int.from_bytes(body[144:148], "big"),
    }


def device_auth_body(decision: int, session_id: bytes, sender_id: bytes,
                     transcript: bytes, key_mac: bytes) -> bytes:
    """49 B: decision(1) session_id(16) sender_id(16) mac(16)."""
    pre = bytes([decision & 0xFF]) + session_id + sender_id
    mac = hmac.new(key_mac, b"unilink-dev-auth-v1" + transcript + pre,
                   hashlib.sha256).digest()[:16]
    return pre + mac


def device_auth_parse(body: bytes, transcript: bytes, key_mac: bytes) -> dict:
    if len(body) != 49:
        raise ValueError(f"device_auth: bad length {len(body)}")
    pre, mac = body[:33], body[33:]
    expect = hmac.new(key_mac, b"unilink-dev-auth-v1" + transcript + pre,
                      hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac, expect):
        raise ValueError("device_auth: mac mismatch")
    return {"decision": body[0], "session_id": body[1:17],
            "sender_id": body[17:33]}


# ------------------------------------------------------------- resume
def resume_req_body(session_id: bytes, fresh_pub: bytes, resume_nonce: bytes,
                    secret: bytes) -> bytes:
    """80 B: session_id(16) fresh_pub(32) nonce(16) mac(16).

    Keyed with the *pairing secret* (session keys are dead at resume
    time) — binds the resume to the original pairing."""
    pre = session_id + fresh_pub + resume_nonce
    mac = hmac.new(secret, b"unilink-resume-v1" + pre,
                   hashlib.sha256).digest()[:16]
    return pre + mac


def resume_req_parse(body: bytes, secret: bytes) -> dict:
    if len(body) != 80:
        raise ValueError(f"resume_req: bad length {len(body)}")
    pre, mac = body[:64], body[64:]
    expect = hmac.new(secret, b"unilink-resume-v1" + pre,
                      hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac, expect):
        raise ValueError("resume_req: mac mismatch")
    return {"session_id": body[:16], "fresh_pub": body[16:48],
            "resume_nonce": body[48:64]}


def resume_ok_body(fresh_pub: bytes, session_id: bytes, req_pub: bytes,
                   secret: bytes) -> bytes:
    """48 B: fresh_pub(32) mac(16)."""
    mac = hmac.new(secret, b"unilink-resume-v1" + session_id + req_pub
                   + fresh_pub, hashlib.sha256).digest()[:16]
    return fresh_pub + mac


def resume_ok_parse(body: bytes, session_id: bytes, req_pub: bytes,
                    secret: bytes) -> bytes:
    if len(body) != 48:
        raise ValueError(f"resume_ok: bad length {len(body)}")
    fresh_pub, mac = body[:32], body[32:]
    expect = hmac.new(secret, b"unilink-resume-v1" + session_id + req_pub
                      + fresh_pub, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(mac, expect):
        raise ValueError("resume_ok: mac mismatch")
    return fresh_pub


def resume_session_keys(shared: bytes, resume_nonce: bytes,
                        session_id: bytes, cipher_sel: int):
    """New (key_aead, key_mac) for a resumed session (fresh ECDH)."""
    keys = hkdf_sha256(shared, resume_nonce + session_id,
                       b"unilink-v1-resume" + bytes([cipher_sel]), 64)
    return keys[0:32], keys[32:64]


# ------------------------------------------------------------- errors
def error_body(fatal: bool, code: int, msg: str) -> bytes:
    """Structured error: fatal(1) code(u16) len(u16) msg."""
    m = msg.encode("utf-8")[:120]
    return bytes([1 if fatal else 0]) + code.to_bytes(2, "big") \
        + len(m).to_bytes(2, "big") + m


def error_parse(body: bytes) -> dict:
    if len(body) < 5:
        raise ValueError("error: short body")
    fatal = body[0] & 0x01
    code = int.from_bytes(body[1:3], "big")
    mlen = int.from_bytes(body[3:5], "big")
    if len(body) < 5 + mlen:
        raise ValueError("error: short message")
    return {"fatal": bool(fatal), "code": code,
            "msg": body[5:5 + mlen].decode("utf-8", "replace")}


# ------------------------------------------------------------- replay
class HandshakeReplayCache:
    """Rejects repeated (ecdh_pub, nonce) handshake pairs (docs/18 T2)."""

    def __init__(self, max_entries: int = 256):
        self._seen = {}
        self._max = max_entries

    def check(self, ecdh_pub: bytes, nonce: bytes) -> bool:
        """True = first time (ok), False = replay (reject)."""
        key = (ecdh_pub, nonce)
        now = time.time()
        if key in self._seen:
            return False
        self._seen[key] = now
        while len(self._seen) > self._max:  # FIFO eviction
            oldest = min(self._seen, key=self._seen.get)
            del self._seen[oldest]
        return True


# ------------------------------------------------------------- throttle
class PairingGate:
    """Per-source pairing failure rate limit (docs/18 T10).

    `attempt()` before each handshake; `failure()` after each failed
    auth. When the window is exhausted, `attempt()` returns False and
    the device MUST refuse with ERR_THROTTLED."""

    def __init__(self, max_failures: int = PAIR_MAX_FAILURES,
                 window_s: float = PAIR_WINDOW_S,
                 clock=time.monotonic):
        self.max_failures = max_failures
        self.window_s = window_s
        self._clock = clock
        self._fails = {}

    def attempt(self, source: str) -> bool:
        now = self._clock()
        self._fails = {s: [t for t in ts if now - t < self.window_s]
                       for s, ts in self._fails.items()}
        recent = self._fails.get(source, [])
        return len(recent) < self.max_failures

    def failure(self, source: str) -> None:
        now = self._clock()
        self._fails.setdefault(source, []).append(now)

    def reset(self, source: str) -> None:
        self._fails.pop(source, None)


# ------------------------------------------------------------- exchange
def identity_exchange(link, role: int, identity: dict, trust,
                      session_id: bytes, peer_wait: float = 10.0) -> dict:
    """Run the v1.1 post-AUTH_OK identity exchange (docs/21 §3).

    Order (both sides, strictly sequential):
      1. device -> MSG_DEVICE_ID
      2. host   -> MSG_DEVICE_ID
      3. device -> MSG_DEVICE_AUTH (about host identity)
      4. host   -> MSG_DEVICE_AUTH (about device identity)

    `trust` is a TrustRegistry (device side: decides about the host);
    the host side passes its own registry for the device identity.
    Returns {"device_id":..., "session_id":..., "trusted": True}.
    Raises ValueError on any failure (caller sends MSG_ERROR).
    """
    from reference_framing import CH_CONTROL, MSG_HELLO
    from ulp_link import Link

    role_device = 1
    is_device = role == role_device

    def send_id():
        body = device_id_body(identity["device_id"], identity["pub"],
                              identity.get("name", "unilink"),
                              identity.get("platform", "unknown"),
                              identity.get("app_ver", "0.0.0"),
                              identity.get("caps", 0),
                              bytes(link.transcript), link.km)
        link.send_msg(MSG_DEVICE_ID, body)

    def recv_id() -> dict:
        mtype, _f, body = link.recv_msg()
        if mtype != MSG_DEVICE_ID:
            raise ValueError(f"expected DEVICE_ID, got {mtype:#x}")
        return device_id_parse(body, link.transcript_prefix, link.km)

    def send_auth(decision: int, sid: bytes):
        body = device_auth_body(decision, sid, identity["device_id"],
                                bytes(link.transcript), link.km)
        link.send_msg(MSG_DEVICE_AUTH, body)

    def recv_auth() -> dict:
        mtype, _f, body = link.recv_msg()
        if mtype != MSG_DEVICE_AUTH:
            raise ValueError(f"expected DEVICE_AUTH, got {mtype:#x}")
        return device_auth_parse(body, link.transcript_prefix, link.km)

    # 1 + 2: both send their DEVICE_ID (device first, fixed order)
    if is_device:
        send_id()
        peer = recv_id()
    else:
        peer = recv_id()
        send_id()

    # 3 + 4: device decides first, then host. A rejecting decision is
    # fatal: send it, then raise (the peer raises on receipt).
    if is_device:
        decision = trust.decide(peer["identity_pub"], peer["device_id"])
        if decision == DECISION_THROTTLED:
            raise ValueError("peer pairing throttled")
        send_auth(decision, session_id)
        if decision == DECISION_REVOKED:
            raise ValueError("device revoked host identity")
        auth = recv_auth()
        if auth["decision"] in (DECISION_REVOKED, DECISION_THROTTLED):
            raise ValueError(f"rejected by host: decision={auth['decision']}")
        if auth["decision"] not in (DECISION_TRUSTED, DECISION_TRUSTED_NEW):
            raise ValueError(f"bad decision {auth['decision']}")
    else:
        auth_dev = recv_auth()
        if auth_dev["decision"] in (DECISION_REVOKED, DECISION_THROTTLED):
            # device declined the host: confirm and stop
            send_auth(DECISION_REVOKED, session_id)
            raise ValueError("host declined by device")
        decision = trust.decide(peer["identity_pub"], peer["device_id"])
        if decision == DECISION_THROTTLED:
            send_auth(DECISION_THROTTLED, session_id)
            raise ValueError("pairing throttled")
        send_auth(decision, session_id)
        if decision == DECISION_REVOKED:
            raise ValueError("host revoked device identity")

    trust.note_trusted(peer["identity_pub"], peer["device_id"],
                       peer.get("name"), peer.get("platform"),
                       peer.get("app_ver"), peer.get("caps", 0))
    return {"device_id": peer["device_id"], "session_id": session_id,
            "trusted": True, "peer": peer}
