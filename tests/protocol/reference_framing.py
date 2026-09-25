#!/usr/bin/env python3
"""UniLink Protocol (ULP) v1 - pure-stdlib Python reference implementation.

Conformance reference for docs/02-PROTOCOL.md. Stdlib only, runs anywhere.
The Rust crate, Kotlin device codec and Node/TS codec must all agree with
this file and with protocol/vectors/*.json.

Contains:
  * X25519 (affine Montgomery ladder; validated against RFC 7748 sec 6.1)
  * HKDF-SHA256 (RFC 5869)
  * INTEROP cipher profile (SHA256-CTR keystream + HMAC-SHA256, ETM)
  * Frame encode/decode (extended length, flags)
  * All CONTROL messages + channel payload codecs
  * Pairing blob + HELLO/HELLO_ACK builders and verifiers

Conformance tooling, not a production runtime: production host/device use
Rust / Kotlin with AES-256-GCM or ChaCha20-Poly1305.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct

# ---------------------------------------------------------------- constants
MAGIC0 = 0x55
MAGIC1 = 0x4C
VERSION = 0x01

CH_CONTROL = 0x00
CH_VIDEO = 0x01
CH_AUDIO_IN = 0x02
CH_AUDIO_OUT = 0x03
CH_INPUT = 0x04
CH_FILE = 0x05
CH_CLIPBOARD = 0x06
CH_NOTIFICATION = 0x07
CH_STATS = 0x08
CH_TUN_V4 = 0x09
CH_TUN_V6 = 0x0A
CH_PROXY = 0x0B
CH_CAMERA = 0x0C
CH_USER = 0x0D

F_COMPRESSED = 0x01
F_ENCRYPTED = 0x02
F_FRAG = 0x04
F_PRIORITY = 0x08
F_ACK = 0x10

MAX_PAYLOAD = 0x00100000  # 1 MiB (extended length)

CIPHER_NONE = 0
CIPHER_INTEROP = 1
CIPHER_AESGCM = 2
CIPHER_CHACHA = 3

ROLE_HOST = 0
ROLE_DEVICE = 1

FEAT_DUAL_STACK = 1 << 0
FEAT_VIDEO = 1 << 1
FEAT_AUDIO = 1 << 2
FEAT_INPUT = 1 << 3
FEAT_PROD = 1 << 4
FEAT_PROXY = 1 << 5
FEAT_CAMERA = 1 << 6
FEAT_QOS = 1 << 7

AUTH_INFO = b"unilink-auth-v1"
HKDF_INFO = b"unilink-v1"


class ProtocolError(Exception):
    """Fatal protocol violation (tear down the session)."""


class FramingError(ProtocolError):
    pass


class AuthError(ProtocolError):
    pass


# ---------------------------------------------------------------- X25519
_P = 2 ** 255 - 19
_A24 = 486662


def _mont_sqrt(c: int) -> int:
    """Square root in F_p where p = 2^255 - 19 (p == 5 mod 8)."""
    c %= _P
    if c == 0:
        return 0
    w = pow(c, (_P + 3) // 8, _P)
    if (w * w) % _P == c:
        return w
    w = (w * pow(2, (_P - 1) // 4, _P)) % _P
    if (w * w) % _P == c:
        return w
    raise ValueError("no square root")


def _mont_from_x(x: int):
    x %= _P
    y2 = (x * x * x + _A24 * x * x + x) % _P
    return (x, _mont_sqrt(y2))


def _mont_double(p):
    if p is None:
        return None
    x1, y1 = p
    if y1 == 0:
        return None
    num = (3 * x1 * x1 + 2 * _A24 * x1 + 1) % _P
    den = (2 * y1) % _P
    lam = (num * pow(den, _P - 2, _P)) % _P
    x3 = (lam * lam - _A24 - 2 * x1) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _mont_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if x1 == x2 and y1 == y2:
        return _mont_double(p)
    lam = ((y2 - y1) * pow((x2 - x1) % _P, _P - 2, _P)) % _P
    x3 = (lam * lam - _A24 - x1 - x2) % _P
    y3 = (lam * (x1 - x3) - y1) % _P
    return (x3, y3)


def _mont_mul(k: int, pt) -> bytes:
    result = None
    for bit in range(255, -1, -1):
        result = _mont_double(result)
        if (k >> bit) & 1:
            result = _mont_add(result, pt)
    if result is None:
        return b"\x00" * 32
    return result[0].to_bytes(32, "little")


def _clamp_x25519(secret: bytes) -> int:
    """RFC 7748 sec 5 scalar clamping:
    clear the three least significant bits, clear the most significant
    bit of the last byte (bit 255), set the second most significant bit
    of the last byte (bit 254). Result = 2^254 + 8 * k'."""
    k = int.from_bytes(secret, "little")
    k &= ~7
    k &= ~(1 << 255)
    k |= 1 << 254
    return k


def x25519(secret: bytes, peer_pub: bytes) -> bytes:
    """X25519 ECDH; inputs/outputs 32-byte little-endian."""
    if len(secret) != 32 or len(peer_pub) != 32:
        raise ValueError("x25519: keys must be 32 bytes")
    k = _clamp_x25519(secret)
    x1 = int.from_bytes(peer_pub, "little") % _P
    if x1 == 0:
        return b"\x00" * 32
    return _mont_mul(k, _mont_from_x(x1))


def x25519_public(secret: bytes) -> bytes:
    k = _clamp_x25519(secret)
    return _mont_mul(k, _mont_from_x(9))


# RFC 7748 sec 6.1 vector - guarantees implementation correctness.
RFC7748_ALICE_PRIV = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
RFC7748_BOB_PRIV = bytes.fromhex(
    "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
RFC7748_ALICE_PUB = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
RFC7748_SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")


def rfc7748_check() -> bool:
    ap = x25519_public(RFC7748_ALICE_PRIV)
    bp = x25519_public(RFC7748_BOB_PRIV)
    ab = x25519(RFC7748_ALICE_PRIV, bp)
    ba = x25519(RFC7748_BOB_PRIV, ap)
    return ap == RFC7748_ALICE_PUB and ab == ba == RFC7748_SHARED


# ---------------------------------------------------------------- HKDF
def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if length > 255 * 32:
        raise ValueError("hkdf: length too large")
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    out = b""
    block = b""
    for i in range(1, (length + 31) // 32 + 1):
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
    return out[:length]


# ------------------------------------------- INTEROP cipher (conformance)
def interop_keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    ks = b""
    i = 0
    while len(ks) < n:
        ks += hashlib.sha256(key + nonce + i.to_bytes(4, "big")).digest()
        i += 1
    return ks[:n]


def interop_encrypt(key_aead, key_mac, nonce, aad, pt) -> bytes:
    """Encrypt-then-MAC: returns ciphertext || tag(16)."""
    ct = bytes(a ^ b for a, b in zip(pt, interop_keystream(key_aead, nonce, len(pt))))
    tag = hmac.new(key_mac, nonce + aad + ct, hashlib.sha256).digest()[:16]
    return ct + tag


def interop_decrypt(key_aead, key_mac, nonce, aad, ct_tag) -> bytes:
    if len(ct_tag) < 16:
        raise AuthError("interop: ciphertext too short")
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    expect = hmac.new(key_mac, nonce + aad + ct, hashlib.sha256).digest()[:16]
    if not hmac.compare_digest(tag, expect):
        raise AuthError("interop: tag mismatch")
    return bytes(a ^ b for a, b in zip(ct, interop_keystream(key_aead, nonce, len(ct))))


# ---------------------------------------------------------------- framing
class Frame:
    __slots__ = ("channel", "flags", "payload")

    def __init__(self, channel: int, flags: int, payload: bytes):
        self.channel = channel
        self.flags = flags & 0xFF
        self.payload = payload

    @property
    def header_bytes(self) -> bytes:
        n = len(self.payload)
        head = bytes([MAGIC0, MAGIC1, VERSION, self.channel, self.flags])
        if n >= 0x8000:
            return head + (0x8000).to_bytes(2, "big") + n.to_bytes(4, "big")
        return head + n.to_bytes(2, "big")

    def encode(self) -> bytes:
        if not 0 <= self.channel <= 0xFF:
            raise FramingError("channel out of range")
        if len(self.payload) > MAX_PAYLOAD:
            raise FramingError("payload too large")
        return self.header_bytes + self.payload

    @classmethod
    def decode(cls, data: bytes, off: int = 0) -> "Frame":
        if len(data) - off < 8:
            raise FramingError("short header")
        m0, m1 = data[off], data[off + 1]
        ver, ch, flg = data[off + 2], data[off + 3], data[off + 4]
        ln = int.from_bytes(data[off + 5:off + 7], "big")
        if m0 != MAGIC0 or m1 != MAGIC1:
            raise FramingError(f"bad magic {m0:02x}{m1:02x}")
        if ver != VERSION:
            raise FramingError(f"unsupported version {ver}")
        if 0x8001 <= ln <= 0xFFFF:
            raise FramingError(f"invalid length field {ln:04x}")
        if ln == 0x8000:
            if len(data) - off < 11:
                raise FramingError("short extended length")
            ext = int.from_bytes(data[off + 7:off + 11], "big")
            if ext > MAX_PAYLOAD:
                raise FramingError("extended length too large")
            header_len, size = 11, ext
        else:
            header_len, size = 7, ln
        if len(data) - off < header_len + size:
            raise FramingError("incomplete frame")
        return cls(ch, flg, data[off + header_len:off + header_len + size])


def frame_nonce(counter: int, channel: int, direction: int) -> bytes:
    """12-byte nonce: u64be(dir bit || counter) || u32be(channel)."""
    hi = ((1 & direction) << 63) | (counter & ((1 << 63) - 1))
    return hi.to_bytes(8, "big") + (channel & 0xFFFFFFFF).to_bytes(4, "big")


# ---------------------------------------------------------------- CONTROL
MSG_HELLO = 0x01
MSG_HELLO_ACK = 0x02
MSG_AUTH_OK = 0x04
MSG_PING = 0x05
MSG_PONG = 0x06
MSG_CONFIG = 0x07
MSG_TUN_UP = 0x08
MSG_TUN_DOWN = 0x09
MSG_STATS_REQ = 0x0A
MSG_STATS_RSP = 0x0B
MSG_MUTE = 0x0C
MSG_QOS = 0x0D
MSG_RESUME = 0x0E
MSG_BYE = 0x0F
MSG_ERROR = 0x10


def msg_encode(mtype: int, body: bytes) -> bytes:
    return bytes([mtype, 0x00]) + len(body).to_bytes(2, "big") + body


def msg_decode(payload: bytes) -> tuple:
    if len(payload) < 4:
        raise FramingError("short message")
    mtype, flags = payload[0], payload[1]
    blen = int.from_bytes(payload[2:4], "big")
    if len(payload) < 4 + blen:
        raise FramingError("short message body")
    return mtype, flags, payload[4 : 4 + blen]


def pairing_mac(secret: bytes, ecdh_pub: bytes, nonce: bytes) -> bytes:
    return hmac.new(secret, AUTH_INFO + ecdh_pub + nonce, hashlib.sha256).digest()


def hello_body(role, feature_mask, cipher_pref, ecdh_pub, nonce_a):
    return (bytes([role]) + feature_mask.to_bytes(2, "big")
            + bytes([cipher_pref]) + ecdh_pub + nonce_a)


def hello_verify(body: bytes, secret: bytes) -> dict:
    if len(body) != 84:
        raise AuthError(f"hello: bad length {len(body)}")
    role, feature_mask = body[0], int.from_bytes(body[1:3], "big")
    cipher_pref, ecdh_pub, nonce_a = body[3], body[4:36], body[36:52]
    mac = body[52:84]
    if not hmac.compare_digest(mac, pairing_mac(secret, ecdh_pub, nonce_a)):
        raise AuthError("hello: pairing mac mismatch")
    return {"role": role, "feature_mask": feature_mask,
            "cipher_pref": cipher_pref, "ecdh_pub": ecdh_pub,
            "nonce_a": nonce_a}


def hello_ack_body(negotiated, cipher_sel, ecdh_pub, nonce_b, nonce_a, secret):
    mac = hmac.new(secret, AUTH_INFO + ecdh_pub + nonce_b + nonce_a,
                   hashlib.sha256).digest()
    return (negotiated.to_bytes(2, "big") + bytes([cipher_sel])
            + ecdh_pub + nonce_b + mac)


def hello_ack_verify(body: bytes, secret: bytes, nonce_a: bytes) -> dict:
    if len(body) != 83:
        raise AuthError(f"hello_ack: bad length {len(body)}")
    negotiated = int.from_bytes(body[0:2], "big")
    cipher_sel = body[2]
    ecdh_pub, nonce_b = body[3:35], body[35:51]
    mac = body[51:83]
    expect = hmac.new(secret, AUTH_INFO + ecdh_pub + nonce_b + nonce_a,
                      hashlib.sha256).digest()
    if not hmac.compare_digest(mac, expect):
        raise AuthError("hello_ack: pairing mac mismatch")
    return {"negotiated": negotiated, "cipher_sel": cipher_sel,
            "ecdh_pub": ecdh_pub, "nonce_b": nonce_b}


def session_keys(shared: bytes, nonce_a: bytes, nonce_b: bytes,
                 cipher_sel: int):
    keys = hkdf_sha256(shared, nonce_a + nonce_b,
                       HKDF_INFO + bytes([cipher_sel]), 64)
    return keys[0:32], keys[32:64]


def config_body(v4_prefix, v4_device, v4_host, v6_prefix=0,
                v6_device=b"\x00" * 16, v6_host=b"\x00" * 16,
                dns=None, routes=None):
    b = (bytes([v4_prefix & 0xFF]) + v4_device + v4_host
         + bytes([v6_prefix & 0xFF]))
    if v6_prefix > 0:
        b += v6_device + v6_host
    dns = dns or []
    routes = routes or []
    b += len(dns).to_bytes(2, "big")
    for d in dns:
        b += d
    b += len(routes).to_bytes(2, "big")
    for r in routes:
        b += bytes([r[0] & 0xFF]) + r[1]
    return b


def config_parse(body: bytes) -> dict:
    off = 0
    v4_prefix = body[off]; off += 1
    v4_device = body[off:off + 4]; off += 4
    v4_host = body[off:off + 4]; off += 4
    v6_prefix = body[off]; off += 1
    v6_device, v6_host = b"\x00" * 16, b"\x00" * 16
    if v6_prefix > 0:
        if len(body) < off + 32:
            raise FramingError("config: short v6 addrs")
        v6_device = body[off:off + 16]; off += 16
        v6_host = body[off:off + 16]; off += 16
    dns_count = int.from_bytes(body[off:off + 2], "big"); off += 2
    dns = [body[off + 4 * i: off + 4 * (i + 1)] for i in range(dns_count)]
    off += 4 * dns_count
    route_count = int.from_bytes(body[off:off + 2], "big"); off += 2
    routes = []
    for _ in range(route_count):
        prefix = body[off]
        routes.append((prefix, body[off + 1:off + 5]))
        off += 5
    return {"v4_prefix": v4_prefix, "v4_device": v4_device,
            "v4_host": v4_host, "v6_prefix": v6_prefix,
            "v6_device": v6_device, "v6_host": v6_host,
            "dns": dns, "routes": routes}


def stats_body(bytes_in=0, bytes_out=0, pkts_in=0, pkts_out=0,
               bytes_video=0, bytes_audio=0, bytes_file=0, drops=0,
               errors=0, frames_video=0, rtt_ms=0, loss_pct_x100=0,
               cpu_pct_x100=0, fps_video=0, audio_level=0):
    u64 = lambda v: v.to_bytes(8, "big")
    u32 = lambda v: v.to_bytes(4, "big")
    return (u64(bytes_in) + u64(bytes_out) + u64(pkts_in)
            + u64(pkts_out) + u64(bytes_video) + u64(bytes_audio)
            + u64(bytes_file) + u64(drops) + u64(errors)
            + u64(frames_video) + u32(rtt_ms) + u32(loss_pct_x100)
            + u32(cpu_pct_x100) + u32(fps_video) + u32(audio_level)
            + u32(0))


def stats_parse(body: bytes) -> dict:
    if len(body) != 104:
        raise FramingError(f"stats: bad length {len(body)}")
    v = struct.unpack(">10Q6I", body)
    return {"bytes_in": v[0], "bytes_out": v[1], "pkts_in": v[2],
            "pkts_out": v[3], "bytes_video": v[4], "bytes_audio": v[5],
            "bytes_file": v[6], "drops": v[7], "errors": v[8],
            "frames_video": v[9], "rtt_ms": v[10],
            "loss_pct_x100": v[11], "cpu_pct_x100": v[12],
            "fps_video": v[13], "audio_level": v[14]}


def qos_body(profile, up_kbps, down_kbps, latency_ms, jitter_ms, loss_pct):
    return (bytes([profile & 0xFF]) + up_kbps.to_bytes(4, "big")
            + down_kbps.to_bytes(4, "big") + latency_ms.to_bytes(2, "big")
            + bytes([jitter_ms & 0xFF, loss_pct & 0xFF]))


def qos_parse(body: bytes) -> dict:
    if len(body) != 13:
        raise FramingError("qos: bad length")
    return {"profile": body[0],
            "up_kbps": int.from_bytes(body[1:5], "big"),
            "down_kbps": int.from_bytes(body[5:9], "big"),
            "latency_ms": int.from_bytes(body[9:11], "big"),
            "jitter_ms": body[11], "loss_pct": body[12]}


# --------------------------------------------------------- channel codecs
def video_body(kind, codec, width, height, fps, pts_ms, seq, nal):
    return (bytes([kind & 0xFF, codec & 0xFF]) + width.to_bytes(2, "big")
            + height.to_bytes(2, "big") + bytes([fps & 0xFF])
            + pts_ms.to_bytes(4, "big") + seq.to_bytes(4, "big") + nal)


def video_parse(body: bytes) -> dict:
    if len(body) < 15:
        raise FramingError("video: short")
    return {"kind": body[0], "codec": body[1],
            "width": int.from_bytes(body[2:4], "big"),
            "height": int.from_bytes(body[4:6], "big"), "fps": body[6],
            "pts_ms": int.from_bytes(body[7:11], "big"),
            "seq": int.from_bytes(body[11:15], "big"), "nal": body[15:]}


def audio_body(codec, rate, ch, seq, pts_ms, data):
    return (bytes([codec & 0xFF]) + rate.to_bytes(2, "big")
            + bytes([ch & 0xFF]) + seq.to_bytes(4, "big")
            + pts_ms.to_bytes(4, "big") + data)


def audio_parse(body: bytes) -> dict:
    if len(body) < 12:
        raise FramingError("audio: short")
    return {"codec": body[0], "rate": int.from_bytes(body[1:3], "big"),
            "ch": body[3], "seq": int.from_bytes(body[4:8], "big"),
            "pts_ms": int.from_bytes(body[8:12], "big"), "data": body[12:]}


def input_body(type_, action, x, y, key=0, text=b""):
    return (bytes([type_ & 0xFF, action & 0xFF]) + x.to_bytes(2, "big")
            + y.to_bytes(2, "big") + key.to_bytes(2, "big")
            + len(text).to_bytes(2, "big") + text)


def input_parse(body: bytes) -> dict:
    if len(body) < 10:
        raise FramingError("input: short")
    t, a = body[0], body[1]
    x = int.from_bytes(body[2:4], "big")
    y = int.from_bytes(body[4:6], "big")
    key = int.from_bytes(body[6:8], "big")
    tl = int.from_bytes(body[8:10], "big")
    if len(body) < 10 + tl:
        raise FramingError("input: short text")
    return {"type": t, "action": a, "x": x, "y": y, "key": key,
            "text": body[10:10 + tl].decode("utf-8", "replace")}


def file_meta_body(direction, file_id, total_size, name):
    nb = name.encode("utf-8")
    return (bytes([0x00, direction & 0xFF]) + file_id.to_bytes(4, "big")
            + total_size.to_bytes(8, "big") + len(nb).to_bytes(2, "big") + nb)


def file_data_body(direction, file_id, seq, offset, chunk):
    return (bytes([0x01, direction & 0xFF]) + file_id.to_bytes(4, "big")
            + seq.to_bytes(4, "big") + offset.to_bytes(8, "big") + chunk)


def file_parse(body: bytes) -> dict:
    if len(body) < 6:
        raise FramingError("file: short")
    op, direction = body[0], body[1]
    file_id = int.from_bytes(body[2:6], "big")
    d = {"op": op, "direction": direction, "file_id": file_id}
    if op == 0x00:
        d["total_size"] = int.from_bytes(body[6:14], "big")
        nl = int.from_bytes(body[14:16], "big")
        d["name"] = body[16:16 + nl].decode("utf-8", "replace")
    elif op == 0x01:
        d["seq"] = int.from_bytes(body[6:10], "big")
        d["offset"] = int.from_bytes(body[10:18], "big")
        d["chunk"] = body[18:]
    elif op == 0x02:
        d["seq_ack"] = int.from_bytes(body[6:10], "big")
    return d


def clipboard_body(direction, kind, data):
    return bytes([direction & 0xFF, kind & 0xFF]) + data


def clipboard_parse(body: bytes) -> dict:
    if len(body) < 2:
        raise FramingError("clipboard: short")
    return {"direction": body[0], "kind": body[1],
            "data": body[2:].decode("utf-8", "replace")}


def notification_body(nid, ts_ms, action, app, title, body_):
    a = app.encode("utf-8")
    t = title.encode("utf-8")
    b = body_.encode("utf-8")
    return (nid.to_bytes(4, "big") + ts_ms.to_bytes(8, "big")
            + bytes([action & 0xFF]) + len(a).to_bytes(2, "big") + a
            + len(t).to_bytes(2, "big") + t + len(b).to_bytes(2, "big") + b)


def notification_parse(body: bytes) -> dict:
    off = 0
    nid = int.from_bytes(body[off:off + 4], "big"); off += 4
    ts = int.from_bytes(body[off:off + 8], "big"); off += 8
    action = body[off]; off += 1
    out = {"id": nid, "ts_ms": ts, "action": action}
    for key in ("app", "title", "body"):
        l = int.from_bytes(body[off:off + 2], "big"); off += 2
        out[key] = body[off:off + l].decode("utf-8", "replace")
        off += l
    return out


# ------------------------------------------------------------- pairing
def pairing_blob(secret: bytes, name: str) -> str:
    nb = name.encode("utf-8")[:32]
    return ("UNITETHER1:"
            + base64.urlsafe_b64encode(secret).decode("ascii")
            + "|" + nb.decode("utf-8"))


def pairing_parse(blob: str):
    if not blob.startswith("UNITETHER1:"):
        raise ValueError("bad pairing blob prefix")
    rest = blob[len("UNITETHER1:"):]
    b64, _, name = rest.partition("|")
    secret = base64.urlsafe_b64decode(b64.encode("ascii"))
    if len(secret) != 32:
        raise ValueError("bad pairing secret length")
    return secret, name


# ------------------------------------------------------------- handshake
class Handshake:
    """Stateless helpers for the ULP handshake (both roles).

    Both sides: shared = x25519(priv_own, pub_peer)
    keys = hkdf_sha256(shared, nonce_a || nonce_b, "unilink-v1" || cipher)
    """

    @staticmethod
    def derive(secret: bytes, priv: bytes, peer_pub: bytes,
               nonce_a: bytes, nonce_b: bytes, cipher_sel: int):
        shared = x25519(priv, peer_pub)
        return session_keys(shared, nonce_a, nonce_b, cipher_sel)
