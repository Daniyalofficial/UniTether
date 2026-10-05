# 02 — UniLink Protocol (ULP) v1 — Specification

Status: **normative for v0.1.x**. All multi-byte integers are
**big-endian**. This document is the single source of truth; the
conformance vectors in `protocol/vectors/`, the Python reference
(`tests/protocol/reference_framing.py`), the Node codec
(`host/gui/src/lib/protocol.ts` + `tests/node/`) and the Rust crate
(`host/crates/protocol/`) must all agree with it (CI enforces).

## 1. Scope & transport assumptions

ULP is a **channel-multiplexed byte protocol** designed to run over any
reliable byte stream (TCP over ADB-USB, LAN TCP, Wi-Fi Direct TCP,
BT-PAN TCP). It is *not* a transport protocol: no ACKs, no reordering —
reliability and ordering come from the underlying stream. Lossy
media over UDP is ULP v1.1 (reserved).

Two endpoints: **role 0 = host**, **role 1 = device**. One session per
transport connection.

## 2. Frame format

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  magic0=0x55  |  magic1=0x4C  |    version    |   channel     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     flags     |                     length                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       payload (length bytes)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

| Field | Size | Value |
|---|---|---|
| `magic0` | 1 B | `0x55` |
| `magic1` | 1 B | `0x4C` |
| `version` | 1 B | `0x01` |
| `channel` | 1 B | see §3 |
| `flags` | 1 B | see §4 |
| `length` | 2 B | payload length; `0x0000–0x7FFF` direct. `0x8000` = *extended length*: the next 4 bytes (BE) hold the length, `0x00000000–0x00100000` (1 MiB max). `0x8001–0xFFFF` = invalid. |
| `payload` | var | `length` bytes; contents per channel (§5–§6) |

Base header = **7 bytes**; extended header = **11 bytes** (the extra 4-byte length field).

### 2.1 Length rule (normative)
- `length < 0x8000` → payload is exactly `length` bytes.
- `length == 0x8000` → read 4 more bytes `L`; payload is `L` bytes;
  `L` must be `≤ 0x00100000`.
- any other 2-byte value in `0x8001–0xFFFF` → **protocol error**, tear down.

## 3. Channels

| Code | Name | Direction | Payload |
|---|---|---|---|
| `0x00` | CONTROL | both | messages, §6 |
| `0x01` | VIDEO | device→host | §5.1 |
| `0x02` | AUDIO_IN | device→host | §5.2 |
| `0x03` | AUDIO_OUT | host→device | §5.2 |
| `0x04` | INPUT | host→device | §5.3 |
| `0x05` | FILE | both | §5.4 |
| `0x06` | CLIPBOARD | both | §5.5 |
| `0x07` | NOTIFICATION | device→host | §5.6 |
| `0x08` | STATS | both | §5.7 |
| `0x09` | TUN_V4 | both | raw IPv4 packet, no header |
| `0x0A` | TUN_V6 | both | raw IPv6 packet, no header |
| `0x0B` | PROXY | both | §5.8 |
| `0x0C` | CAMERA | device→host | §5.1 layout, codec `0x03`=MJPEG |
| `0x0D` | USER | both | reserved |
| `0x0E–0x7F` | — | — | reserved |
| `0x80–0xFF` | — | — | experimental (must not be used by stable builds) |

Direction rules are enforced: receiving a payload-bearing frame on a
wrong-direction channel is a protocol error (CONTROL/FILE/CLIPBOARD/
STATS/PROXY are bidirectional).

## 4. Frame flags

| Bit | Name | Meaning |
|---|---|---|
| `0x01` | COMPRESSED | payload is a zstd frame (RFC 8878) of the original payload |
| `0x02` | ENCRYPTED | payload is AEAD ciphertext (see §7); 16-byte tag included at end |
| `0x04` | FRAG | payload begins with `u16 frag_seq` (0-based) of a reassembled logical payload; receiver reassembles in seq order until the reassembler buffer is full (max 1 MiB) |
| `0x08` | PRIORITY | scheduler hint: process ahead of normal traffic |
| `0x10` | ACK | (reserved) in-band acknowledgment |
| `0xE0–0x30` | — | reserved |

- Pre-handshake: only CONTROL frames with `flags = 0x00` are allowed.
- Post-handshake: **all** frames MUST be `ENCRYPTED`. A non-ENCRYPTED
  frame after handshake is a fatal protocol error.
- `COMPRESSED` + `ENCRYPTED`: compress first, then encrypt.
- v1.0 reference implementations use extended length instead of
  fragmentation; FRAG is normative for interop but optional to send.

## 5. Channel payloads

### 5.1 VIDEO / CAMERA (device→host)
```
offset size field
0      1    kind      0x00 keyframe, 0x01 delta, 0x02 end-of-stream
1      1    codec     0x00 H.264, 0x01 HEVC, 0x02 AV1, 0x03 MJPEG (CAMERA only)
2      2    width     pixels
4      2    height    pixels
6      1    fps       frames per second (target)
7      4    pts_ms    presentation time, ms since session start
11     4    seq       monotonically increasing, u32
15     N    nal       raw NAL units (H.264/HEVC) or OBU (AV1) or JPEG bytes
```

### 5.2 AUDIO (both directions)
```
0   1    codec    0x00 Opus, 0x01 AAC-ADTS, 0x02 PCM s16le
1   2    rate     sample rate (48000)
3   1    ch       channel count
4   4    seq      u32
8   4    pts_ms   ms
12  N    data
```

### 5.3 INPUT (host→device)
```
0   1    type   0x00 touch, 0x01 key, 0x02 mouse, 0x03 text
1   1    action 0x00 down, 0x01 up, 0x02 move
2   2    x      normalized 0–1000 (touch/mouse)
4   2    y      normalized 0–1000
6   2    key    Android keycode (type=0x01) or 0
8   2    text_len
10  N    utf8   (type=0x03 only; text_len=0 otherwise)
```

### 5.4 FILE (both directions)
```
common:
0   1    op        0x00 meta, 0x01 data, 0x02 ack, 0x03 cancel, 0x04 done,
                   0x05 resume_req, 0x06 resume_rsp, 0x07 checksum  [v2]
1   1    direction 0x00 host→device, 0x01 device→host
2   4    file_id   session-scoped u32
per-op:
meta:   6  8  total_size
        14 2  name_len ; 16 N utf8 name
data:   6  4  seq ; 10 8 offset ; 18 N chunk (≤ 256 KiB)
ack:    6  4  seq_ack   (checksum ack uses seq_ack = 0xFFFF)
cancel/done: nothing
resume_req: 6  8  expected_offset                                [v2]
resume_rsp: 6  8  offset ; 14 1 state (0 none | 1 partial | 2 complete) [v2]
checksum:   6 32  sha256 of the full file                        [v2]
```

**v2 transfer protocol** (backward compatible: v1 peers ignore
0x05–0x07 by the unknown-op rule; golden vectors in
`protocol/vectors/file_vectors.json`; reference engine in
`tests/protocol/file_transfer.py`, conformance ports in
`tests/node/fileV2.mjs` and `productivity/FileTransfer.kt`):

1. Sender → `meta`, then `resume_req(expected_offset=0)`.
2. Receiver → `resume_rsp(offset, state)`. `state=2` (complete,
   including duplicate skip: same bare name + total size) ends the
   transfer with zero data. `state=1` resumes at the receiver's
   contiguous `.part` offset.
3. Chunked `data` (ack per chunk) from that offset.
4. Sender → `done`, then `checksum(sha256)`.
5. Receiver verifies the hash over its `.part`:
   - match → **atomic commit** (`.part` renamed to final name;
     collisions pre-reserved with `.1/.2` suffixes at `meta` time)
     → `ack(seq_ack=0xFFFF)`.
   - mismatch → delete `.part`, log, `cancel` → sender restarts
     from 0 (bounded: the file is reset, so it converges).

Integrity is whole-file SHA-256 (system/audited digest); no per-chunk
MAC is added — the channel is already AEAD-protected per frame.

### 5.5 CLIPBOARD (both directions)
```
0  1    direction 0x00 device→host, 0x01 host→device
1  1    kind      0x00 text(plain utf8), 0x01 html, 0x02 image(png)
2  N    data
```

### 5.6 NOTIFICATION (device→host)
```
0  4   id
4  8   ts_ms
12 1   action   0x00 post, 0x01 clear
13 2   app_len ; 15 N app package utf8
15+N 2 title_len ; … title utf8
…    2 body_len  ; … body utf8
```

### 5.7 STATS — fixed 104-byte struct `StatCounters`
```
offset size field
0    8  bytes_in        tunnel bytes received by this endpoint (from peer)
8    8  bytes_out       tunnel bytes sent
16   8  pkts_in
24   8  pkts_out
32   8  bytes_video     video channel payload bytes
40   8  bytes_audio
48   8  bytes_file
56   8  drops           frames dropped (QoS/queue overflow)
64   8  errors          AEAD/protocol errors
72   8  frames_video
80   4  rtt_ms          last measured RTT
84   4  loss_pct_x100   50 = 0.50 %
88   4  cpu_pct_x100    endpoint CPU (0 if unknown)
92   4  fps_video
96   4  audio_level     0–255 RMS
100  4  reserved0
104? — end (total = 104 bytes)
```

### 5.8 PROXY (both directions)
First frame of a stream carries the header; subsequent frames are raw:
```
0   1    direction 0x00 host→device, 0x01 device→host
1   4    stream_id
4   2    target_port BE
6   1    target_family 4 / 6
7   4|16 target address
…  N    initial payload (may be empty)
later frames on same stream: 1 B direction, 4 B stream_id, payload
```

### 5.9 TUN_V4 / TUN_V6
Payload **is** the raw IP packet. No header. This is what makes
ICMP/traceroute/dual-stack trivial: whatever the host kernel IP stack
does, the device VPN does the same.

## 6. CONTROL messages

CONTROL payload = message:
```
0   1    type
1   1    msg_flags   (reserved, 0x00)
2   2    body_len
4   N    body
```

| Type | Name | Body | Sent by |
|---|---|---|---|
| `0x01` | HELLO | §7.2 | initiator (usually host) |
| `0x02` | HELLO_ACK | §7.2 | responder (usually device) |
| `0x04` | AUTH_OK | empty | both, after verify |
| `0x05` | PING | `u64 tstamp_ms` | both (2 s cadence) |
| `0x06` | PONG | `u64 tstamp_ms` (echo) | both |
| `0x07` | CONFIG | §7.3 | host |
| `0x08` | TUN_UP | empty | both |
| `0x09` | TUN_DOWN | empty | both |
| `0x0A` | STATS_REQ | empty | both |
| `0x0B` | STATS_RSP | `StatCounters` (104 B) | both |
| `0x0C` | MUTE | `u8 mask`: b0 video, b1 audio_in, b2 audio_out, b3 input (1=muted) | both |
| `0x0D` | QOS | §7.4 | both |
| `0x0E` | RESUME | `u64 session_id` | rejoiner (v1.1) |
| `0x0F` | BYE | `u8 reason` (0 normal, 1 error, 2 user, 3 superseded) | both |
| `0x10` | ERROR | `u8 code, u16 text_len, utf8 text` | both |

Unknown message types MUST be ignored (forward compat); unknown
`type & 0x80` = reserved-experimental, also ignored.

## 7. Handshake & security

### 7.1 Pairing blob
QR payload (and manual code):
```
UNITETHER1:<base64url(pairing_secret[32])>|<utf8 device name ≤ 32 B>
```
`pairing_secret` = 32 uniform random bytes (device generates; the QR is
generated by the *host* only when the device cannot display a QR — the
canonical flow is: device generates the secret, shows its own QR, host
scans).

### 7.2 HELLO / HELLO_ACK
```
HELLO body:
0    1    role            0x00 host, 0x01 device
1    2    feature_mask    u16 (bit 0 = dual_stack, bit 1 = video,
                          bit 2 = audio, bit 3 = input, bit 4 = prod,
                          bit 5 = proxy, bit 6 = camera, bit 7 = qos)
3    1    cipher_pref     best supported cipher profile (§7.5)
4    32   ecdh_pub        X25519 public key
36   16   nonce_a
52   32   pairing_mac     HMAC-SHA256(pairing_secret,
                           "unilink-auth-v1" || ecdh_pub || nonce_a)
→ 84 bytes

HELLO_ACK body:
0    2    negotiated      feature_mask AND
2    1    cipher_sel      chosen cipher profile (≤ both prefs)
3    32   ecdh_pub        responder's
39   16   nonce_b
55   32   pairing_mac     HMAC-SHA256(pairing_secret,
                           "unilink-auth-v1" || ecdh_pub || nonce_b || nonce_a)
→ 83 bytes
```
The responder's mac chains `nonce_a` to bind the two messages
(anti-reflection). Verification failure ⇒ send `ERROR(code=11)` and
close.

### 7.3 CONFIG body
```
0    1   v4_prefix_len   (e.g. 20)
1    4   v4_device_addr  (10.8.0.2)
5    4   v4_host_addr    (10.8.0.1)
9    1   v6_prefix_len   (64) or 0 = no IPv6
10   16  v6_device_addr  (only if v6_prefix_len > 0)
…    16  v6_host_addr    (only if v6_prefix_len > 0)
…    2   dns_count ; then dns_count × 4B (IPv4 only in v1)
…    2   route_count ; then route_count × (1 B prefix + 4 B addr)
```
Default (when omitted): v4 10.8.0.0/20, v6 fd00:4c:55:01::/64,
DNS = host's primary resolver, route 0.0.0.0/0 (and `::/0` for v6).

### 7.4 QOS body
```
0   1   profile   0 none, 1 2G, 2 3G, 3 4G, 4 5G, 5 custom
1   4   up_kbps
5   4   down_kbps
9   2   latency_ms   one-way artificial delay added by receiver shaper
11  1   jitter_ms    max ±
12  1   loss_pct     0–99
```
Built-in profiles: 2G = 384/768 kbps + 120 ms + 2 % loss; 3G =
3000/5000 + 40 ms + 1 %; 4G = 30000/50000 + 15 ms; 5G = unlimited +
5 ms. `custom` uses the given fields. The *receiving* endpoint shapes
inbound tunnel traffic (so device-side QOS throttles what the device
sees, host-side QOS throttles what the host injects).

### 7.5 Cipher profiles
| Id | Name | AEAD | Availability |
|---|---|---|---|
| 0 | NONE | plaintext | handshake only; runtime use requires explicit `--insecure` (dev/testing) |
| 1 | INTEROP | SHA256-CTR keystream + HMAC-SHA256 (ETM, 16 B tag) | pure-stdlib conformance suites (Python/Node); **rejected by production builds** unless opted in |
| 2 | AES-256-GCM | 32 B key, 12 B nonce, 16 B tag | Rust `aes-gcm`, Android `javax.crypto` |
| 3 | CHACHA20-POLY1305 | 32 B key, 12 B nonce, 16 B tag | Rust `chacha20poly1305` |

Key derivation:
```
shared  = X25519(priv_own, pub_peer)
salt    = nonce_a || nonce_b           (32 B)
info    = "unilink-v1" || u8(cipher_sel)
keys    = HKDF-SHA256(ikm=shared, salt, info, L=64)
key_aead = keys[0..32]
key_mac  = keys[32..64]
```
Per-frame nonce (12 B): `u64be(direction_bit || session_counter) ‖ u32be(channel)`
where `session_counter` increments per encrypted frame per direction.
AEAD AAD = frame header bytes (magic…flags, including the 2-byte
length field) — binds channel/flags into authentication.

INTEROP profile details:
```
block_i   = SHA256(key_aead || nonce_12 || u32be(i))     (32 B, i = 0,1,2)
keystream = block_0 ‖ block_1 ‖ block_2 … as needed
ct        = pt XOR keystream
tag       = HMAC-SHA256(key_mac, nonce_12 || ct)[0..16]
wire      = ct ‖ tag
```

## 8. Conventions

- Timestamps: milliseconds since session start (u32 wraps at ~49.7 days;
  session restarts before that in practice).
- All names/text are UTF-8, length-prefixed in bytes.
- Endpoints MUST close the transport on any fatal protocol error and
  MUST send `BYE(reason=1)`/`ERROR` when they can.
- A receiver MUST tolerate: unknown reserved channels (drop), unknown
  message types (drop), PRIORITY on any channel (process first).

## 9. Versioning

`version` byte: 1 = this spec. A higher version with unknown features
is announced via `HELLO.version` (v1.1 will carry a `u8 minor` field in
HELLO). Interop rule: use the lower version's behavior; negotiate
features via `feature_mask`, never via framing.

---

## 15. ULP v1.1 extensions (backward compatible)

**Byte-stability rule:** v1 frames and messages keep their exact bytes
forever (all `protocol/vectors/*.json` remain the gate). v1.1 extends
by addition only (docs/21).

### 15.1 Version / capability negotiation

- Feature bit **`FEAT_VERSIONED = 1 << 8`** in the u16 HELLO feature
  mask (v1 peers use ≤ 0x00FF and ignore unknown bits).
- The negotiated feature field in HELLO_ACK decides: bit 8 set in
  `negotiated` ⇒ v1.1 identity exchange is MANDATORY; otherwise the
  session runs as pure v1 (no identity messages, zero byte changes).

### 15.2 Identity exchange (post-AUTH_OK, only if FEAT_VERSIONED)

Strict order (device first), each message MACed over the **wire
transcript** — exact bytes of all frames (header + payload, both
directions, local observation order) observed up to **before** the
current frame:

1. device → `MSG_DEVICE_ID (0x11)`, body 164 B:
   `device_id(16) ‖ identity_pub(32) ‖ name(64) ‖ platform(16) ‖ app_ver(16) ‖ caps(u32be) ‖ mac(16)`
   where `device_id = SHA256("unilink-dev-id-v1" ‖ identity_pub)[:16]`
   and `mac = HMAC-SHA256(key_mac, "unilink-dev-id-v1" ‖ transcript ‖ body[:148])[:16]`.
2. host → `MSG_DEVICE_ID` (its own identity).
3. device → `MSG_DEVICE_AUTH (0x12)`, body 49 B:
   `decision(1) ‖ session_id(16) ‖ sender_id(16) ‖ mac(16)`,
   `mac = HMAC-SHA256(key_mac, "unilink-dev-auth-v1" ‖ transcript ‖ body[:33])[:16]`.
4. host → `MSG_DEVICE_AUTH` (its decision about the device identity;
   carries the freshly generated 16-byte `session_id`).

`decision`: 0 TRUSTED, 1 TRUSTED_NEW, 2 REVOKED (fatal),
3 THROTTLED (fatal). A rejecting decision is fatal: sender raises
after sending; peer tears down on receipt. A v1.1 peer that negotiated
the feature and does not complete the exchange within 5 s must send
`MSG_ERROR(ERR_IDENTITY_REQUIRED)` and close (downgrade protection).

### 15.3 Session resumption

- `MSG_RESUME_REQ (0x0E)` (v1 reserved slot, format fixed by v1.1),
  body 80 B: `session_id(16) ‖ fresh_pub(32) ‖ resume_nonce(16) ‖ mac(16)`,
  `mac = HMAC-SHA256(pairing_secret, "unilink-resume-v1" ‖ body[:64])[:16]`.
  Keyed by the **pairing secret** (session keys are dead at resume time).
- `MSG_RESUME_OK (0x13)`, body 48 B: `fresh_pub(32) ‖ mac(16)`,
  `mac = HMAC-SHA256(pairing_secret, "unilink-resume-v1" ‖ session_id ‖ req_pub ‖ fresh_pub)[:16]`.
- Both sides: `shared = X25519(fresh_priv, peer_fresh_pub)`;
  `(key_aead, key_mac) = HKDF-SHA256(ikm=shared,
  salt=resume_nonce ‖ session_id, info="unilink-v1-resume" ‖ u8(cipher), 64)`;
  per-direction counters restart at 0 (fresh keys ⇒ nonce safety).
- Validity bounds (configurable): same pairing secret, ≤ 10 min since
  last frame, ≤ 50 resumptions, identity not revoked.
- After resume: channel state replays via existing CONFIG/TUN_UP/QOS;
  in-flight file transfers resume via `FILE_RESUME` (§16).

### 15.4 Structured errors

`MSG_ERROR` with message **flag 0x01** carries body
`fatal(1) ‖ code(u16be) ‖ len(u16be) ‖ msg(≤120)`; flag 0x00 keeps the
legacy opaque body. Codes: 0x0001 AUTH, 0x0002 CIPHER, 0x0003 VERSION,
0x0004 FORMAT, 0x0005 LIMIT, 0x0006 TIMEOUT, 0x0007 IDENTITY_REQUIRED,
0x0008 THROTTLED, 0x0009 REVOKED, 0x000A RESUME_INVALID,
0x000B UPGRADE_REQUIRED. `fatal=0` errors are logged, not fatal.

### 15.5 Conformance

Golden vectors: `protocol/vectors/v11.json` (generator
`tests/protocol/gen_v11_vectors.py`). Tests: `tests/protocol/test_v11.py`
(54 checks incl. in-process identity exchange + revocation),
`tests/protocol/test_v11_vectors.py` (23), Node `test.mjs` v1.1 section,
`tests/e2e/test_resume.py` (14, real TCP resume).
