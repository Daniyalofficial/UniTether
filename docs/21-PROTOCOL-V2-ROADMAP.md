# 21 — Protocol Versioning & ULP v2 Roadmap

Status: v1.1 spec **implemented in this delivery** (slices A4/A6); v2 is
**design only**.

## 1. Versioning rules (binding)

1. **Byte-stability.** ULP v1 frames/messages keep their exact bytes
   forever. All existing vectors remain the gate.
2. **Extension by addition only.** New capabilities arrive as: new
   message types in the free range, new feature bits, new channel IDs,
   new message-flags bits. Re-encoding existing bytes = protocol break.
3. **Negotiation before use.** A sender uses an extension only if the
   peer advertised the corresponding feature bit in a MACed HELLO.
4. **Unknown ≠ error.** Unknown message types (except the reserved
   0x7F–0xFF range), unknown feature bits, and unknown channel IDs on
   non-control channels are *ignored with a structured event*. This is
   the forward-compatibility contract, tested in A11.
5. **Error codes.** `MSG_ERROR` body v1: `u16 code ‖ u16 len ‖ msg`
   (existing 14 B golden uses code=0x0001). v1.1 adds codes — see §3.
   Receiving an ERROR is fatal for the current handshake, non-fatal
   (log) for post-handshake if `fatal=0` flag bit.
6. **Identity binding.** From v1.1, when `FEAT_DEVICE_ID` is negotiated,
   the session identity is the device's registered identity (docs/18 T4);
   a peer that negotiated the feature but failed identity exchange MUST
   be rejected.

## 2. Version negotiation flow

```
HELLO.frame_version = 1            (frame format version — stays 1 through v2)
HELLO.proto_version  = u16         (NEW, first 2 bytes of HELLO body — v1.1)
HELLO.features       = u16         (existing; bits 8+ reserved for extensions)
```

**Backward-compatibility decision (implemented, honest):** v1.1 adds
**no bytes to HELLO/HELLO_ACK** — the classic 84 B / 83 B layouts are
untouched. The feature bit alone is the switch:

- v1 peer (features ≤ 0x00FF): sees bit 8 as an unknown feature →
  ignores it (rule 3) → `negotiated` never contains bit 8 → session
  runs as pure v1 (no identity messages).
- v1.1 peer + v1.1 peer: `negotiated & 0x0100` ⇒ mandatory identity
  exchange after mutual AUTH_OK (§15.2 of docs/02). Identity
  authenticity rides on `MSG_DEVICE_ID`'s session-key MAC over the wire
  transcript (the classic pairing MAC inputs are unchanged).
- v1.1 device receiving a v1 HELLO (no bit 8): operates in v1 mode,
  logs `proto=negotiated.v1`.

This keeps every v1 byte identical while giving a clean v1→v1.1 path.

## 3. v1.1 message additions (implemented, slice A4/A6)

| Msg | ID | Direction | Body |
|---|---|---|---|
| `MSG_DEVICE_ID` | 0x11 | device→host, immediately after HELLO_ACK (if FEAT_DEVICE_ID) | `device_id(16) ‖ identity_pub(32) ‖ name(≤64) ‖ platform(16) ‖ app_ver(16) ‖ caps(u32) ‖ mac(16)` where `mac = HMAC(key_mac, transcript ‖ body[:len-16])[:16]`, transcript = all bytes exchanged since HELLO (both dirs) |
| `MSG_DEVICE_AUTH` | 0x12 | host→device, reply to 0x11 | `decision(1) ‖ session_id(16) ‖ host_id(16) ‖ mac(16)`; decision: 0=TRUSTED, 1=TRUSTED_NEW (host auto-approves first time), 2=REVOKED (fatal), 3=THROTTLED (fatal, retry later) |
| `MSG_RESUME_REQ` | 0x0E (format finalized) | either | `session_id(16) ‖ fresh_pub(32) ‖ resume_nonce(16) ‖ mac(16)`; mac over `pairing_secret ‖ session_id ‖ resume_nonce ‖ fresh_pub` |
| `MSG_RESUME_OK` | 0x13 | peer | `fresh_pub(32) ‖ mac(16)` — both sides derive new ECDH keys (fresh X25519), same pairing secret; channel state replay via existing CONFIG/TUN_UP/QOS; file transfers resume via `FILE_RESUME` (A7) |

**Session ID:** host generates `session_id` (16 B random) at first
connect, returns it in `MSG_DEVICE_AUTH`. Resumption is valid while:
(a) pairing secret unchanged, (b) ≤ 10 min since last frame, (c) ≤ 50
resumptions total, (d) identity not revoked. All bounds configurable (A3).

**Downgrade protection (T4):** a v1.1 host that negotiated FEAT_DEVICE_ID
and never received a valid `MSG_DEVICE_ID` within 5 s of AUTH_OK sends
`MSG_ERROR(code=0x0007 IDENTITY_REQUIRED)` and tears down. An attacker
stripping the message cannot forge the MAC.

## 4. Compatibility matrix (target)

| Host \ Device | v1 | v1.1 | v2 |
|---|---|---|---|
| v1 | v1 | v1 (degrade, no identity) | v1 |
| v1.1 | v1 | v1.1 | v1.1 |
| v2 | v1 | v1.1 | v2 (QUIC transport optional) |

Minimum supported: v1. Deprecation policy: a protocol version is
deprecated after 2 stable releases, removed after 4, with ≥ 6 months
notice in CHANGELOG.

## 5. ULP v2 (design only, not implemented)

- **Transport-agnostic core:** ULP is defined over the `Transport`
  trait (A1); v2 adds QUIC transport with ULP stream = QUIC stream
  (control), QUIC datagrams (tunnel/video priority), 0-RTT resumption
  (replaces in-protocol RESUME when available; in-protocol RESUME stays
  as fallback for TCP).
- **Stream identifiers:** v1 relies on (channel, implicit order); v2
  adds explicit `stream_id` + `request_id`/`correlation_id` (u32) to
  request/response messages (STATS, file ops, proxy ops) — enabling
  out-of-order responses.
- **Capability registry (device fabric):** HELLO carries a 64-bit
  capability vector; apps request capabilities from authorized devices
  (docs/25 §6).
- **Message framing v2:** 1-byte type + 16-bit body length (TLV
  extensions), reserved field for per-message auth token.
- **Explicitly deferred to v2+ (not promised):** multipath, in-band key
  rotation, group sessions.

## 6. Testing contract for every protocol change

New message ⇒ golden vector + encode/decode round-trip (all 4 impls) +
one negative test + one E2E use + docs/02 update + CHANGELOG entry.
