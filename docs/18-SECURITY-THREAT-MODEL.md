# 18 — Security Threat Model

Status: audit complete. Legend used throughout: **[I]** implemented and
tested, **[P]** partially implemented, **[N]** not implemented (planned).
No certification is claimed; no claim is made beyond what tests cover.

## 1. Assets

| Asset | Value | Where it lives |
|---|---|---|
| Paired-network credentials (32 B pairing secret) | grants full control of a session | device prefs (Android), host CLI arg/file |
| Session keys (aead + mac, 64 B) | decrypts one session | RAM only |
| Device network traffic (tunnel) | private data | in-transit + TUN/VPN |
| Screen content, audio, camera | highly sensitive | media channels, in-transit |
| Clipboard, notifications, SMS previews | highly sensitive | `CH_CLIPBOARD`, `CH_NOTIFICATION`, `CH_USER` |
| Files transferred | sensitive | `CH_FILE` |
| Device identity keys (v1.1) | long-term trust anchor | device keystore-backed file **[N]** |

## 2. Trust boundaries

```
[User + phone OS]   |   [ULP session]   |   [Host user]
       |                      |                    |
  device app code    <-== encrypted frames ==>   host core
  (untrusted host?    boundary B1: pairing MAC     (untrusted phone?
   no — same user)    + X25519 ECDH)               no — same user)
                          |
                 [optional relay] boundary B2 (v2):
                 relay sees ciphertext only
```

**Threat assumption:** the user owns both endpoints. The primary threats
are (a) LAN eavesdropping/active attacks at pairing and in-session,
(b) a stolen/stale pairing credential, (c) a compromised *peer device*
(lost phone or PC), (d) DoS/resource exhaustion, (e) supply chain.
A hostile *same-user* endpoint is out of scope (that is device theft —
handled by revocation, Phase A6).

## 3. Cryptographic primitive audit

| Primitive | Usage | Status | Notes |
|---|---|---|---|
| X25519 (RFC 7748) | ECDH for session keys | [I] | 4 independent impls (Rust/Python/Node/Kotlin) all verified against RFC §5.2/§6.1 vectors; RFC-compliant clamp; accepts non-canonical points per spec |
| HKDF-SHA256 (RFC 5869) | 2×32 B key separation from ECDH shared secret, salt=nonce_a‖nonce_b, info=`unilink-v1`‖u8(cipher) | [I] | vectors in `protocol/vectors/hkdf.json`; distinct aead/mac keys |
| SHA-256 | transcript MACs, INTEROP keystream blocks, file integrity (v2) | [I] | stdlib impls, no custom hash |
| HMAC-SHA256 | pairing MAC, frame tags, identity binding | [I] | vectors present |
| INTEROP AEAD | per-frame confidentiality+integrity | [I] **[P]** | *Custom construction* (documented below, deliberately isolated); a standardized AEAD (ChaCha20-Poly1305, cipher 3) is negotiated but **not yet implemented in the data path** — production path uses INTEROP for conformance determinism. Migration to libchacha20poly1305 is A11 work |
| Randomness | nonces, secrets, session IDs | [P] | Python/Node use `os.urandom`/`crypto.getRandomValues` [I]; Rust host uses `/dev/urandom` [P — needs `getrandom`-grade source + Windows `BCryptGenRandom` verification in CI]; Android `SecureRandom` [I] |
| Argon2/scrypt | secret storage at rest | [N] | pairing secret is stored plaintext in device prefs; **accepted risk v0.x** (device is user-owned, encrypted at rest by OS); keystore-backed identity keys in A6 |

### 3.1 The INTEROP AEAD — why it exists and its isolation

`docs/02-PROTOCOL.md §7` defines: keystream block `B_i = SHA256(key‖nonce‖u32be(i))`,
XOR onto plaintext, tag = `HMAC-SHA256(key_mac, nonce‖aad‖ct)[:16]`.

**Why custom:** the design goal was a byte-deterministic AEAD that
identical code in four languages can implement with only SHA-256/HMAC —
removing provider variance (different AES/ChaCha implementations,
padding bugs, SIV edge cases) from the conformance gate. It is a
stream-cipher + encrypt-then-MAC composition (sound structure, standard
primitives) with a **64-bit security bound** (HMAC truncation) —
sufficient for session keys with per-session rotation, *not* suitable as
a general-purpose AEAD. **Isolation:** it exists only in
`reference_framing.py::interop_*`, `ulplink.mjs::interop*`,
`UlpCrypto.kt::interop*`, `unilink-protocol::interop` — no other code may
call it; the negotiated cipher field is the seam for replacing it.

### 3.2 Nonce/counter analysis

- Frame nonce = `u64be((dir<<63) | counter) ‖ u32be(channel)`. Direction
  bit fixes the top bit; counter is per-direction monotonically increasing
  from 0. **Counter overflow:** u63 counter — no reachable overflow in any
  session lifetime; on overflow the session MUST be torn down (checked in
  A2/A3).
- AEAD nonce uniqueness: (dir, counter) unique per key → unique nonce.
  Key rotation per handshake → no nonce reuse across sessions.
- **Replay:** within a session, a retransmitted frame is rejected by the
  AEAD only if the receiver tracks used nonces — the INTEROP construction
  does not reject replays of *valid* frames (stream cipher). Accepted
  v0.x risk: replays only make sense for idempotent channels (tunnel
  packets, where the TUN layer de-dupes via IP; control, where sequence
  checks apply in A4). File v2 (A7) adds per-chunk checksums + offsets
  that make replayed data detectable/harmless. **Documented as a known
  property, not hidden.**

## 4. STRIDE threat table (top threats)

| # | Threat | Scenario | Mitigation | Status |
|---|---|---|---|---|
| T1 | MITM at pairing | attacker intercepts QR/blob | pairing MAC binds secret+pub+nonce; blob contains 32 B secret (entropy, not guessable); **QR is not authenticated** → user must verify device name (UX step, A10) | [P] |
| T2 | Pairing replay | capture blob, replay later | secret is static (v1) → **no expiry** [N → A6: pairing TTL + single-use handshake nonces + replay cache] | [P] |
| T3 | Downgrade cipher | force cipher 0 when 3 supported | cipher selection is in host's HELLO pref, device's ACK; MAC covers selection | [I] (tests A11: downgrade attempt rejected/marked) |
| T4 | Version downgrade | attacker strips v1.1 identity exchange | version + features in MACed HELLO; v1.1 hosts require identity when feature negotiated | [N → A4] |
| T5 | Frame tampering in-session | flip a bit in transit | AEAD tag (128-bit MAC) | [I] (negative tests A11) |
| T6 | Oversized/malicious frames | attacker sends 1 MiB × N | `MAX_PAYLOAD` 1 MiB + queue caps + rate limits | [P → A3] |
| T7 | Proxy abuse | host uses phone as open proxy | proxy binds loopback only; explicit enable; bypass list; (relay quotas v2) | [I] loopback bind; [N] quotas |
| T8 | Path traversal in file names | `../../evil` in file meta | device sanitizes names to `[A-Za-z0-9._-]`, confines to app dir | [I] (Kotlin `sanitize`; negative test A11) |
| T9 | Decompression bomb | F_COMPRESSED frames | **compression is not implemented** (flag reserved, never set) — nothing to bomb; A3 rejects F_COMPRESSED frames on receive until a codec ships | [I by absence] |
| T10 | Brute force pairing | flood connect attempts | no throttling (v1) → A6: per-transport pairing rate limit + lockout | [N → A6] |
| T11 | Stolen device | phone lost, secret on disk | device lock (OS), app data wipe on user request, (A6: remote revocation of identity) | [P] |
| T12 | Supply chain | malicious dependency | no lockfiles yet, no SBOM → A11: lockfiles + cargo audit + npm audit + SBOM in CI | [N → A11] |
| T13 | GUI injection | malicious HTML in Tauri | `csp: null` **is a gap** → A10: set CSP, disable nodeIntegration (default in Tauri 2) | [N → A10] |
| T14 | Log leakage | secrets/frames in logs | no logging of payloads today (verified by grep in A11); A9 adds redaction test: telemetry schema forbids content fields | [P → A9] |
| T15 | Relay sees content | (v2) | relay routes opaque encrypted frames; end-to-end keys never touch relay; design in docs/19 | [N, by design] |

## 5. What negative tests must prove (Phase 37/4, implemented in A11)

`tests/security/` (Python + Node, CI-gated):
invalid MAC, invalid key, wrong nonce, replayed frame (control + file),
modified AAD, modified ciphertext, wrong counter, wrong direction,
unsupported cipher, unsupported version, malformed handshake (each field),
downgrade attempt (cipher + version), oversized frame, extended-length
overflow, unknown channel, unknown message (must be ignored, not crash),
path traversal name, filename collision, decompression-flag rejection,
auth-attempt overflow (throttle), pairing blob with truncated/padded
secret, QR blob with corrupted base64.

## 6. Incident response (v0.x, minimal)

1. Revoke: unpair device (delete blob on host + "Forget" on device).
2. Rotate: generate new pairing secret (QR) → re-pair.
3. Report: `SECURITY.md` process (email, 90-day response target — aspirational).
4. (Enterprise, planned: audit trail + forced revocation via policy — docs/25.)

## 7. Explicitly NOT claimed

No formal verification, no independent audit, no certification (FIPS/
SOC2/ISO). INTEROP AEAD is not a published algorithm — it is documented,
isolated, vector-pinned, and bounded to 128-bit security.
