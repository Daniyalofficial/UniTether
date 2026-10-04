# 16 — Security Audit Plan (pre-1.0)

## Scope (what the external auditor reviews)
1. **ULP cryptographic profile**: X25519 + HKDF-SHA256 key
   derivation; AES-256-GCM / ChaCha20-Poly1305 AEAD usage; nonce
   management (per-direction counter, channel bound into AAD);
   pairing-secret handling (never leaves memory in cleartext on wire;
   stored encrypted at rest via OS keychain/KeyStore).
2. **VPNService privilege review**: can a malicious *host* (or a
   compromised ULP peer) escalate inside the device? Focus: packet
   stream handling, DNS injection, route manipulation, file channel
   path traversal, notification/clipboard deserialization.
3. **Host TUN review**: can a malicious *device* affect the host
   beyond the tunnel (e.g., via raw packet crafting)? Focus: tunnel
   channel → TUN write path, proxy channel, stats overflow.
4. **Supply chain**: dependency audit (RustSec advisories,
   `npm audit` with lockfile pinning, Gradle dependency verification),
   signing of all release artifacts, update-channel integrity
   (minisign + sha256).
5. **Transport pairing UX**: can a MITM on a crowded LAN trick the
   pairing (QR swap, mDNS spoofing)? Focus: QR pairing binding,
   mDNS instance-name validation, warning UI for name mismatch.

## Deliverables
- Written report: findings rated Critical/High/Med/Low with PoCs.
- Fix verification: re-test on patched builds; all Critical/High
  closed before 1.0 (gate in `03-ROADMAP.md` week 19).
- Public summary (no PoC details) in `SECURITY.md` history.

## Budget & timing
- 2 senior security engineers × 4 weeks (Phase 4, week 19).
- Fuzzing infrastructure (already in CI) handed over as part of the
  engagement scope.

## Interim controls (before the audit)
- Production builds **reject the INTEROP cipher** (R9).
- ASan/UBSan + fuzzing in CI from week 1.
- Dependency pinning + lockfile commits from day 1.
- No telemetry by default; opt-in only, and it sends **no**
  identifiers, only aggregate counters (GDPR-clean, see
  `09-MARKETING.md`).

## Implemented controls — status (v0.2.0, evidence-linked)

Legend: **[I]** implemented + tested in CI · **[P]** partially
implemented · **[N]** planned / not implemented (never documented as
done). Evidence = the suite that pins the control.

| # | Control | Status | Evidence |
|---|---------|--------|----------|
| 1 | Pairing MAC binds (secret, ecdh_pub, nonce) — MITM substitution of any field fails | [I] | test_security.py `sec:mitm-*`, test_v11 |
| 2 | Handshake replay: 256-entry FIFO (ecdh_pub, nonce) cache; duplicates rejected | [I] | test_security.py `sec:replay-cache-*` |
| 3 | Resume replay: duplicate RESUME_REQ (same nonce) → ERR_RESUME_INVALID (0x000A), session continues | [I] | test_security.py, test_chaos.py S4 |
| 4 | AEAD nonce management: per-direction counter, channel in AAD; nonce reuse ⇒ tag mismatch | [I] | test_security.py `sec:replay-aead-*`, fuzz `aead` |
| 5 | Pairing brute force: 5 failures / 60 s per source ⇒ ERR_THROTTLED; success resets; per-source isolation | [I] | test_security.py `sec:bruteforce-*` (PairingGate) |
| 6 | Device identity: stable device_id = SHA256(domain‖identity_pub)[:16]; transcript-bound DEVICE_ID/DEVICE_AUTH; trust registry persists across host crashes (no re-pairing) | [I] | test_v11 (trust), test_chaos.py S2, test_security `sec:mitm-identity-mac` |
| 7 | Resource limits on every network-controlled value (lengths, queues, file chunks, proxy); rejection not clamping; RESERVED_FLAGS 0x05 rejected on receive | [I] | test_limits (19/19), test_security `sec:oversized-*`, limits.py / ulplink.mjs / protocol/src/limits.rs |
| 8 | Structured errors: stable codes 0x0001–0x000B + flag 0x01 body, fatal/retryable semantics, correlation | [I] | test_limits, ulp_v11.error_body/parse, Rust error.rs |
| 9 | QoS scheduler: weighted deficit RR, CONTROL>INPUT>AUDIO>VIDEO>FILE, starvation bound ≤ max(weights) pops, backpressure (8 MiB / 4096 items) with counted drops | [I] | test_scheduler (732/732 incl. property), test_security `sec:exhaustion-*` |
| 10 | File transfer v2: whole-file SHA-256 integrity, atomic .part→final commit, resume from contiguous offset, collision suffixes, duplicate skip, path-traversal-safe names | [I] | test_file (23/23), test_chaos.py S5, test_security `sec:traversal-*` |
| 11 | Observability privacy: mechanical denylist (16 content field families), string caps, no binary, schema v1 | [I] | test_obs (38/38 + 3000-event privacy fuzz), fuzz `obs` |
| 12 | Session lifecycle: explicit state machine (11 states / 37 transitions), reconnect backoff + jitter with exhaustion → FAILED, resume events | [I] | test_state (107/107), test_session_manager (26/26), test_resume (14/14), test_chaos S1/S3 |
| 13 | Chaos: flap / crash-restart / IP change / duplicate handshake / mid-file loss / injected latency — all recover to a verifiable state | [I] | test_chaos (20/20) |
| 14 | Fuzz targets in CI: frame, message, AEAD, handshake, file ops, scheduler, observability (deterministic, seedable) | [I] | fuzz.py (7 targets; 2000 iters local, 500 in CI) |
| 15 | Cipher downgrade floor: negotiated cipher never below the shared INTEROP floor; unsupported frame version rejected | [I] | test_security `sec:downgrade-*`, hello_verify |
| 16 | Supply chain: RustSec / npm audit / SBOM / signed artifacts | [N] planned (Phase 68/69) |
| 17 | Tenant isolation + RBAC + audit backend (cloud) | [N] not implemented — local-only stack has no tenant dimension yet |
| 18 | QUIC experimental transport behind abstraction | [N] not implemented (TCP/ADB only; no blind replacement) |
| 19 | External audit (this plan's scope) | [N] scheduled pre-1.0 |
| 20 | Decompression-bomb surface | [N/A] no decompression exists anywhere in the ULP (AEAD before any expansion); RESERVED_FLAGS reject F_COMPRESSED/F_FRAG on receive |
