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
