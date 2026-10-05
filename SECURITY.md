# UniTether Security Policy

## Supported versions

| Version | Supported until |
|---------|-----------------|
| 0.1.x   | 2026-12-31      |
| 1.0.x   | 12 months after 1.0 GA |

## Threat model (summary)

- **Man-in-the-middle on LAN/Wi-Fi Direct/BT**: mitigated by mandatory
  pairing (X25519 ECDH key exchange bound to a 32-byte QR pairing secret)
  before any channel other than control can carry data. Production cipher
  profile: AES-256-GCM or ChaCha20-Poly1305. The SHA256-CTR/HMAC
  "interop" profile is for conformance tooling and is rejected by
  production builds unless `--allow-interop-cipher` is passed.
- **Untrusted host / untrusted device**: both sides are first-class;
  the pairing dialog is the trust anchor on the *device* screen (QR scan
  or manual code), so a rogue host cannot bind to a device without
  physical proximity + user confirmation.
- **Local abuse**: the host TUN interface can see all device traffic
  (documented, inherent to reverse tethering — same threat model as
  Gnirehtet, USB/ADB trust).
- **Supply chain**: pinned `Cargo.lock`, `npm ci` with lockfile, Gradle
  dependency verification in CI, reproducible-build steps for installers.

## Reporting

Report vulnerabilities to `security@unilink.dev` (PGP key in-repo
`SECURITY.asc` at 1.0). Response: acknowledge ≤ 72 h, mitigation plan
≤ 14 days, coordinated disclosure ≤ 90 days.

## Audit plan

See `docs/16-SECURITY-AUDIT.md`: pre-1.0 external audit of the protocol
cryptographic profile, VPNService privilege escalation review, and
dependency review; continuous fuzzing (`cargo fuzz`, `libFuzzer` for the
NDK codec glue) in CI.
