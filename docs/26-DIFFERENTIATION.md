# 26 — Differentiation

Honest positioning. No "fastest/most secure" claims — every claim below
is either evidenced in this repository or explicitly labeled as a
target.

## 1. Category map (what exists today, publicly)

| Category | Examples | What they do well | Where UniTether differs |
|---|---|---|---|
| Reverse tethering | Gnirehtet, iPnet (paid) | no-root Android→PC internet | single-purpose, ADB-only, no crypto session, no media |
| Screen mirroring | scrcpy, DroidScrcpy, manufacturer suites | low-latency H.264 | one-way, no return input on some, no persistent pairing, no IPv6 tunnel |
| Remote desktop | RustDesk, Parsec | mature remote control | PC↔PC focus; phone-as-device is secondary |
| Tethering apps (phone side) | Netshare, PdaNet | hotspot alternatives | no host-side tunnel, no encryption story, no enterprise |

## 2. Differentiation claims (evidence-linked)

1. **Local-first, cloud-optional.** The full product works with zero
   cloud dependency — proven by the E2E suite running on 127.0.0.1
   (docs/17 §4). Relay/enterprise are additive (docs/19/25), never a
   dependency. *Evidence: tests/e2e.*
2. **Cryptographic session protocol with a public, byte-pinned spec.**
   ULP v1 is defined in docs/02 with golden vectors and 4 independent
   verified implementations (Python/Node/Rust/Kotlin) — interoperability
   is *tested*, not assumed. Most competitors' transports are
   proprietary or ADB-trusted. *Evidence: protocol/vectors, tests/.*
3. **Dual-stack (IPv4+IPv6) reverse tunnel** with custom DNS/routes —
   rare in this category (Gnirehtet: IPv4 only). *Evidence: dual-stack
   E2E vectors.*
4. **One pairing, many capabilities.** A single authenticated session
   carries tunnel + mirror + audio + input + files + camera + SMS reply
   (feature-negotiated), instead of N tools each with their own setup.
   *Evidence: feature bits + channel conformance.*
5. **Transport-agnostic by design.** TCP/ADB today; QUIC/relay behind
   one `Transport` trait (A1) — the protocol never changes when the
   transport does. *Evidence: A1 trait + tests.*
6. **Reliability engineering as a feature.** Explicit state machine,
   resumption, backoff, chaos/soak tests (A2/A4/A11) — a production
   bar most consumer tethering tools don't have a test plan for.
7. **Enterprise path without lock-in.** Orgs/policies/RBAC/audit are
   designed on top of the same open protocol (docs/25); a self-hosted
   deployment is the intended enterprise shape, not a SaaS hostage
   situation. *Status: designed, v2.*
8. **Protocol transparency + developer SDK.** Byte spec + vectors +
   stable Rust SDK (docs/24) invite third-party interop — a moat
   competitors with closed protocols can't match.

## 3. What is NOT a differentiator (honest)

- "Faster than X" — no head-to-head benchmark exists; A11 produces
  UniTether's own numbers (docs/19 §6), cross-tool comparisons are
  future work and will be published with methodology.
- "Most secure" — security is designed and tested at protocol level
  (docs/18); no audit/certification yet (explicitly not claimed).
- Battery life claims — drain is a measured metric (target < 10 %/h,
  bench_device.sh), not a marketing number.

## 4. Positioning statement

> UniTether is the open, cryptographically-secure, local-first device
> fabric that makes a phone and a desktop act as one machine — with the
> protocol, SDK, and enterprise controls to prove it.
