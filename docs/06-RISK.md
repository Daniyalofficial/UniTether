# 06 — Risk Analysis & Mitigation

Risk register (likelihood L / impact I, both 1–5). Owners: see `07-TEAM.md`.

| # | Risk | L | I | Score | Mitigation |
|---|---|---|---|---|---|
| R1 | **MediaProjection policy change** (Google tightening screen capture for third-party apps, see Android 14 "capture consent" UX) | 3 | 4 | 12 | (a) keep capture UX transparent + per-session consent; (b) fallback: scrcpy-style ADB path as "high-fidelity mode"; (c) track AOSP changes quarterly. |
| R2 | **TUN access friction** (Linux group, macOS privilege, Windows WinTun install) | 3 | 3 | 9 | First-run diagnostics + per-OS one-click fix scripts (`packaging/doctor/`), GUI wizard; WinTun auto-install. |
| R3 | **Mirroring latency > 50 ms** on mid-tier devices (encoder queue) | 3 | 4 | 12 | Adaptive bitrate + keyframe cadence control; `C2` async encoder; benchmark gate in CI (`benchmarks/`); HEVC/AV1 for 4K. |
| R4 | **Wi-Fi Direct flakiness** (group owner negotiation across vendors) | 4 | 2 | 8 | Treat WiFi-Direct as *optional* transport; LAN + ADB always available; 5-min stability test in CI matrix (real device farm). |
| R5 | **Audio feedback/echo** when both directions active | 3 | 2 | 6 | `VOICE_COMMUNICATION` source (AEC on device), per-stream mute, level metering; ship "one-way audio" as default. |
| R6 | **Play Store policy** on VPNService + accessibility (listing review) | 2 | 4 | 8 | Play Console "security & privacy" questionnaire pre-filled; accessibility service is *optional* (feature degrades gracefully); side-load + GitHub first, store later. |
| R7 | **Protocol interop drift** (3 impls diverge) | 2 | 4 | 8 | Spec-first workflow + vector tests in CI across Rust/Python/Node; breaking changes only via version byte. |
| R8 | **Battery > 10 %/h** target missed | 2 | 3 | 6 | Encoder power budget (H.264 baseline), audio 16 kHz option, Wi-Fi scan duty-cycling; battery benchmark in Phase 4. |
| R9 | **Security bug in crypto profile** (interop cipher misused in prod) | 2 | 5 | 10 | Production builds **reject** INTEROP cipher unless `--allow-interop-cipher`; external audit pre-1.0 (R19); fuzzing soak. |
| R10 | **Key-person dependency** (one Rust systems engineer) | 3 | 4 | 12 | Pair on every subsystem; docs mandatory; bus-factor ≥ 2 per crate by week 12. |
| R11 | **Scope creep to 4K/AV1/camera before core is stable** | 4 | 3 | 12 | Roadmap slippage policy (cut from bottom); MVP line in `08-MVP.md` is contractual. |
| R12 | **ADB trust model criticism** (USB = privileged) | 2 | 3 | 6 | Document threat model (`SECURITY.md`); wireless transports don't inherit ADB trust — QR pairing applies. |
| R13 | **Apple/MS platform policy** (background TUN on macOS, App Store for Windows) | 2 | 2 | 4 | Distribute outside stores first (official site + brew/winget/AppImage); macOS uses standard `utun` (same as OpenVPN). |
| R14 | **Legal: "tethering" branding / carrier ToS** (some carriers restrict tethering) | 2 | 2 | 4 | We do *reverse* tethering (device uses PC's internet) — carrier-neutral; legal review of copy pre-launch. |
| R15 | **Funding/attrition** (small team) | 3 | 5 | 15 | Open-source-first (community carries docs/bugs), no cloud = low COGS, 6-month runway plan in `09-MARKETING.md`. |

## Burn-down policy
Any risk at score ≥ 12 gets a named owner + weekly review. R15 is
managed by the roadmap itself: Phase 1 ships a useful product (dual-stack
wireless tethering) that stands alone even if Phase 2 stalls.
