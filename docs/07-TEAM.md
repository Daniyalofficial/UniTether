# 07 — Team Size & Roles

## Minimum viable team: **5 FTE + 2 part-time**

| Role | FTE | Owns | Hiring profile |
|---|---|---|---|
| **Tech lead / Rust systems** (1) | 1.0 | tunnel, protocol, crypto, CI | 7+ y systems Rust; kernel/TUN experience; will be the Gnirehtet-core person |
| **Android engineer** (1) | 1.0 | VPN service, MediaProjection, audio, prod features, NDK glue | 5+ y Kotlin; has shipped a screen-capture or media app |
| **Desktop/GUI engineer** (1) | 1.0 | Tauri shell, Svelte UI, i18n, installers, auto-update | strong TS + one native-OS depth (Windows or macOS) |
| **QA / DevRel** (1) | 1.0 | device farm, benchmarks, e2e harness, docs, beta program | SDET mindset; comfortable with real phones (≥ 5 models) |
| **Security engineer** (0.5→1.0 at Phase 4) | 0.5 | threat model, audit liaison, fuzzing, supply chain | crypto review background |
| **Product/design** (part-time) | 0.5 | UX, pairing flow, marketing assets | doubles for launch content |
| **Community/DevRel** (part-time) | 0.5 | Discord, triage, tutorials, i18n coordination | from existing contributor base after v0.2 |

## Hiring order
1. Rust lead (already the author of the protocol crate)
2. Android engineer (week 1)
3. GUI engineer (week 2)
4. QA (week 4 — before media phase)
5. Security 0.5 (week 12, scales to 1.0 week 19)

## Why not smaller?
3-person team is possible for Phase 1 only (Rust+Android+GUI), but the
**concurrent** media + productivity + 4-platform CI workload makes
6-month-to-1.0 unrealistic without dedicated QA. Why not bigger?
The codebase is intentionally small-core (protocol + tunnel ≈ 6 kLOC);
beyond 5–6 engineers, coordination cost exceeds throughput until 1.0
adoption justifies a platform group.

## Working agreements
- Spec-first protocol changes (vectors + spec in the same PR).
- Every subsystem has a demo script (`tests/`), not just tests.
- Weekly latency/battery dashboards from the device farm (R3/R8).
- Bus-factor ≥ 2 per crate by end of Phase 1 (R10).
