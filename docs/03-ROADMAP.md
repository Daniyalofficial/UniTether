# 03 — 6-Month Development Roadmap

Assumptions: 5-person team (see `07-TEAM.md`), this scaffold as week 0
state. Exit criteria per phase are testable (CI green + demo script).

## Phase 0 — Foundation (done, week 0)
- [x] Protocol v1 spec + vectors + Python/Node conformance
- [x] Rust workspace (protocol/transport/tunnel/proxy/cli)
- [x] Android app skeleton (VPN dual-stack, media, audio, prod)
- [x] Tauri GUI skeleton, CI, installers, docs

## Phase 1 — Network core (weeks 1–6) → tag `v0.2`

| Week | Milestone | Exit criteria |
|---|---|---|
| 1 | ADB transport hardening; `adb forward` lifecycle; auto-stop on unplug | unplug test: TUN down < 1 s, no zombie service |
| 2 | LAN TCP + mDNS discovery (host `mdns-sd`, device NsdManager) | 2 real devices pair over Wi-Fi in < 30 s |
| 3 | Dual-stack tunnel E2E: IPv6 on both ends, DNS64 off, ping6 | `ping6` from device to host internet works |
| 4 | QoS engine E2E (shaper both ends, latency/loss injectors, profiles) | iperf3 within ±15 % of profile rate; jitter/loss visible in pings |
| 5 | SOCKS5 + HTTP proxy; proxy channel; multi-device (3 devices) | 3 phones on one PC, independent subnets, 10 Mbit each |
| 6 | Stats pipeline (104-B struct, CLI `--watch`, GUI live panel) | stats panel error < 5 % vs `nstat` ground truth |

## Phase 2 — Media (weeks 7–12) → tag `v0.3`

| Week | Milestone | Exit criteria |
|---|---|---|
| 7 | MediaProjection + C2 H.264 encoder, keyframe/delta, EOI | stable 1080p60 encode on mid-tier phone, 0 drops/min |
| 8 | Video channel + adaptive bitrate (AIMD on queue RTT) | bitrate converges in < 3 s after link change |
| 9 | WebCodecs decode in GUI; <50 ms glass-to-glass (LAN, H.264) | p95 latency < 50 ms (method in `12-BENCHMARKS.md`) |
| 10 | Audio: Opus NDK both directions, mute, level metering | audible round trip < 120 ms; no feedback loop with AEC |
| 11 | Input injection (touch/mouse/key/text), multi-monitor routing | 95 % touch accuracy grid test; keyboard IME passthrough |
| 12 | HEVC/AV1 encode profiles; 4K60 HEVC on fast LAN; camera as webcam | 4K60 stable; host sees camera via standard UVC-bridge (OBS) |

## Phase 3 — Productivity (weeks 13–18) → tag `v0.4`

| Week | Milestone | Exit criteria |
|---|---|---|
| 13 | Clipboard sync (text/html/image) both ways | 50 ms sync on LAN, round-trip no data loss (1 MB text) |
| 14 | File transfer (chunked, resume, MediaStore scan) + drag-drop in GUI | 1 GB file at 60 % of link rate; resume after kill |
| 15 | Notification mirroring + reply actions; screenshot capture | mirror < 300 ms; screenshot button in tray |
| 16 | SMS bridge (send/receive), WhatsApp-Deep-Link reply (documented limits) | send/receive on real SIM; no silent failures |
| 17 | Wi-Fi Direct + BT-PAN transports E2E | pair + tunnel + 5-min stability each |
| 18 | Session resume (RESUME), saved-device auto-reconnect, i18n 6 locales | reconnect < 2 s on Wi-Fi roam; all strings localized |

## Phase 4 — Hardening & 1.0 (weeks 19–24) → tag `v1.0`

| Week | Milestone | Exit criteria |
|---|---|---|
| 19 | External security audit (crypto + VPN priv esc); fixes | audit report, 0 critical open |
| 20 | Fuzzing soak (protocol, NDK glue), crash reporting (self-hosted) | 72 h fuzz, 0 unfixed memory safety bugs |
| 21 | Installers + auto-update (MSI/DMG/AppImage/DEB/AAPK/AAB), telemetry opt-in | clean install on Win10/macOS11/Ubuntu20.04; update < 60 s |
| 22 | Perf: <10 % battery/h tether-only; CPU < 8 % idle session | methodology in `12-BENCHMARKS.md`, 3-device sample |
| 23 | Docs: user guide, wiki, API, 3 video tutorials; beta program | 100 beta users, crash-free ≥ 99 % |
| 24 | v1.0 GA: changelog, tag, announcement | launch checklist in `09-MARKETING.md` complete |

## Slippage policy
Any milestone slipping > 1 week triggers scope cut from the *bottom*
of that phase (productivity first, network core never). The dual-stack
+ wireless + mirroring triad is the non-negotiable 1.0 story.
