# 08 — MVP (first 3 months) — contractual cut line

The MVP is what gets shipped as **v0.5** (~week 13) and what the beta
program tests. It is *deliberately* a subset of the 6-month plan.

## In
### Network (the hero feature)
- [ ] Reverse tethering over **ADB (USB) + LAN (mDNS)** — the two
      transports that cover 95 % of first use
- [ ] **IPv4 + IPv6 dual-stack** (the #1 Gnirehtet gap, closed on day one)
- [ ] ICMP/ping passthrough, custom DNS + routes (CONFIG)
- [ ] **Auto-stop on disconnect** (the #2 Gnirehtet gap)
- [ ] QR pairing + saved devices + auto-reconnect
- [ ] Live stats (bandwidth, RTT, packet counters) in CLI + GUI
- [ ] Multi-device: 2 phones simultaneously (5+ is v0.6)
### Media (the differentiator, LAN only)
- [ ] Screen mirroring H.264 1080p60, adaptive bitrate, <50 ms p95 (LAN)
- [ ] One-way audio device→host (Opus), mute toggle
      (bidirectional audio is v0.6)
- [ ] Touch + mouse injection (no keyboard/IME yet)
### Productivity (cheap wins)
- [ ] Clipboard sync (text) both ways
- [ ] Screenshot capture (device → host)
- [ ] File transfer (host → device, drag-and-drop in GUI)
### Platform
- [ ] Windows 10 + macOS 11 + Ubuntu 20.04 installers (MSI/DMG/AppImage)
- [ ] GUI + CLI parity for MVP features; dark/light; English + Urdu
- [ ] Crash reporting (self-hosted Sentry), opt-in telemetry stub

## Out (explicitly deferred)
- Wi-Fi Direct, Bluetooth PAN (v0.6)
- Bidirectional audio, keyboard/IME, camera-as-webcam (v0.6)
- Throttling/QoS + proxy (v0.6 — shaper is in core since week 4, UI deferred)
- HEVC/AV1 + 4K (v0.7)
- Notifications, SMS bridge (v0.7)
- Session resume, 6-locale full i18n (v0.7/v1.0)

## MVP acceptance (demo script, 10 minutes)
1. New PC: install MSI → GUI opens, "Pair device" QR shows.
2. Phone: install APK → scan QR → "Connected".
3. `ping` + `ping6` from phone reach the internet; speed test ≥ 90 % of
   PC uplink (no shaper).
4. Unplug USB → phone stops within 1 s; notification dismisses.
5. GUI: mirror at 1080p60, move phone, p95 < 50 ms (LAN), touch phone
   from mouse; copy text on phone → paste on PC < 1 s.
6. Restart PC → saved device auto-reconnects.
**If this script passes on 3 different phones (budget/mid/flagship), the
MVP is done — regardless of the rest of the roadmap.**
