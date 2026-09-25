# Changelog

All notable changes to UniTether are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-09-24 — "Scaffold"

### Added
- **Protocol**: UniLink Protocol (ULP) v1 specification — 12/14-byte frame
  header, 13 multiplexed channels (control, tunnel-v4, tunnel-v6, video,
  audio in/out, input, file, clipboard, notification, stats, proxy, camera,
  user), X25519 + SHA256-CTR/HMAC interop cipher profile, AES-256-GCM /
  ChaCha20-Poly1305 production profiles, fragmentation, zstd compression.
- **Host (Rust workspace)**
  - `unilink-protocol` — pure-Rust framing/codec, zero hard dependencies,
    vector-driven test suite.
  - `unilink-transport` — ADB (adb-forward) transport with auto-disconnect
    handling, LAN TCP transport, mDNS discovery (`_unilink._tcp`),
    Wi-Fi Direct group connect, pairing/QR payload codec, TLS wrapper.
  - `unilink-tunnel` — TUN engine (Linux `/dev/net/tun`, macOS `utun`,
    Windows WinTun), **IPv4+IPv6 dual-stack**, raw ICMP passthrough,
    token-bucket throttling (2G/3G/4G/5G/custom), latency + packet-loss
    injection, live statistics.
  - `unilink-proxy` — SOCKS5 and HTTP proxies bridged into the tunnel.
  - `unitether` CLI — `pair`, `scan`, `connect`, `disconnect`, `stats`,
    `qos`, `tunnel`, `proxy`, `devices` subcommands; auto-stop on
    disconnect (fixes the Gnirehtet v2 manual-stop annoyance).
- **GUI (Tauri 2 + Svelte 4)** — device list, one-click connect, live
  stats panel, mirror view (WebCodecs H.264), mute/QoS controls, pairing
  dialog, dark/light themes, i18n (en, ur, ar, es, zh, hi), tray icon.
- **Android app (Kotlin, min SDK 21, no root)**
  - `UniVpnService` — dual-stack VPNService (IPv4/IPv6), packet forwarding
    over ULP tunnel channels, custom DNS + per-prefix routes.
  - MediaProjection screen capture → hardware H.264 encode (C2), adaptive
    bitrate, <50 ms glass-to-glass target on LAN.
  - Bidirectional Opus audio (NDK `libopus`, PCM fallback), per-stream
    mute.
  - Input injection via AccessibilityService `dispatchGesture`.
  - Wi-Fi Direct (P2P), Bluetooth PAN and LAN (mDNS/NsdManager) transports;
    ADB transport parity with Gnirehtet.
  - Productivity: bidirectional clipboard sync, notification mirroring,
    file transfer, SMS bridge, screenshot capture.
  - QR pairing (ZXing), foreground service, WorkManager reconnect.
- **Tests** — Python protocol reference implementation + test vectors,
  cross-language Node.js codec tests, full end-to-end protocol simulation
  (handshake → auth → config → tunnel ICMP echo → video/audio/clipboard).
- **CI/CD** — GitHub Actions: Rust workspace test + coverage gate (tarpaulin,
  ≥80 %), protocol conformance (Python + Node), Android `assembleDebug` +
  lint, GUI build, release matrix (MSI/DMG/AppImage/DEB/AUR/Homebrew/winget
  manifests + APK/AAB), auto-update metadata.
- **Docs** — architecture (Mermaid), protocol spec, 6-month roadmap,
  competitive matrix, risk register, team plan, marketing plan, security
  audit plan, installer guides, Gnirehtet acknowledgment.

[0.1.0]: https://github.com/Daniyalofficial/UniTether/tree/v0.1.0
