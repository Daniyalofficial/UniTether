# Changelog

All notable changes to UniTether are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
project follows [Semantic Versioning](https://semver.org/).

## [0.2.0-dev] - 2026-10-05 — "Reliability core + complete GUI"

### Added
- **ULP v1.1**: device identity (stable ID + pubkey + trust registry),
  handshake/resume replay caches, pairing brute-force throttle, AEAD nonce
  management, protocol version floor (downgrade protection), structured
  error codes 0x0001–0x000B.
- **Reliability**: explicit 12-state session state machine; reconnect
  backoff + jitter; hard resource limits on every network-controlled
  value; QoS channel scheduler (CONTROL > INPUT > AUDIO > VIDEO > FILE)
  with proven no-starvation bound; session resumption.
- **File transfer v2**: chunking, whole-file SHA-256, atomic commit,
  resume from contiguous offset (10 GB @ 97 % verified), path-traversal
  safety.
- **Security suite**: 54 tests (replay, downgrade, MITM, malformed, brute
  force, exhaustion, traversal) + 7 deterministic fuzz targets in CI +
  20-scenario chaos suite (flap/crash/IP-change/dup/loss/latency) — all
  recovering to a verifiable state.
- **Observability**: metadata-only events with a mechanical content
  denylist (privacy-enforced in tests).
- **GUI (complete)**: Dashboard (live stats, dual-stack tunnel + DNS,
  host proxy), Devices (mDNS + ADB discovery, manual connect), Pairing
  (QR + blob), Settings — 6 locales (en/ur/ar/es/zh/hi) with RTL,
  accessibility-clean build, backend adapter (real Tauri commands;
  clearly-labelled simulation in browser preview).
- **i18n automation**: consistency checkers for Android strings (6 × 21)
  and GUI catalogs (6 × 69): key parity, placeholder parity, RTL set,
  empty values, `t()` key usage — wired into `make i18n`, `make test`,
  CI (both Android and GUI).
- **Gradle wrapper** (official 8.5) committed; Android CI job is now a
  hard gate that builds all 3 ABIs and uploads the APK artifact.
- **Docs**: `26-DIFFERENTIATION`, `27-FINAL-PRODUCTION-READINESS`
  (implemented / partial / not-implemented / blocked / next),
  `28-QUICKSTART` (what to start, in what order, how to use each screen).
- **Transport refactor (A1)**: `Transport` trait + `Framed` single
  reservoir + generic `Session<T>` in `unilink-transport`; TCP path
  regression-pinned (coalesced frames).

### Changed
- Android app restructured to `com.unilink.{core,transport,tunnel,mirror,
  audio,camera,input,productivity,ui}`; ULP v1.1 codec added to the
  device; no-root VPNService dual-stack with custom DNS.
- README rewritten to match what is actually built (feature status table
  with implemented / partial / planned; honest CI description).

### Fixed
- TCP coalescing bug in the Rust host (bytes dropped at handshake →
  encrypted switch) — pinned by `framed_coalesced_frames_then_raw_path`.
- CI android job no longer hides build failures (previous fallback
  exited 0 without an APK).

### Not yet (tracked in docs/27)
Host-side consumers for mirror/audio/input/files/notifications/SMS/camera
channels; cloud/relay (optional by design); supply-chain gates;
Windows/macOS CI runners; signed staged releases; soak; hardware
latency/battery verification.

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
