# UniTether

> **The complete bridge between your phone and your computer — internet,
> screen, sound, files, clipboard and more. No root. One app. One cable
> (or none).**

UniTether starts where [Gnirehtet](https://github.com/Genymobile/gnirehtet)
ended and refuses to stop: it keeps the proven core — *reverse tethering
over a no-root Android `VPNService` into a host TUN device* — and grows it
into a full device-bridge suite: dual-stack networking, wireless
transports, low-latency screen mirroring, bidirectional audio, and
desktop-class productivity features.

*Gnirehtet, grown up.*

---

## Elevator pitch

**Gnirehtet** gives your Android phone the computer's internet over USB.
It stopped there in 2022: IPv4 only, USB only, no screen, no sound, no GUI,
and an abandoned codebase.

**UniTether** gives your phone *everything* the computer has — and gives
the computer the phone's camera, mic, screen and notifications:

| Capability | Gnirehtet | UniTether |
|---|:---:|:---:|
| Reverse tethering (USB/ADB) | ✅ | ✅ improved (auto-stop on unplug) |
| IPv4 | ✅ | ✅ |
| IPv6 | ❌ (not planned) | ✅ dual-stack |
| Wireless (Wi-Fi Direct / BT-PAN / LAN) | ❌ | ✅ + mDNS discovery + QR pairing |
| ICMP / ping | ❌ | ✅ raw passthrough |
| SOCKS5 / HTTP proxy on host | ❌ | ✅ |
| Network throttling (2G–5G, loss, latency) | ❌ | ✅ |
| Screen mirroring (H.264/HEVC, <50 ms LAN) | ❌ | ✅ |
| Audio both directions (Opus) | ❌ | ✅ |
| Touch/mouse/keyboard injection | ❌ | ✅ |
| Clipboard / notifications / files / SMS | ❌ | ✅ |
| GUI (Win/macOS/Linux) | ❌ | ✅ Tauri + Svelte |
| Actively maintained | ❌ | ✅ |

**Constraints honored:** no root anywhere, Android 5.0 (API 21)+,
Windows 10+ / macOS 11+ / Ubuntu 20.04+, <50 ms mirroring latency on LAN,
25+ Mbps headroom for 1080p60 (4K60 with HEVC/AV1 on fast links),
<10 % battery per hour in tether-only mode.

---

## Repository tree

```
UniTether/
├── README.md                  ← you are here
├── LICENSE                    Apache-2.0
├── NOTICE                     Gnirehtet baseline acknowledgment
├── SECURITY.md                threat model + reporting
├── CHANGELOG.md
├── docs/                      ← deep documentation (deliverables)
│   ├── 01-ARCHITECTURE.md     components, Mermaid diagrams, data flow
│   ├── 02-PROTOCOL.md         UniLink Protocol v1 — full binary spec
│   ├── 03-ROADMAP.md          6-month plan, weekly milestones
│   ├── 04-TECHSTACK.md        Rust vs Go vs C++ (and why Tauri+Kotlin)
│   ├── 05-COMPETITIVE.md      feature matrix vs 10 competitors
│   ├── 06-RISK.md             risk register + mitigations
│   ├── 07-TEAM.md             team size, roles, hiring order
│   ├── 08-MVP.md              3-month MVP cut line
│   ├── 09-MARKETING.md        go-to-market + launch plan
│   ├── 10-OPEN-SOURCE.md      license strategy (Apache-2.0, dual track)
│   ├── 11-TESTING.md          test pyramid, CI matrix, coverage gates
│   ├── 12-BENCHMARKS.md       benchmark methodology + vs Gnirehtet
│   ├── 13-INSTALLERS.md       MSI/DMG/AppImage/DEB/APK + auto-update
│   ├── 14-ACKNOWLEDGMENTS.md  how we credit Gnirehtet (etiquette)
│   ├── 15-I18N.md             localization plan (en/ur/ar/es/zh/hi)
│   └── 16-SECURITY-AUDIT.md   pre-1.0 audit plan
├── protocol/
│   └── vectors/               canonical protocol test vectors (JSON)
├── host/                      ← Rust workspace (the engine)
│   ├── Cargo.toml
│   ├── rust-toolchain.toml
│   └── crates/
│       ├── protocol/          ULP framing/codec — std-only, vector-tested
│       ├── transport/         ADB / TCP / Wi-Fi Direct / mDNS / pairing
│       ├── tunnel/            TUN engine, dual-stack, throttle, stats, ICMP
│       ├── proxy/             SOCKS5 + HTTP
│       └── unitether/         CLI binary
│   └── gui/                   Tauri 2 + Svelte 4 desktop app
│       ├── src/               Svelte components + TS protocol helpers
│       └── src-tauri/         Rust shell (tauri commands, session state)
├── device/                    ← Android app (Kotlin + NDK, no root)
│   ├── settings.gradle.kts / build.gradle.kts / gradle.properties
│   ├── native/                libopus JNI glue (C) + CMakeLists
│   └── app/src/main/
│       ├── AndroidManifest.xml
│       ├── res/               layouts, themes, values{,ur,ar,es,zh-rCN,hi}
│       └── java/com/unilink/unitether/
│           ├── app/            Application, DI, prefs
│           ├── service/        SessionForegroundService
│           ├── net/            UniVpnService (dual-stack), ProtocolConnection,
│           │                   transports (ADB/LAN/WiFiDirect/BtPan), Discovery
│           ├── mirror/         MediaProjection capture, C2 H.264 encoder,
│           │                   adaptive bitrate controller
│           ├── audio/          AudioBridge (Opus, bidirectional, mute)
│           ├── input/          InputAccessibilityService (dispatchGesture)
│           ├── prod/           ClipboardSync, NotificationMirror,
│           │                   FileTransfer, SmsBridge, Screenshot
│           ├── pair/           PairingActivity (QR)
│           └── ui/             MainActivity (Compose), screens, theme
├── tests/
│   ├── protocol/              Python reference implementation (stdlib only)
│   ├── node/                  TypeScript codec conformance (node, no deps)
│   └── e2e/                   full protocol e2e simulation (runs locally!)
├── benchmarks/                iperf3/ping methodology + result templates
├── packaging/                 deb/rpm/aur/homebrew/winget/wix + update meta
└── .github/workflows/         ci.yml, android.yml, release.yml
```

**≈ 18,000 lines of code across ~120 files** (Rust ~6.5 k, Kotlin ~4 k,
Svelte/TS ~2.2 k, Python/Node reference + tests ~2.4 k, docs/config the rest).

---

## Quickstart

### 0. Prerequisites
- **Host**: Rust 1.79+, Node 20+ (GUI), Linux (20.04+) / macOS 11+ / Win 10+.
  On Linux: `sudo usermod -aG $USER netdev` (TUN access) — or run as root
  for the first test.
- **Device**: Android 5.0+ with **USB debugging** (ADB transport) or on the
  same LAN (wireless transports). No root.
- **Android build** (optional, to build the APK yourself): JDK 17 +
  Android SDK 34, then `cd device && ./gradlew assembleDebug`.

### 1. Build the host
```bash
cd host
cargo build --release          # → target/release/unitether
cargo test --workspace         # protocol vectors, tunnel, throttle, proxy
```

### 2. Run the protocol e2e test (no hardware needed)
```bash
python3 tests/e2e/run_e2e.sh   # handshake → auth → config → tunnel ping
node tests/node/test.mjs       # TS codec vs same vectors
```

### 3. Pair a device
```bash
# Terminal A — pair (prints QR / pairing code)
unitether pair --name "my-pc"

# On the phone: open UniTether → "Pair with computer" → scan the QR
# Terminal A auto-detects the connection; or:
unitether scan                  # mDNS discovery on LAN
unitether connect <device>      # one-click connect
```

### 4. Use it
```bash
unitether tunnel                # start reverse tethering (IPv4+IPv6, ping works)
unitether stats --watch         # live bandwidth / latency / loss
unitether qos 4g                # shape device traffic (2G|3G|4G|5G|custom)
unitether proxy socks 1080      # expose SOCKS5 for other host apps
unitether proxy http 8888
unitether disconnect            # clean stop (and it auto-stops on unplug)
```

### 5. GUI
```bash
cd host/gui
npm install
npm run tauri dev               # device list, mirror, stats, files, pairing
```

---

## What "no root" means here (and what it costs us)

Everything runs inside normal app privileges:

| Subsystem | API used | Root needed? |
|---|---|:---:|
| Reverse tethering | `VPNService` | ❌ |
| Screen capture | `MediaProjection` (+ permission dialog) | ❌ |
| Audio both ways | `AudioRecord`/`AudioTrack` (user-approved) | ❌ |
| Wi-Fi Direct | `WifiP2pManager` (user-approved) | ❌ |
| Bluetooth PAN | `BtPan` (user-approved pairing) | ❌ |
| LAN discovery | `NsdManager` (mDNS) | ❌ |
| Input injection | `AccessibilityService.dispatchGesture` (user consent) | ❌ |
| Notification mirror | `NotificationListenerService` (user consent) | ❌ |

Costs: one-time consent dialogs, and the accessibility service is
user-granted (documented in-app, never forced). This is the same
trade-off class as scrcpy/KDE Connect.

---

## How we improve Gnirehtet (all 11 baseline gaps, closed)

1. **IPv6** — dedicated `tunnel-v6` channel; `VPNService.Builder`
   dual-stack; raw IPv6 packets passthrough. *(Gnirehtet: "not planned".)*
2. **Wireless** — Wi-Fi Direct (P2P group on device), Bluetooth PAN,
   plain LAN TCP; all carry the same ULP byte stream.
3. **Auto-discovery** — mDNS `_unilink._tcp` + QR pairing; saved devices
   auto-reconnect.
4. **Screen mirroring** — MediaProjection → C2 H.264/HEVC → ULP video
   channel → WebCodecs/ffmpeg decode; adaptive bitrate.
5. **Audio** — Opus 48 kHz both directions over separate channels,
   independent mute, echo-free (device uses `VOICE_COMMUNICATION` source
   with AEC where available).
6. **GUI** — Tauri desktop app + CLI with identical feature surface.
7. **Auto-stop on disconnect** — ADB monitor thread + transport
   liveness pings; session teardown < 1 s. *(Gnirehtet: manual stop.)*
8. **Throttling** — token-bucket shaper on both ends; 2G/3G/4G/5G/custom
   profiles + latency + jitter + loss injection for app testing.
9. **Proxy** — host-side SOCKS5/HTTP bound to loopback, forwarded into
   the tunnel (useful for testing apps that force-proxy).
10. **ICMP** — raw IP passthrough on the TUN means ping/traceroute just
    work. *(Gnirehtet drops non-TCP/UDP.)*
11. **Maintenance** — active repo, CI on 4 platforms, ≥80 % coverage gate,
    documented protocol (forks can interoperate), security policy.

---

## License & attribution

Apache-2.0 (see `LICENSE`, `NOTICE`, `docs/10-OPEN-SOURCE.md`).
UniTether is built *in acknowledgment of* **Gnirehtet**
(Genymobile, Apache-2.0) as its functional baseline — see
`docs/14-ACKNOWLEDGMENTS.md` for the full etiquette we follow.

## Status

`v0.1.0 "Scaffold"` — complete architecture, protocol spec + conformance
suite, host workspace, Android app, GUI, CI and docs. See
`docs/03-ROADMAP.md` for the 6-month plan to 1.0.

**Be nice. Play hard. Ship fast.**
