# UniTether

> **The complete bridge between your phone and your computer — internet
> first, screen/sound/files next. No root. One APK + one desktop app.**

UniTether keeps the proven [Gnirehtet](https://github.com/Genymobile/gnirehtet)
baseline — *reverse tethering over a no-root Android `VPNService` into a host
TUN device* — and grows it: a versioned, cryptographic protocol (ULP v1.1),
identity-based pairing, QoS scheduling, host proxy, and a real desktop GUI.

**Status: v0.2.0-dev.** Networking is implemented and tested end-to-end;
the GUI is complete; screen/audio/input/file/SMS/camera channels are
protocol-complete with device services in place and host-side rendering
in progress. Nothing below is claimed beyond what is built and tested —
see [`docs/27-FINAL-PRODUCTION-READINESS.md`](docs/27-FINAL-PRODUCTION-READINESS.md)
for the full IMPLEMENTED / PARTIAL / BLOCKED matrix.

---

## Feature status (honest)

| Capability | Status | Notes |
|---|---|---|
| Reverse tethering (no-root `VPNService` → host TUN) | ✅ implemented, tested | ADB + LAN/TCP transports, e2e on real TCP |
| Protocol ULP v1 + v1.1 | ✅ implemented, tested | X25519 pairing, replay cache, nonce mgmt, downgrade floor; 83+107+54 vectors |
| Pairing (QR → verify → authorize → connect) | ✅ implemented | identity-based (stable ID + pubkey + trust registry), never name-based |
| Session state machine + limits | ✅ implemented, tested | 12 states, 107 state tests; hard limits on every network-controlled value |
| QoS channel scheduler | ✅ implemented, tested | CONTROL > INPUT > AUDIO > VIDEO > FILE, no starvation (732 tests) |
| Dual-stack tunnel (IPv4 + IPv6) + custom DNS | ✅ implemented | Gnirehtet had IPv4 only |
| ICMP / raw IP passthrough | ✅ implemented | ping/traceroute work over TUN |
| Host proxy (SOCKS5 + HTTP, bypass list) | ✅ implemented | forwards host apps into the tunnel |
| GUI (Tauri 2 + Svelte) | ✅ implemented, builds clean | Dashboard / Devices / Pairing / Settings, live stats, 6 locales incl. RTL |
| i18n (en/ur/ar/es/zh/hi) | ✅ implemented + automated | Android strings + GUI catalogs checked in CI (keys/placeholders/RTL) |
| File transfer | ✅ protocol + engine (v2) | chunking, SHA-256, 10 GB @ 97 % resume verified by test; UI panel pending |
| Screen mirroring | 🟡 partial | device capture (MediaProjection + H.264) and video channel implemented; host decoder/renderer pending |
| Audio (Opus, both directions) | 🟡 partial | device bridge + JNI (opus or stub) and audio channel implemented; host playback pending |
| Remote input (touch/keys/text) | 🟡 partial | `InputInjector` + input channel implemented; host-side driver pending |
| Clipboard / notifications / SMS reply | 🟡 partial | device bridges implemented over ULP channels; host consumers pending |
| Camera as host webcam | 🟡 partial | device bridge implemented; host UVC pending |
| mDNS auto-discovery + ADB discovery | ✅ implemented | `_unilink._tcp` + `adb devices` on the host |
| Wireless: Wi-Fi Direct / BT-PAN | ⬜ planned | not started; LAN + ADB cover v0.2 |
| Network throttling (2G–5G profiles) | ⬜ planned | not started (QoS scheduler is per-channel, not a link shaper) |
| Cloud/relay | ⬜ planned (optional by design) | local-only must always work; relay would never see plaintext |

**Constraints honored:** no root anywhere, Android 5.0 (API 21)+,
host targets Windows 10+ / macOS 11+ / Ubuntu 20.04+.

---

## Repository tree (actual)

```
UniTether/
├── README.md
├── LICENSE / NOTICE / SECURITY.md / CHANGELOG.md / CONTRIBUTING.md
├── Makefile                     ← make test / i18n / gui / gui-build / android
├── docs/
│   ├── 01..15                   architecture, protocol spec, testing, i18n, …
│   ├── 16-SECURITY-AUDIT.md     pre-1.0 audit status
│   ├── 26-DIFFERENTIATION.md
│   ├── 27-FINAL-PRODUCTION-READINESS.md   ← implemented/partial/blocked matrix
│   └── 28-QUICKSTART.md         ← what to start, in what order, how to use each screen
├── protocol/vectors/            canonical protocol test vectors (JSON)
├── host/
│   ├── Cargo.toml               Rust workspace
│   ├── crates/
│   │   ├── protocol/            ULP framing/codec — std-only, vector-tested
│   │   ├── transport/           Transport trait, Framed reservoir, Session<T>
│   │   ├── tunnel/              TUN engine (linux/macos/windows + null)
│   │   ├── proxy/               SOCKS5 + HTTP host proxy
│   │   └── unitether/           CLI binary
│   └── gui/                     Tauri 2 + Svelte 4 desktop app
│       ├── src/                 views (Dashboard/Devices/Pairing/Settings),
│       │                        store, backend adapter (real Tauri ↔ labelled sim)
│       └── src-tauri/           commands: list_devices, connect, disconnect,
│                                tunnel_config, proxy_config, get_stats, get_pairing
├── device/                      Android app (Kotlin, no root, minSdk 21)
│   ├── gradlew                  (official Gradle 8.5 wrapper)
│   └── app/src/main/
│       ├── AndroidManifest.xml
│       ├── res/                 values{,ur,ar,es,zh,hi}/strings.xml — 6 locales
│       ├── jni/opus_jni.c       Opus JNI (passthrough stub if libopus absent)
│       └── java/com/unilink/
│           ├── core/            ULP v1+v1.1 codec, crypto, channels, pairing,
│           │                    trust registry, session state
│           ├── transport/       DeviceTransport (TCP/ADB), mDNS advertise
│           ├── tunnel/          TunnellingService (no-root VPNService)
│           ├── mirror/          MirroringService, ScreenCapturer
│           ├── audio/           AudioBridgeService, OpusJni
│           ├── camera/          CameraBridge
│           ├── input/           InputInjector
│           ├── productivity/    BootReceiver, ClipboardBridge, FileTransfer,
│           │                    NotificationMirror, SmsReplier
│           └── ui/              PairingQr
├── tests/
│   ├── protocol/                Python reference (stdlib only): vectors, state,
│   │                            v1.1, limits, scheduler, obs, session, file,
│   │                            security, fuzz (7 targets)
│   ├── node/                    JS codec conformance (212 assertions, no deps)
│   ├── e2e/                     real-TCP e2e, resume, chaos (20 scenarios)
│   └── i18n/                    Android + GUI i18n consistency checkers
├── benchmarks/                  loopback benchmark (245 µs frame path)
├── packaging/                   android-ndk.sh (libopus cross-compile + APK)
└── .github/workflows/ci.yml     5 jobs: protocol, rust, android, gui, benchmarks
```

≈ 18,400 lines of code (Rust 6.1 k, Kotlin 3.2 k, GUI 0.9 k, tests 8.1 k).

---

## Quickstart — what to start, in what order

Full walkthrough (every screen, real-hardware order, dev commands):
**[`docs/28-QUICKSTART.md`](docs/28-QUICKSTART.md)**. The short version:

### A. Try the GUI now (browser, no install)

Open the live preview — you get the full UI against a clearly-labelled
**simulation** (badge always visible): Devices → Connect → Pairing (QR) →
Dashboard (tunnel toggles, DNS, proxy, live stats) → Settings (6 languages,
RTL for ur/ar).

### B. Real reverse tethering (phone + host)

```
Phone:  1. install APK → allow VPN + foreground (no root, no adb needed)
        2. app advertises via mDNS and shows the pairing QR
Host:   3. cd host/gui && npm install && npm run tauri dev
        4. Devices screen: phone appears → Connect (or Pairing → scan QR)
        5. Dashboard: IPv4/IPv6 on → set DNS → Apply
        6. phone internet now flows through the host's TUN
```

### C. Verify without hardware

```bash
make test          # protocol vectors → state → v1.1 → limits → QoS → obs →
                   # session → file → security → fuzz → resume → chaos →
                   # node → E2E real-TCP → i18n → rust → gui build
bash tests/e2e/run_e2e.sh
```

### D. Build the artifacts

| Artifact | Command | Verified by |
|---|---|---|
| Desktop app (Win/macOS/Linux) | `make gui` (Tauri release) | `gui` CI job (frontend); Tauri cross-builds on your OS |
| APK (arm64-v8a, armeabi-v7a, x86_64) | `bash packaging/android-ndk.sh build` | `android` CI job (hard gate, artifact uploaded) |
| CLI | `cd host && cargo build --release` | `rust` CI job (build + clippy `-D warnings` + test) |

> APK build needs JDK 17 + Android SDK 34 + NDK 26 (the CI job provisions
> them automatically; see the BLOCKED section in docs/27 for sandbox notes).

---

## Security (summary)

- **Crypto**: X25519 (RFC 7748, audited), HKDF, AES-GCM, HMAC-SHA256 — no
  invented primitives; reference implementation pinned by 83 golden vectors.
- **Pairing is identity-based**: stable device ID + public key + trust
  registry; register / revoke / re-pair; never device-name based.
- **Replay + downgrade protected**: replay cache with eviction, nonce
  management, protocol version floor (v1.1 pin tests).
- **Limits**: every network-controlled value bounded (19 dedicated tests).
- **Audit**: 54 security tests (replay, downgrade, MITM, malformed, brute
  force, exhaustion, path traversal) + 7 fuzz targets in CI + 20 chaos
  scenarios. Full model: [`SECURITY.md`](SECURITY.md), status:
  [`docs/16-SECURITY-AUDIT.md`](docs/16-SECURITY-AUDIT.md).
- **Privacy**: telemetry is metadata-only and consented; no payloads,
  clipboard, SMS, screen or camera content in logs or metrics.

## Testing & CI (honest)

- **CI runs on `ubuntu-latest` only** (5 jobs: protocol conformance, Rust
  build/clippy/test, Android release APK, GUI build + GUI i18n, benchmarks).
  There is **no coverage gate** and **no Windows/macOS CI runner** yet —
  desktop matrix builds are a v1.0 item (docs/27).
- Test totals at HEAD: 212 node assertions, 83 vectors, 107 state, 54 v1.1,
  23 v1.1 pin, 19 limits, 732 scheduler/property, 38 observability, 26
  session, 23 file-v2, 54 security, 7 fuzz targets (500 iters in CI),
  14 resume, 20 chaos, 124+9 i18n checks.

## i18n

6 locales: en, ur, ar (both RTL), es, zh, hi — on the device
(`res/values-*/strings.xml`) **and** in the GUI (JSON catalogs + RTL layout
switch). Consistency is enforced by `make i18n` / CI: key parity,
placeholder parity, RTL set, no empty values, and every `t()` key in the
Svelte views must exist.

---

## License & attribution

Apache-2.0 (`LICENSE`, `NOTICE`). UniTether is built in acknowledgment of
**Gnirehtet** (Genymobile, Apache-2.0) as its functional baseline —
etiquette in `docs/14-ACKNOWLEDGMENTS.md`.
