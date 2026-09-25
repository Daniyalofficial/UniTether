# 04 — Technology Stack & Justification

## 1. Host core: **Rust** (chosen) vs Go vs C++

| Criterion | Rust | Go | C++ |
|---|---|---|---|
| Zero-copy framing perf | ✅ SIMD-friendly, no GC pauses | ~ good, GC jitter (ms-scale) | ✅ |
| TUN / syscalls | ✅ `libc`/`windows-sys`, safe wrappers | ✅ via `golang.org/x/sys` | ✅ |
| Memory safety (no root = trust surface) | ✅ compile-time | ✅ runtime | ❌ manual |
| Single static binary (all 3 OS) | ✅ | ✅ (CGO off) | ~ toolchain per OS |
| Concurrency model for per-packet paths | ✅ threads + `tokio`, no stop-the-world | ✅ goroutines (GOMAXPROCS) | ~ manual |
| Ecosystem: crypto (x25519/chacha), mDNS, tun, Tauri | ✅ best-in-class | ⚠ `x/crypto` good, no Tauri | ⚠ fragmented |
| GUI integration | ✅ **Tauri** (Rust core + webview) | ❌ needs cgo bridge or second runtime | ~ Qt/native only |
| Team hiring (systems + product) | ~ harder than Go | ✅ easiest | ~ hardest |
| Precedent | scrcpy host (C), adb (C), **Gnirehtet rust version** | — | scrcpy |

**Decision: Rust.** The tie-breaker is the *one-language-to-GUI*
property: the tunnel engine, the protocol codec and the Tauri shell are
the same language, so a session object is shared between CLI and GUI
with zero IPC friction. Go wins on hiring ease but forces a second
runtime for the desktop shell; C++ wins on raw ceiling we don't need
and loses on safety. Budget for the Rust hiring cost is in `07-TEAM.md`.

## 2. Android: **Kotlin** (+ C via NDK only for codecs)

- Kotlin 1.9 on JVM target 1.8, minSdk 21, targetSdk 34: matches
  Gnirehtet's floor (API 21) so the device fleet overlap is maximal.
- Compose UI (works on API 21+ with desugaring) for modern, small UI.
- NDK C **only** where the JVM is slow: Opus encode/decode (`libopus`),
  and later AV1 decode. Everything else Kotlin — permissions, services,
  MediaProjection, AudioRecord, NsdManager are all Java/Kotlin APIs.
- Why not Rust-on-Android (UniFFI) for the protocol crate? We *could*,
  and the protocol crate is deliberately std-only to make that a
  non-breaking future option. For v1, framing in Kotlin is ~400 LOC and
  keeps the APK dependency graph small.

## 3. GUI: **Tauri 2 + Svelte 4** (justification, as requested)

- **Tauri vs Electron**: Tauri uses the OS webview + a Rust backend →
  3–6 MB vs 80 MB+, 10× lower idle RAM, and the backend *is* our Rust
  engine (no IPC serialization of session state). Electron would mean
  either a sidecar binary (two processes, two update streams) or porting
  the engine to JS (no TUN access in JS).
- **Tauri vs native (Qt/WinUI/Swift)**: one codebase for Win/macOS/Linux,
  fast iteration, and the mirror view needs a *video canvas* —
  WebCodecs + `<canvas>` is the fastest path to H.264/HEVC rendering
  on desktop (WebView2 110+, Safari 16.4+). Qt would need FFmpeg
  plumbing per-OS for the same result.
- **Svelte 4 vs React**: smaller bundle, compiler-driven reactivity
  (cheap for a 60 fps stats panel), first-class `svelte-i18n` story for
  the 6 locales; team preference otherwise neutral.
- **Crypto in GUI**: none. All AEAD stays in Rust; the webview only
  ever sees decrypted NAL units via Tauri events (attack surface
  minimized: webview is sandboxed, credentials never cross the bridge).

## 4. Key libraries (pinned in Cargo.lock / package.json / Gradle)

| Concern | Choice | Notes |
|---|---|---|
| Async runtime (host) | `tokio` 1.x | multi-thread, io_uring on Linux later |
| TUN (Linux) | direct `/dev/net/tun` + `libc` ioctl | no extra driver; `netdev` group |
| TUN (macOS) | `utun` via `UTUN` ioctls | `com.apple.VirtualInterface` |
| TUN (Windows) | **WinTun** driver | standard, free, signed |
| mDNS (host) | `mdns-sd` | `_unilink._tcp` |
| Crypto | `x25519-dalek`, `hkdf`, `sha2`, `aes-gcm`, `chacha20poly1305` | audited crates |
| Compression | `zstd` (0.13+) | 3× better than flate, hardware on recent CPUs |
| QR | `qrcode` (host), ZXing core (device) | pairing |
| Proxy | hand-rolled SOCKS5 (RFC 1928) + HTTP/1.1 CONNECT | 300 LOC, no deps |
| GUI | `tauri` 2, `svelte` 4, `vite` 5 | |
| Android | AGP 8.5, Kotlin 1.9.24, Compose BOM, coroutines, ZXing | minSdk 21 |
| Audio codec | `libopus` (BSD) via NDK; `cpal` for host audio later | Opus 48 kHz |

## 5. What we deliberately do NOT use
- **smoltcp** (host): the host already has a kernel IP stack via TUN;
  smoltcp would be a second stack. We keep it as a reference for the
  device-side *future* pure-Rust appliance (no kernel VPN on
  Android 5 without VPNService anyway).
- **WebRTC** for mirroring: too heavy, P2P signaling we don't need,
  codec control (keyframe cadence, 4K) is worse than direct H.264/HEVC.
- **Any root/Magisk/adb-shell dependency**: non-negotiable (see README).
