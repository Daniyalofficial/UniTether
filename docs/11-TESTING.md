# 11 — Testing Strategy

## Pyramid

```
                 /  e2e  \        20 scenarios (real + simulated)
               / integration \     host↔device protocol, transports
             /    component     \   tunnel, QoS, proxy, mirror pipeline
            /      unit tests    \  protocol codec, shaper, codecs, msgs
```

## Unit (per crate, CI on every PR)
- `unilink-protocol`: **vector-driven** — every frame/message in
  `protocol/vectors/*.json` round-trips and matches golden bytes.
  Property tests: random valid frames → encode → decode identity;
  malformed headers (bad magic, bad extended length, unknown channel
  after handshake) → `ProtocolError`, never panic.
- `unilink-tunnel`: token-bucket math (deterministic clock), loss/
  latency injector distribution, stats counter overflow (u64 wrap).
- `unilink-proxy`: SOCKS5 handshake state machine incl. auth fail,
  HTTP CONNECT method table, loopback bind checks.
- Coverage gate: **tarpaulin ≥ 80 %** lines per crate (`ci.yml`).

## Conformance (cross-language, CI on every PR)
- **Python reference** (`tests/protocol/reference_framing.py`):
  pure-stdlib implementation of ULP v1 (framing, messages, INTEROP
  cipher, X25519) + vector validation.
- **Node codec** (`tests/node/`): TypeScript codec (same code as the
  GUI's `lib/protocol.ts`) validated against the *same* vectors.
- **E2E simulation** (`tests/e2e/`): Python "device" + Python "host
  harness" over real TCP: HELLO→ACK→AUTH_OK→CONFIG→TUN_UP, then
  **real ICMP echo request/reply** over TUN_V4, a video frame burst,
  audio frames, clipboard sync, QOS application. Runs in < 5 s, no
  hardware. This is the protocol's "unit test suite at session scale".

## Integration (nightly + release)
- Host ↔ **device simulator** (full `device-sim.py` with fake
  VPN/MediaProjection producers).
- Real-device matrix (device farm, Phase 2+): Pixel 6 (flagship),
  Redmi 12 (budget), Samsung S23 (OEM), Android 11/13/15.
- Transport matrix: ADB-USB, LAN (Wi-Fi 5), WiFi-Direct.
- Soak: 8 h tether at 50 Mbit + 1080p60 mirror; assert leak
  (RSS slope < 5 MB/h), no TUN fd leak, battery delta.

## E2E (release gate)
- The **MVP acceptance script** (`08-MVP.md`) automated where
  possible (pair, connect, ping4/6, unplug, mirror latency, clipboard).
- 3-phone cross-test per release candidate.

## Fuzzing (continuous)
- `cargo fuzz` targets: `frame_decode`, `message_parse`, `socks5_parse`
  (72 h soak pre-1.0, R9).
- libFuzzer for NDK Opus glue (buffer overflows at codec boundary).
- ASan/UBSan builds of the workspace in CI (Linux job).

## What we intentionally don't test
- 4K/AV1 encoder matrix on every device (cost) — sampled on 3 phones
  weekly, full matrix at release candidates only.
- Bluetooth PAN (flaky hardware; manual checklist per release).
