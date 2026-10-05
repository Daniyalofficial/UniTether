# 12 — Benchmarks: Methodology + Comparison

## Methodology (reproducible)
- **Throughput**: `iperf3 -P 4` over the tunnel (device app →
  `iperf3 -s` on host), 30 s runs, median of 5. Baselines: direct LAN
  (no tunnel), Gnirehtet v2.5.1 on the same hardware.
- **Latency**: `ping -i 0.2` 500 samples, p50/p95/p99; mirror latency
  = device frame `pts_ms` → host render timestamp (instrumented in
  GUI, glass-to-glass measured with a camera + high-speed webcam on
  the phone screen for the "true" number, ±1 frame).
- **Battery**: `dumpsys battery unplug` + full charge → 1 h tether-only
  at 50 Mbit, Δ% on 3 phones (R8).
- **CPU**: `top`/`perf stat` host + `amprofile` device, 10-min window.
- Hardware reference: host = Ryzen 7 5800X / Intel i5-12400 (LAN),
  device = Pixel 6 (reference), Redmi 12 (floor).

## Expected results (hypotheses we benchmark against)

| Metric | Gnirehtet v2.5.1 (expected) | scrcpy (expected) | **UniTether target** |
|---|---|---|---|
| Tunnel throughput (LAN, IPv4) | ~92 % of line | n/a | **≥ 95 % of line** (zstd only on control; tunnel raw) |
| IPv6 | ✗ unsupported | n/a | **≥ 95 % of line** |
| Tunnel overhead (per-packet) | ~24 B (UDP framing) | n/a | **≤ 34 B** (ULP header + AEAD tag; 8/12 B hdr + 16 tag) |
| Ping (device→host) | works (UDP) | n/a | **works, raw ICMP** |
| Mirror latency p95 (1080p60 LAN) | n/a | ~20–40 ms (USB) | **< 50 ms** (LAN) / < 80 ms (Wi-Fi) |
| 4K60 | ✗ |  (USB only) | **HEVC, ≥ 90 % of 25 Mbps** |
| QoS accuracy (4G profile) | ✗ | ✗ | **±15 %** |
| Battery/h (tether only) | ~6–9 % (measured) | ~4 % (mirror) | **< 10 %** (target), measured |

## Scripts
- `benchmarks/bench_tput.sh` — iperf3 matrix + CSV out
- `benchmarks/bench_latency.sh` — ping + mirror p95 harness
- `benchmarks/bench_battery.sh` — battery delta loop
- `benchmarks/RESULTS.md` — populated per release (template included)

**Reporting rule**: every published number includes hardware, OS
versions, and the exact command line. No cherry-picked averages.
