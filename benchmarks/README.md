# UniTether benchmarks

Loopback (no device) benchmarks for the host protocol stack. These are
the same numbers CI asserts against; device-in-the-loop numbers are in
`benchmarks/device-results/` (regenerated with `bench_device.sh`).

| Benchmark            | Metric                        | Target (CI gate) |
|----------------------|-------------------------------|------------------|
| `bench_loopback.py`  | framing+crypto per frame (µs, Python reference) | < 600 µs RT @ 1 KB (Rust target < 50 µs) |
| `bench_loopback.py`  | tunnel throughput (Gbps)      | > 1 Gbps local   |
| `bench_device.sh`    | mirror one-way latency (ms)   | < 50 ms LAN      |
| `bench_device.sh`    | 4K60 headroom (Mbps sustained)| > 25 Mbps        |
| `bench_device.sh`    | battery drain (%/h)           | < 10 %/h idle    |
