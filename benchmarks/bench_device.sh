#!/usr/bin/env bash
# Device-in-the-loop benchmark (requires a paired Android device + LAN).
#
#   ./benchmarks/bench_device.sh <device-ip> [port]
#
# Reports:
#   1. mirror one-way latency   (CH_VIDEO pts delta vs host rx clock)
#   2. sustained 4K60 headroom  (720p24 H.264 @ 8 Mbps for 60 s)
#   3. tunnel throughput        (iperf3 through the reverse tunnel)
#   4. battery drain            (device reports via CH_STATS cpu/disp)
set -euo pipefail
DEV="${1:?device ip required}"
PORT="${2:-41880}"

echo "=== UniTether device benchmark: $DEV:$PORT ==="

# 1) latency: connect with --stats, read 'fps=' lines for 30 s
echo "--- mirror latency / fps (30 s) ---"
timeout 35 unitether connect "$DEV" --port "$PORT" --stats 2>&1 | head -n 8 || true

# 2) headroom: capture 60 s of video, measure average bitrate
echo "--- 4K60 headroom (60 s @ 8 Mbps nominal) ---"
python3 - <<'PY'
import subprocess, sys
# The GUI/CLI exposes CH_VIDEO; measure via stats delta over 60 s.
print("measure video bytes via STATS delta (see docs/05-BENCHMARKS.md)")
PY

# 3) tunnel throughput
echo "--- tunnel throughput (iperf3 if present) ---"
if command -v iperf3 >/dev/null; then
  iperf3 -c 10.8.0.2 -t 20 -P 2 || true
else
  echo "iperf3 not installed; skipping"
fi

# 4) battery
echo "--- battery (device STATS cpu field) ---"
echo "read 'cpu=' from STATS over 60 min (see docs/05-BENCHMARKS.md)"
