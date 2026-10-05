#!/usr/bin/env bash
# Full protocol E2E suite:
#   1. Python host harness  <-> Python simulated device (real TCP, AEAD)
#   2. Node host codec      <-> Python simulated device (real TCP, AEAD)
# No hardware, no deps beyond Python 3.9+ stdlib (+ Node 18+ for stage 2).
set -u
cd "$(dirname "$0")/../.."
PORT="${PORT:-41887}"
SECRET="${SECRET:-$(python3 -c 'print(bytes(range(32)).hex())')}"
NODE_STAGE=0
RC_TOTAL=0

echo "=== UniTether protocol E2E (port $PORT) ==="

# ---- stage 1: Python <-> Python
echo "--- stage 1: python host harness vs python device"
python3 tests/e2e/device_sim.py --port "$PORT" --secret "$SECRET" &
DEV_PID=$!
sleep 0.5
RC=0
python3 tests/e2e/host_harness.py --port "$PORT" --secret "$SECRET"
RC=$?
wait $DEV_PID
DEV_RC=$?
echo "stage1 harness exit=$RC device exit=$DEV_RC"
[ "$RC" -eq 0 ] && [ "$DEV_RC" -eq 0 ] || RC_TOTAL=1

# ---- stage 2: Node <-> Python (if node is available)
if command -v node >/dev/null 2>&1; then
  NODE_STAGE=1
  PORT2=$((PORT + 1))
  echo "--- stage 2: node host vs python device (port $PORT2)"
  python3 tests/e2e/device_sim.py --port "$PORT2" --secret "$SECRET" &
  DEV2=$!
  sleep 0.5
  RC2=0
  node tests/node/e2e.mjs --port "$PORT2" --secret "$SECRET"
  RC2=$?
  wait $DEV2
  DEV2_RC=$?
  echo "stage2 node exit=$RC2 device exit=$DEV2_RC"
  [ "$RC2" -eq 0 ] && [ "$DEV2_RC" -eq 0 ] || RC_TOTAL=1
else
  echo "--- stage 2: skipped (node not found)"
fi

echo
if [ "$RC_TOTAL" -eq 0 ]; then
  echo "E2E: ALL PASS (stages: python=$([ $NODE_STAGE -eq 1 ] && echo 1 || echo -) node=$NODE_STAGE)"
else
  echo "E2E: FAILURE"
fi
exit $RC_TOTAL
