#!/usr/bin/env python3
"""Host loopback benchmark: framing + handshake + crypto throughput.

Spins a full ULP session pair (host + device roles) on localhost TCP,
exchanges N encrypted frames of the given payload size, and reports
per-frame RT latency + bi-directional throughput. Uses the same
conformance code path as tests/e2e (tests/e2e/ulp_link.py).

Usage:
    python3 benchmarks/bench_loopback.py [--size 1024] [--frames 2000]
"""
import argparse
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tests", "e2e"))
import ulp_link as ulp  # noqa: E402  (stdlib-only conformance code)
from ulp_link import Link, Session, ULPError  # noqa: E402
import reference_framing as rf  # noqa: E402  (via ulp_link's own import)


def run(size: int, frames: int):
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    port = lsock.getsockname()[1]
    lsock.listen(1)
    secret = os.urandom(32)
    error = []

    def device_side():
        try:
            conn, _ = lsock.accept()
            priv = os.urandom(32)
            sess = Session(conn, rf.ROLE_DEVICE, secret, priv, "bench-dev")
            sess.link = Link(conn, 1, b"\x00" * 32, b"\x00" * 32)
            sess.start_device()
            got = 0
            while got < frames:
                f = sess.link.recv_frame()
                got += 1
                sess.link.send_frame(f.channel, 0, b"\x00" * 8)
            return got
        except Exception as e:  # noqa: BLE001
            error.append(e)
            return 0

    th = threading.Thread(target=device_side, daemon=True)
    th.start()
    time.sleep(0.05)

    conn = socket.create_connection(("127.0.0.1", port), timeout=30)
    priv = os.urandom(32)
    sess = Session(conn, rf.ROLE_HOST, secret, priv, "bench-host")
    sess.link = Link(conn, 0, b"\x00" * 32, b"\x00" * 32)
    sess.start_host()  # full X25519 + MAC handshake
    payload = os.urandom(size)
    time.sleep(0.02)

    t0 = time.perf_counter()
    for _ in range(frames):
        sess.link.send_frame(rf.CH_TUN_V4, 0, payload)
        ack = sess.link.recv_frame()
        assert ack.channel == rf.CH_TUN_V4
    dt = time.perf_counter() - t0
    th.join(timeout=10)
    conn.close()
    lsock.close()
    if error:
        raise SystemExit(f"device side failed: {error[0]}")

    total_bytes = frames * (size + 8) * 2
    gbps = total_bytes * 8 / dt / 1e9
    us = dt / frames * 1e6
    print(f"size={size} B  frames={frames}  (handshake + {frames} encrypted RTs)")
    print(f"  rt frame latency : {us:8.2f} us  (one-way {us / 2:.2f} us)")
    print(f"  bi-directional   : {gbps:8.3f} Gbps")
    return us


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--size", type=int, default=1024)
    ap.add_argument("--frames", type=int, default=2000)
    args = ap.parse_args()
    us = run(args.size, args.frames)
    # Gate is calibrated for the pure-Python reference implementation
    # (measured 270-330 us RT on a 2-core CI runner). The production
    # Rust stack (host/crates) targets < 50 us RT on the same workload
    # per docs/05-BENCHMARKS.md; this gate protects the conformance
    # code path from regressions, not the production binary.
    ok = us < 600
    print(f"GATE: {'PASS' if ok else 'FAIL'} (per-frame RT {us:.2f} us < 600 us, python reference)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
