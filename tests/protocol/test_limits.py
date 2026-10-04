#!/usr/bin/env python3
"""Resource limits + structured errors (Phases 8/46)."""
import os
import socket
import sys
import threading

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "e2e"))

import reference_framing as rf  # noqa: E402
import ulp_v11 as v11  # noqa: E402
from limits import (BoundedControlQueue, FileTransferGovernor, Limits)  # noqa: E402
from ulp_link import Link, Session, ULPError  # noqa: E402

PASS = FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(f"{name} {detail}")


def main():
    # ---- limits sanity
    check("limits:frame max", Limits.MAX_FRAME_BYTES == rf.MAX_PAYLOAD)
    check("limits:reserved flags",
          Limits.RESERVED_FLAGS == (rf.F_COMPRESSED | rf.F_FRAG))

    # ---- structured error codes
    check("errors:framing code", rf.FramingError("x").code == v11.ERR_FORMAT)
    check("errors:auth code", rf.AuthError("x").code == v11.ERR_AUTH)
    e = rf.FramingError("bad", correlation_id="s-42")
    check("errors:correlation id", e.correlation_id == "s-42")
    check("errors:retryable flags",
          rf.FramingError().retryable is False
          and rf.TimeoutError_().retryable is True
          and rf.TimeoutError_().code == v11.ERR_TIMEOUT)
    # wire round-trip of the structured error
    wire = v11.error_body(True, e.code, str(e))
    p = v11.error_parse(wire)
    check("errors:wire roundtrip", p["code"] == e.code and p["msg"] == str(e))

    # ---- reserved flag rejection over a real socket pair
    a, b = socket.socketpair()
    la = Link(a, 0, b"\x11" * 32, b"\x22" * 32, encrypted=False)
    lb = Link(b, 1, b"\x11" * 32, b"\x22" * 32, encrypted=False)
    # F_COMPRESSED frame from "peer"
    frame = rf.Frame(rf.CH_VIDEO, rf.F_COMPRESSED, b"xyz")
    a.sendall(frame.encode())
    try:
        lb.recv_frame()
        check("limits:compressed rejected", False)
    except ULPError as e:
        check("limits:compressed rejected",
              e.code == v11.ERR_FORMAT and "reserved" in str(e))
    # F_FRAG
    frame = rf.Frame(rf.CH_VIDEO, rf.F_FRAG, b"xyz")
    a.sendall(frame.encode())
    try:
        lb.recv_frame()
        check("limits:frag rejected", False)
    except ULPError:
        check("limits:frag rejected", True)
    # normal frame still fine
    frame = rf.Frame(rf.CH_VIDEO, 0, b"ok")
    a.sendall(frame.encode())
    check("limits:normal frame ok", lb.recv_frame().payload == b"ok")
    a.close(); b.close()

    # ---- oversized extended frame rejected by framing
    try:
        rf.Frame(rf.CH_FILE, 0, b"x" * (rf.MAX_PAYLOAD + 1)).encode()
        check("limits:oversize frame rejected", False)
    except (FramingErrorOverflow := rf.FramingError):
        check("limits:oversize frame rejected", True)

    # ---- bounded control queue
    q = BoundedControlQueue(limit=4)
    for i in range(10):
        q.push(i)
    check("queue:bounded", len(q) == 4 and q.dropped == 6)
    check("queue:order", q.pop() == 6 and q.pop() == 7)

    # ---- file governor
    g = FileTransferGovernor()
    g.begin(1, 1000)
    check("file:progress ok", g.progress(1, 500))
    check("file:over total rejected", not g.progress(1, 600))
    check("file:end incomplete", not g.end(1))
    g.begin(2, 50)
    g.progress(2, 50)
    check("file:end complete", g.end(2))
    try:
        g.begin(3, Limits.MAX_FILE_SIZE + 1)
        check("file:too large rejected", False)
    except ValueError:
        check("file:too large rejected", True)
    for i in range(Limits.MAX_CONCURRENT_FILES):
        g.begin(100 + i, 10)
    try:
        g.begin(999, 10)
        check("file:concurrency cap", False)
    except ValueError:
        check("file:concurrency cap", True)

    print(f"LIMITS+ERRORS: {PASS} pass, {FAIL} fail")
    for x in FAILURES:
        print("  FAIL", x)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
