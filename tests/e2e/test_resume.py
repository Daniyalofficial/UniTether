#!/usr/bin/env python3
"""Session resumption E2E (Phase 7) over real loopback TCP.

Flow: full v1.1 session (handshake + identity) → link killed → new TCP
connection → fresh handshake → identity exchange → RESUME_REQ/RESUME_OK
with fresh X25519 keys (same pairing secret, negotiated session_id) →
channel-state replay (CONFIG + TUN_UP) → encrypted frame exchange on
the new keys. Negative: wrong-secret resume rejected. Backoff manager
determinism/bounds also covered.
"""
import os
import socket
import sys
import threading
import time

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "protocol"))
sys.path.insert(0, HERE)

import reference_framing as rf  # noqa: E402
import ulp_v11 as v11  # noqa: E402
from ulp_link import Link, Session  # noqa: E402
from reconnect import ReconnectPolicy  # noqa: E402

PASS = FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(f"{name} {detail}")


class MemReg:
    """In-memory trust registry: everything trusted (e2e test)."""

    def decide(self, identity_pub, device_id):
        return v11.DECISION_TRUSTED

    def note_trusted(self, *a, **k):
        pass


def make_listener():
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(8)
    return lsock, lsock.getsockname()[1]


def device_handshake_thread(lsock, secret, run_identity):
    """Accept one connection, run v1 device handshake, optional
    identity exchange. Returns (thread, holder)."""
    holder = {}

    def run():
        try:
            conn, _ = lsock.accept()
            sess = Session(conn, rf.ROLE_DEVICE, secret,
                           os.urandom(32), "dev")
            sess.link = Link(conn, 1, b"\x00" * 32, b"\x00" * 32)
            sess.start_device()
            holder["sess"] = sess
            if run_identity:
                run_identity(sess.link)
        except Exception as e:  # noqa: BLE001
            holder["err"] = e

    th = threading.Thread(target=run, daemon=True)
    th.start()
    return th, holder


def host_connect(port, secret, start_host=True):
    cs = socket.create_connection(("127.0.0.1", port), timeout=15)
    hs = Session(cs, rf.ROLE_HOST, secret, os.urandom(32), "host")
    hs.link = Link(cs, 0, b"\x00" * 32, b"\x00" * 32)
    if start_host:
        hs.start_host()
    return cs, hs, hs.link


def main():
    lsock, port = make_listener()
    secret = os.urandom(32)
    session_id = os.urandom(16)
    dev_id = v11.new_identity()
    dev_id.update(name="Pixel 8", platform="android", app_ver="0.2.0",
                  caps=v11.CAP_NETWORK)
    host_id = v11.new_identity()
    host_id.update(name="host", platform="linux", app_ver="0.2.0",
                   caps=v11.CAP_NETWORK)
    dreg, hreg = MemReg(), MemReg()
    identity_err = {}

    # ---------- original v1.1 session
    th, dh = device_handshake_thread(
        lsock, secret,
        lambda link: _identity(link, rf.ROLE_DEVICE, dev_id, dreg,
                               session_id, identity_err, "dev"))
    cs, hs, hl = host_connect(port, secret)
    _identity(hl, rf.ROLE_HOST, host_id, hreg, session_id, identity_err,
              "host")
    th.join(timeout=10)
    check("resume:original v1.1 session", "err" not in dh and
          "err" not in identity_err,
          f"{dh.get('err')!r} {identity_err!r}")
    ds = dh["sess"]
    dl = ds.link

    hl.send_frame(rf.CH_TUN_V4, 0, b"before-drop")
    check("resume:pre-drop frame", dl.recv_frame().payload == b"before-drop")

    # ---------- kill the link
    cs.close()
    dl.sock.close()
    time.sleep(0.05)

    # ---------- resume on a new connection
    dev_state = {"session_id": session_id, "attempts": 0,
                 "cipher": rf.CIPHER_INTEROP}

    def resume_device(link):
        mtype, _f, body = link.recv_msg()
        assert mtype == v11.MSG_RESUME_REQ, f"got {mtype:#x}"
        r = v11.resume_req_parse(body, secret)
        assert r["session_id"] == dev_state["session_id"]
        dev_state["attempts"] += 1
        fresh = v11.new_identity()
        link.send_msg(v11.MSG_RESUME_OK,
                      v11.resume_ok_body(fresh["pub"], session_id,
                                         r["fresh_pub"], secret))
        shared = rf.x25519(fresh["priv"], r["fresh_pub"])
        ka, km = v11.resume_session_keys(shared, r["resume_nonce"],
                                         session_id, dev_state["cipher"])
        link.ka, link.km = ka, km
        link.tx_counter = 0
        link.rx_counter = 0

    identity_err2 = {}

    def resume_flow(link):
        _identity(link, rf.ROLE_DEVICE, dev_id, dreg, session_id,
                  identity_err2, "dev2")
        resume_device(link)

    th2, dh2 = device_handshake_thread(lsock, secret, resume_flow)
    cs2, hs2, hl2 = host_connect(port, secret)
    # identity exchange on the new connection too (fresh transcript)
    _identity(hl2, rf.ROLE_HOST, host_id, hreg, session_id, identity_err2,
              "host2")
    check("resume:re-handshake ok", "err" not in dh2 and
          "err" not in identity_err2,
          f"{dh2.get('err')!r} {identity_err2!r}")

    # RESUME_REQ / RESUME_OK: host sends REQ, device (thread) replies OK
    fresh_h = v11.new_identity()
    nonce = os.urandom(16)
    hl2.send_msg(v11.MSG_RESUME_REQ,
                 v11.resume_req_body(session_id, fresh_h["pub"], nonce,
                                     secret))
    mtype, _f, body = _recv_with_timeout(hl2, 15)
    check("resume:RESUME_OK received (host side)",
          mtype == v11.MSG_RESUME_OK, f"got {mtype:#x}")
    th2.join(timeout=10)
    if "err" in dh2:
        raise SystemExit(f"device resume flow error: {dh2['err']!r}")
    ds2 = dh2["sess"]
    dl2 = ds2.link
    ok_pub = v11.resume_ok_parse(body, session_id, fresh_h["pub"], secret)
    shared = rf.x25519(fresh_h["priv"], ok_pub)
    ka, km = v11.resume_session_keys(shared, nonce, session_id,
                                     rf.CIPHER_INTEROP)
    hl2.ka, hl2.km = ka, km
    hl2.tx_counter = 0
    hl2.rx_counter = 0

    # channel-state replay
    cfg = rf.config_body(
        20, bytes([10, 8, 0, 2]), bytes([10, 8, 0, 1]), 64,
        bytes.fromhex("fd004c55010000000000000002"),
        bytes.fromhex("fd004c55010000000000000001"),
        [bytes([1, 1, 1, 1])])
    hl2.send_msg(rf.MSG_CONFIG, cfg)
    hl2.send_msg(rf.MSG_TUN_UP, b"")
    m1, _f, _b = _recv_with_timeout(dl2, 15)
    m2, _f, _b = _recv_with_timeout(dl2, 15)
    check("resume:state replay accepted",
          m1 == rf.MSG_CONFIG and m2 == rf.MSG_TUN_UP,
          f"got {m1:#x},{m2:#x}")

    hl2.send_frame(rf.CH_TUN_V4, 0, b"after-resume")
    check("resume:frame on fresh keys",
          dl2.recv_frame().payload == b"after-resume")
    check("resume:attempts counted", dev_state["attempts"] == 1)

    # ---------- negative: wrong secret rejected
    bad = v11.resume_req_body(session_id, fresh_h["pub"], nonce,
                              os.urandom(32))
    try:
        v11.resume_req_parse(bad, secret)
        check("resume:wrong secret rejected", False)
    except ValueError:
        check("resume:wrong secret rejected", True)
    # unknown session id: MAC ok but state must refuse (device logic)
    r = v11.resume_req_parse(v11.resume_req_body(
        os.urandom(16), fresh_h["pub"], nonce, secret), secret)
    check("resume:unknown session id detectable",
          r["session_id"] != dev_state["session_id"])

    # ---------- backoff manager
    p1 = ReconnectPolicy(seed=42)
    p2 = ReconnectPolicy(seed=42)
    s1 = [p1.next_delay() for _ in range(10)]
    s2 = [p2.next_delay() for _ in range(10)]
    check("backoff:deterministic with seed", s1 == s2)
    check("backoff:cap respected", all(d <= p1.cap_s * 1.21 for d in s1),
          str(s1))
    p3 = ReconnectPolicy(max_attempts=4, seed=1)
    seq, exhausted = [], False
    for _ in range(6):
        try:
            seq.append(p3.next_delay())
        except StopIteration:
            exhausted = True
            break
    check("backoff:exhaustion after max_attempts",
          exhausted and len(seq) == 4)
    p4 = ReconnectPolicy(cap_s=8.0, jitter=0.0, seed=2)
    g = [p4.next_delay() for _ in range(6)]
    check("backoff:monotone to cap",
          all(g[i] <= g[i + 1] + 1e-9 for i in range(len(g) - 1))
          and abs(g[-1] - 8.0) < 1e-9, str(g))
    # reset after success
    p5 = ReconnectPolicy(seed=3)
    d_a = p5.next_delay()
    p5.reset()
    check("backoff:reset", p5.next_delay() <= d_a * 1.21)

    lsock.close()
    print(f"RESUME E2E: {PASS} pass, {FAIL} fail")
    if FAILURES:
        for x in FAILURES:
            print("  FAIL", x)
    return 1 if FAIL else 0


def _identity(link, role, identity, reg, session_id, err, who):
    try:
        v11.identity_exchange(link, role, identity, reg, session_id)
    except Exception as e:  # noqa: BLE001
        err[who] = e


def _recv_with_timeout(link, seconds):
    old = link.deadline
    link.deadline = seconds
    try:
        return link.recv_msg()
    finally:
        link.deadline = old


if __name__ == "__main__":
    raise SystemExit(main())
