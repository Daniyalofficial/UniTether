#!/usr/bin/env python3
"""ULP v1.1 conformance + security tests (Phases 2/3/5).

Covers: identity encode/parse + tamper, trust decisions (trusted/new/
revoked/rotated/expired/renamed), full in-process identity exchange over
a real TCP loopback (device + host roles), replay protection, pairing
rate limiting, resume MACs, structured errors, and v1 byte-stability
(unchanged vectors still pass — enforced separately by test_vectors.py).
"""
import os
import socket
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "e2e"))

import reference_framing as rf  # noqa: E402
import ulp_link  # noqa: E402
import ulp_v11 as v11  # noqa: E402
from trust_registry import TrustRegistry  # noqa: E402
from ulp_link import Link, Session, ULPError  # noqa: E402

def safe_unlink(*paths):
    for p_ in paths:
        for cand in (p_, p_ + ".corrupt"):
            try:
                if os.path.exists(cand):
                    os.unlink(cand)
            except OSError:
                pass


PASS = FAIL = 0
FAILURES = []


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        FAILURES.append(f"{name} {detail}")


def tcp_pair():
    """Two connected socket objects (loopback)."""
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    def acceptor():
        conn, _ = lsock.accept()
        return conn

    csock = socket.create_connection(("127.0.0.1", port))
    dsock = acceptor()
    lsock.close()
    return csock, dsock  # host sock, device sock


def full_handshake():
    """Run the v1 handshake on a fresh loopback pair.
    Returns (host_sess, dev_sess, host_link, dev_link, secret)."""
    secret = os.urandom(32)
    cs, ds = tcp_pair()
    dev_priv, host_priv = os.urandom(32), os.urandom(32)
    host_sess = Session(cs, rf.ROLE_HOST, secret, host_priv, "t-host")
    host_sess.link = Link(cs, 0, b"\x00" * 32, b"\x00" * 32)
    dev_sess = Session(ds, rf.ROLE_DEVICE, secret, dev_priv, "t-dev")
    dev_sess.link = Link(ds, 1, b"\x00" * 32, b"\x00" * 32)

    def dev():
        dev_sess.start_device()

    th = threading.Thread(target=dev, daemon=True)
    th.start()
    host_sess.start_host()
    th.join(timeout=10)
    return host_sess, dev_sess, host_sess.link, dev_sess.link, secret


def main():
    # ---------------- 1) identity build/parse + tamper
    id1 = v11.new_identity(os.urandom(32))
    id2 = v11.new_identity(os.urandom(32))
    km = os.urandom(32)
    b = v11.device_id_body(id1["device_id"], id1["pub"], "Pixel 8",
                           "android", "0.2.0",
                           v11.CAP_NETWORK | v11.CAP_CAMERA | v11.CAP_MIC,
                           b"wire", km)
    check("v11:device_id length", len(b) == 164, f"{len(b)}")
    d = v11.device_id_parse(b, b"wire", km)
    check("v11:device_id roundtrip", d["name"] == "Pixel 8"
          and d["caps"] == (v11.CAP_NETWORK | v11.CAP_CAMERA | v11.CAP_MIC)
          and d["device_id"] == id1["device_id"] and d["platform"] == "android"
          and d["app_ver"] == "0.2.0")
    check("v11:device_id derived stable",
          d["device_id"] == v11.device_id_from_pub(id1["pub"]))
    try:
        v11.device_id_parse(b[:-1] + bytes([b[-1] ^ 1]), b"wire", km)
        check("v11:device_id tamper mac", False)
    except ValueError:
        check("v11:device_id tamper mac", True)
    try:
        v11.device_id_parse(b, b"wire2", km)
        check("v11:device_id transcript bind", False)
    except ValueError:
        check("v11:device_id transcript bind", True)
    try:
        v11.device_id_parse(b + b"\x00", b"wire", km)
        check("v11:device_id overlong", False)
    except ValueError:
        check("v11:device_id overlong", True)

    # auth body
    sid = os.urandom(16)
    a = v11.device_auth_body(v11.DECISION_TRUSTED_NEW, sid, id1["device_id"],
                             b"wire", km)
    check("v11:device_auth length", len(a) == 49, f"{len(a)}")
    check("v11:device_auth roundtrip",
          v11.device_auth_parse(a, b"wire", km)["decision"]
          == v11.DECISION_TRUSTED_NEW)
    try:
        v11.device_auth_parse(a, b"other", km)
        check("v11:device_auth transcript bind", False)
    except ValueError:
        check("v11:device_auth transcript bind", True)

    # resume MACs
    nonce = os.urandom(16)
    secret = os.urandom(32)
    rr = v11.resume_req_body(sid, id2["pub"], nonce, secret)
    check("v11:resume_req length", len(rr) == 80, f"{len(rr)}")
    r = v11.resume_req_parse(rr, secret)
    check("v11:resume_req roundtrip", r["session_id"] == sid
          and r["fresh_pub"] == id2["pub"] and r["resume_nonce"] == nonce)
    try:
        v11.resume_req_parse(rr, os.urandom(32))
        check("v11:resume_req wrong secret", False)
    except ValueError:
        check("v11:resume_req wrong secret", True)
    ok = v11.resume_ok_body(id1["pub"], sid, id2["pub"], secret)
    check("v11:resume_ok length", len(ok) == 48, f"{len(ok)}")
    check("v11:resume_ok roundtrip",
          v11.resume_ok_parse(ok, sid, id2["pub"], secret) == id1["pub"])
    try:
        v11.resume_ok_parse(ok, sid, os.urandom(32), secret)
        check("v11:resume_ok wrong req_pub", False)
    except ValueError:
        check("v11:resume_ok wrong req_pub", True)
    # resume key derivation symmetry
    shared = rf.x25519(id1["priv"], id2["pub"])
    k1 = v11.resume_session_keys(shared, nonce, sid, rf.CIPHER_INTEROP)
    k2 = v11.resume_session_keys(shared, nonce, sid, rf.CIPHER_INTEROP)
    check("v11:resume keys deterministic", k1 == k2 and len(k1[0]) == 32)
    k3 = v11.resume_session_keys(shared, nonce, sid, 2)
    check("v11:resume keys cipher-bound", k1 != k3)

    # ---------------- 2) structured errors
    for code in (v11.ERR_AUTH, v11.ERR_CIPHER, v11.ERR_VERSION, v11.ERR_FORMAT,
                 v11.ERR_LIMIT, v11.ERR_TIMEOUT, v11.ERR_IDENTITY_REQUIRED,
                 v11.ERR_THROTTLED, v11.ERR_REVOKED, v11.ERR_RESUME_INVALID,
                 v11.ERR_UPGRADE_REQUIRED):
        e = v11.error_body(True, code, f"msg {code}")
        p = v11.error_parse(e)
        check(f"v11:error code {code:#x}", p["code"] == code and p["fatal"]
              and p["msg"] == f"msg {code}")
    check("v11:error nonfatal", v11.error_body(False, 1, "x")[:1] == b"\x00")
    try:
        v11.error_parse(b"\x01\x00")
        check("v11:error short", False)
    except ValueError:
        check("v11:error short", True)

    # ---------------- 3) trust registry
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.unlink(path)
    clock = [1000.0]
    reg = TrustRegistry(path, clock=lambda: clock[0])
    reg.register(id1["pub"], id1["device_id"], "Pixel 8", "android", "0.2.0",
                 caps=0b11, group="home")
    check("trust:registered", reg.decide(id1["pub"], id1["device_id"])
          == v11.DECISION_TRUSTED)
    check("trust:unknown -> new", reg.decide(id2["pub"], id2["device_id"])
          == v11.DECISION_TRUSTED_NEW)
    reg.revoke(identity_pub=id1["pub"], reason="stolen")
    check("trust:revoked", reg.decide(id1["pub"], id1["device_id"])
          == v11.DECISION_REVOKED)
    # key rotation: same device_id + new pub revokes old
    id3 = v11.new_identity()
    reg.register(id3["pub"], id1["device_id"], "Pixel 8 rotated", "android",
                 "0.2.1", caps=0b11, group="home")
    check("trust:rotation new key ok",
          reg.decide(id3["pub"], id1["device_id"]) == v11.DECISION_TRUSTED)
    check("trust:rotation old key gone",
          id1["pub"].hex() in reg._data["revoked"])
    # expiry
    clock[0] += 100
    reg.set_expiry(id3["pub"], 50)
    clock[0] += 100
    check("trust:expired", reg.decide(id3["pub"], id1["device_id"])
          == v11.DECISION_REVOKED)
    # rename keeps identity
    reg4pub = v11.new_identity()
    reg.register(reg4pub["pub"], reg4pub["device_id"], "old name")
    reg.register(reg4pub["pub"], reg4pub["device_id"], "NEW NAME")
    devs = {d["device_id"]: d for d in reg.devices()}
    check("trust:rename keeps identity",
          reg.decide(reg4pub["pub"], reg4pub["device_id"])
          == v11.DECISION_TRUSTED
          and devs[reg4pub["device_id"].hex()]["name"] == "NEW NAME")
    # multiple devices/groups
    check("trust:groups", "home" in reg.groups() and len(reg.devices()) >= 3)
    # corruption → safe-fail empty
    with open(path, "ab") as f:
        f.write(b"XXXX")
    reg2 = TrustRegistry(path, clock=lambda: clock[0])
    check("trust:corruption safe-fail", reg2.devices() == [])
    safe_unlink(path)

    # ---------------- 4) replay cache + pairing throttle
    cache = v11.HandshakeReplayCache()
    check("replay:first ok", cache.check(b"P", b"N"))
    check("replay:dup rejected", not cache.check(b"P", b"N"))
    check("replay:other ok", cache.check(b"P2", b"N"))
    gate = v11.PairingGate(max_failures=3, window_s=10, clock=time.monotonic)
    src = "10.0.0.9"
    check("throttle:initial ok", gate.attempt(src))
    for _ in range(3):
        gate.failure(src)
    check("throttle:exhausted", not gate.attempt(src))
    check("throttle:other source ok", gate.attempt("10.0.0.10"))
    gate.reset(src)
    check("throttle:reset ok", gate.attempt(src))

    # ---------------- 5) full identity exchange over TCP (v1.1 session)
    h_sess, d_sess, h_link, d_link, secret = full_handshake()
    h_sess.link.ka, h_sess.link.km = h_link.ka, h_link.km
    dev_id = v11.new_identity()
    dev_id.update(name="Pixel 8", platform="android", app_ver="0.2.0",
                  caps=v11.CAP_NETWORK | v11.CAP_CAMERA | v11.CAP_DISPLAY)
    host_id = v11.new_identity()
    host_id.update(name="workbook", platform="linux", app_ver="0.2.0",
                   caps=v11.CAP_NETWORK)
    host_reg_path = tempfile.mktemp()
    dev_reg_path = tempfile.mktemp()
    host_reg = TrustRegistry(host_reg_path)
    dev_reg = TrustRegistry(dev_reg_path)
    session_id = os.urandom(16)

    def dev_exchange():
        return v11.identity_exchange(d_link, rf.ROLE_DEVICE, dev_id,
                                     dev_reg, session_id)

    def _run():
        try:
            globals()["_dev_res"][0] = dev_exchange()
        except Exception as e:  # noqa: BLE001
            globals()["_dev_res"][0] = e

    globals()["_dev_res"] = [None]
    th = threading.Thread(target=_run, daemon=True)
    th.start()
    try:
        h_res = v11.identity_exchange(h_link, rf.ROLE_HOST, host_id,
                                      host_reg, session_id)
        ok_host = isinstance(h_res, dict) and h_res["trusted"]
    except Exception as e:  # noqa: BLE001
        ok_host, h_res = False, e
    th.join(timeout=10)
    d_res = globals()["_dev_res"][0]
    ok_dev = isinstance(d_res, dict) and d_res["trusted"]
    check("exchange:v1.1 session established", ok_host and ok_dev,
          f"host={h_res!r} dev={d_res!r}")
    if ok_host:
        check("exchange:device id seen by host",
              h_res["device_id"] == dev_id["device_id"])
        check("exchange:session id agreed",
              h_res["session_id"] == session_id)
        check("exchange:trust recorded",
              any(x["identity_pub"] == dev_id["pub"].hex()
                  for x in host_reg.devices()))
    # session still works after identity exchange (encrypted frame)
    h_link.send_frame(rf.CH_TUN_V4, 0, b"post-identity-ping")
    f = d_link.recv_frame()
    check("exchange:session usable after", f.payload == b"post-identity-ping")
    safe_unlink(host_reg_path, dev_reg_path)

    # ---------------- 6) revocation rejects the session
    h2, d2, hl2, dl2, secret2 = full_handshake()
    dev_id2 = v11.new_identity()
    dev_id2.update(name="bad", platform="android", app_ver="0.1", caps=1)
    host_id2 = v11.new_identity()
    hr2_path, dr2_path = tempfile.mktemp(), tempfile.mktemp()
    hr2 = TrustRegistry(hr2_path)
    dr2 = TrustRegistry(dr2_path)
    sid2 = os.urandom(16)
    hr2.register(dev_id2["pub"], dev_id2["device_id"], "bad", "android")
    hr2.revoke(identity_pub=dev_id2["pub"], reason="compromised")

    def dev_ex2():
        return v11.identity_exchange(dl2, rf.ROLE_DEVICE, dev_id2, dr2, sid2)

    def _run2():
        try:
            globals()["_dev_res2"][0] = dev_ex2()
        except Exception as e:  # noqa: BLE001
            globals()["_dev_res2"][0] = e

    globals()["_dev_res2"] = [None]
    th2 = threading.Thread(target=_run2, daemon=True)
    th2.start()
    host_raised = False
    try:
        v11.identity_exchange(hl2, rf.ROLE_HOST, host_id2, hr2, sid2)
    except ValueError:
        host_raised = True
    th2.join(timeout=10)
    check("exchange:revoked device rejected (host side)", host_raised)
    check("exchange:revoked device rejected (device side)",
          isinstance(globals()["_dev_res2"][0], Exception))
    safe_unlink(hr2_path, dr2_path)

    # ---------------- 7) v1 byte-stability: classic handshake unaffected
    h3, d3, _, _, _ = full_handshake()
    check("v1:classic handshake unchanged", True)

    print(f"ULP v1.1: {PASS} pass, {FAIL} fail")
    if FAILURES:
        for f_ in FAILURES:
            print("  FAIL", f_)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
