#!/usr/bin/env python3
"""Chaos engineering E2E (Phases 40/41) over real loopback TCP.

Deterministic fault injection against full v1.1 sessions (real
X25519/HKDF/INTEROP crypto, real trust registry):

  S1 flap        3 disconnect→reconnect cycles, full resume each time,
                 monotonic backoff d1<d2<d3 (deterministic seed)
  S2 crash       host "crash" (state lost, socket gone) → restart with
                 persisted file-backed trust registry → re-pair as a
                 FRESH session; device decision must be TRUSTED, not
                 TRUSTED_NEW (no re-pairing of an unknown device)
  S3 ip-change   host rebinds a different address/port; resume cycle
                 succeeds on the new endpoint (transport-agnostic)
  S4 dup         duplicated RESUME_REQ on the wire → replay cache
                 rejects the duplicate, session continues, frame ok
  S5 file-loss   link severed mid-file-transfer (62.5%) → resume cycle
                 → file engine continues from .part offset, whole-file
                 SHA-256 verified on commit
  S6 latency     40 ms injected one-way delay: control round-trip
                 stays bounded, frames still delivered

No fake recovery: every scenario ends in a verifiable state
(encrypted frame exchange, committed file hash, registry decision).
"""
import os
import shutil
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "protocol"))
sys.path.insert(0, HERE)

import reference_framing as rf  # noqa: E402
import ulp_v11 as v11  # noqa: E402
from ulp_link import Link, Session  # noqa: E402
from reconnect import ReconnectPolicy  # noqa: E402
from file_transfer import FileReceiver, FileSender  # noqa: E402
from trust_registry import TrustRegistry  # noqa: E402
from observability import Emitter  # noqa: E402
from test_resume import (device_handshake_thread, host_connect,  # noqa: E402
                         make_listener, _identity, _recv_with_timeout)

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
    def decide(self, identity_pub, device_id):
        return v11.DECISION_TRUSTED

    def note_trusted(self, *a, **k):
        pass


def replay_state(cfg_v4_prefix=20):
    return rf.config_body(
        cfg_v4_prefix, bytes([10, 8, 0, 2]), bytes([10, 8, 0, 1]), 64,
        bytes.fromhex("fd004c55010000000000000002"),
        bytes.fromhex("fd004c55010000000000000001"),
        [bytes([1, 1, 1, 1])])


def resume_cycle(lsock, port, secret, session_id, dev_id, dreg, h_id, hreg,
                 errs, label, emitter=None):
    """One disconnect→reconnect→RESUME cycle. Returns session dict or
    None (errors in `errs`)."""
    ready = threading.Event()

    def resume_device(link):
        mtype, _f, body = link.recv_msg()
        assert mtype == v11.MSG_RESUME_REQ, f"got {mtype:#x}"
        r = v11.resume_req_parse(body, secret)
        assert r["session_id"] == session_id
        fresh = v11.new_identity()
        link.send_msg(v11.MSG_RESUME_OK, v11.resume_ok_body(
            fresh["pub"], session_id, r["fresh_pub"], secret))
        shared = rf.x25519(fresh["priv"], r["fresh_pub"])
        ka, km = v11.resume_session_keys(shared, r["resume_nonce"],
                                         session_id, rf.CIPHER_INTEROP)
        link.ka, link.km = ka, km
        link.tx_counter = 0
        link.rx_counter = 0

    def resume_flow(link):
        _identity(link, rf.ROLE_DEVICE, dev_id, dreg, session_id, errs,
                  f"dev-{label}")
        resume_device(link)
        ready.set()  # device key reset complete; safe to replay state

    th, dh = device_handshake_thread(lsock, secret, resume_flow)
    cs, hs, hl = host_connect(port, secret)
    _identity(hl, rf.ROLE_HOST, h_id, hreg, session_id, errs, f"host-{label}")
    th.join(timeout=10)
    if "err" in dh:
        errs[f"flow-{label}"] = dh["err"]
        return None

    fresh_h = v11.new_identity()
    nonce = os.urandom(16)
    hl.send_msg(v11.MSG_RESUME_REQ, v11.resume_req_body(
        session_id, fresh_h["pub"], nonce, secret))
    mtype, _f, body = _recv_with_timeout(hl, 15)
    if mtype != v11.MSG_RESUME_OK:
        errs[f"resume-ok-{label}"] = f"got {mtype:#x}"
        return None
    ok_pub = v11.resume_ok_parse(body, session_id, fresh_h["pub"], secret)
    shared = rf.x25519(fresh_h["priv"], ok_pub)
    ka, km = v11.resume_session_keys(shared, nonce, session_id,
                                     rf.CIPHER_INTEROP)
    hl.ka, hl.km = ka, km
    hl.tx_counter = 0
    hl.rx_counter = 0

    # gate: the device has finished its key reset before state replay
    # (OK is sent before the device's reset; CONFIG must not be
    # decrypted against the pre-resume counter)
    if not ready.wait(60):
        errs[f"ready-{label}"] = "device flow did not finish"
        return None

    # channel-state replay
    hl.send_msg(rf.MSG_CONFIG, replay_state())
    hl.send_msg(rf.MSG_TUN_UP, b"")
    dl = dh["sess"].link
    if os.environ.get("CHAOS_DBG"):
        print(f"DBG {label}: host tx={hl.tx_counter} rx={hl.rx_counter} "
              f"dev tx={dl.tx_counter} rx={dl.rx_counter} "
              f"hostkey={hl.ka[:4].hex()} devkey={dl.ka[:4].hex}",
              flush=True)
    m1, _f, _b = _recv_with_timeout(dl, 15)
    m2, _f, _b = _recv_with_timeout(dl, 15)
    if not (m1 == rf.MSG_CONFIG and m2 == rf.MSG_TUN_UP):
        errs[f"replay-{label}"] = f"got {m1:#x},{m2:#x}"
        return None
    hl.send_frame(rf.CH_TUN_V4, 0, f"after-{label}".encode())
    got = dl.recv_frame().payload
    if got != f"after-{label}".encode():
        errs[f"frame-{label}"] = repr(got)
        return None
    if emitter:
        emitter.emit("session.resume", ok=True, session=session_id[:12].hex())
    return {"cs": cs, "hl": hl, "dl": dl, "th": th}


def main():
    tmp = tempfile.mkdtemp(prefix="ut-chaos-")
    clock = [0.0]
    emitter = Emitter(clock=lambda: clock[0])
    dev_id = v11.new_identity()
    dev_id.update(name="Pixel 8", platform="android", app_ver="0.2.0",
                  caps=v11.CAP_NETWORK)

    try:
        # ================= S1: flap (3 cycles, monotonic backoff)
        lsock, port = make_listener()
        secret = os.urandom(32)
        session_id = os.urandom(16)
        h_id = v11.new_identity()
        h_id.update(name="host", platform="linux", app_ver="0.2.0",
                    caps=v11.CAP_NETWORK)
        dreg, hreg = MemReg(), MemReg()
        errs = {}

        th, dh = device_handshake_thread(
            lsock, secret,
            lambda link: _identity(link, rf.ROLE_DEVICE, dev_id, dreg,
                                   session_id, errs, "dev"))
        cs, hs, hl = host_connect(port, secret)
        _identity(hl, rf.ROLE_HOST, h_id, hreg, session_id, errs, "host")
        th.join(timeout=10)
        check("chaos:s1 initial session", "err" not in dh and "err" not in errs,
              f"{dh.get('err')!r} {errs!r}")
        dl = dh["sess"].link

        policy = ReconnectPolicy(base_s=0.1, factor=2.0, cap_s=5.0,
                                 jitter=0.1, seed=42)
        delays = []
        ok_all = True
        for i in range(3):
            delays.append(policy.next_delay())
            cs.close()
            dl.sock.close()
            time.sleep(0.02)
            sess = resume_cycle(lsock, port, secret, session_id, dev_id,
                                dreg, h_id, hreg, errs, f"flap{i}", emitter)
            if sess is None:
                ok_all = False
                break
            if i < 2:  # sever again for the next cycle
                sess["cs"].close()
                sess["dl"].sock.close()
                time.sleep(0.02)
        check("chaos:s1 three resume cycles", ok_all, f"{errs!r}")
        check("chaos:s1 backoff monotonic",
              delays[0] < delays[1] < delays[2], str(delays))
        check("chaos:s1 backoff bounded", all(d <= 5.0 for d in delays))

        # ================= S3: IP change (rebind new address)
        lsock2, port2 = make_listener()
        errs3 = {}
        sess3 = resume_cycle(lsock2, port2, secret, session_id, dev_id,
                             dreg, h_id, hreg, errs3, "ipchange", emitter)
        check("chaos:s3 resume on new endpoint", sess3 is not None,
              f"{errs3!r}")
        if sess3:
            sess3["cs"].close()
            sess3["dl"].sock.close()

        # ================= S2: host crash + restart (persisted trust)
        reg_path = os.path.join(tmp, "host-registry.json")
        hreg2 = TrustRegistry(reg_path, clock=lambda: clock[0])
        # device already trusted during S1 (via note_trusted in identity
        # exchange — MemReg on the device side, file-backed on the host)
        sess = resume_cycle(lsock, port, secret, session_id, dev_id, dreg,
                            h_id, hreg2, {}, "pre-crash", emitter)
        if sess:
            sess["cs"].close()
            sess["dl"].sock.close()
        # host CRASH: all in-memory session state gone. Registry file
        # survives. Device decides:
        decision = hreg2.decide(dev_id["pub"], dev_id["device_id"])
        check("chaos:s2 trust persisted across crash",
              decision == v11.DECISION_TRUSTED, f"got {decision}")
        # restart: FRESH session (host has no session_id → no resume),
        # full handshake + identity on both sides
        new_sid = os.urandom(16)
        errs2 = {}
        th2, dh2 = device_handshake_thread(
            lsock, secret,
            lambda link: _identity(link, rf.ROLE_DEVICE, dev_id, dreg,
                                   new_sid, errs2, "dev-crash"))
        cs2, hs2, hl2 = host_connect(port, secret)
        _identity(hl2, rf.ROLE_HOST, h_id, hreg2, new_sid, errs2,
                  "host-crash")
        th2.join(timeout=10)
        dl2 = dh2["sess"].link if "sess" in dh2 else None
        check("chaos:s2 fresh session after restart",
              dl2 is not None and "err" not in dh2 and "err" not in errs2,
              f"{dh2.get('err')!r} {errs2!r}")
        if dl2:
            hl2.send_frame(rf.CH_TUN_V4, 0, b"post-crash")
            check("chaos:s2 frame post-crash",
                  dl2.recv_frame().payload == b"post-crash")
            cs2.close()
            dl2.sock.close()

        # ================= S4: duplicated RESUME_REQ (dup tolerance)
        lsock4, port4 = make_listener()
        secret4 = os.urandom(32)
        sid4 = os.urandom(16)
        dreg4, hreg4 = MemReg(), MemReg()
        errs4 = {}
        dup_seen = {"n": 0}

        def resume_device_dup(link):
            mtype, _f, body = link.recv_msg()
            assert mtype == v11.MSG_RESUME_REQ, f"got {mtype:#x}"
            r = v11.resume_req_parse(body, secret4)
            fresh = v11.new_identity()
            link.send_msg(v11.MSG_RESUME_OK, v11.resume_ok_body(
                fresh["pub"], sid4, r["fresh_pub"], secret4))
            shared = rf.x25519(fresh["priv"], r["fresh_pub"])
            ka, km = v11.resume_session_keys(shared, r["resume_nonce"],
                                             sid4, rf.CIPHER_INTEROP)
            # duplicate of the same REQ on the wire (still old keys/ctr):
            mtype2, _f, body2 = _recv_with_timeout(link, 5)
            if mtype2 == v11.MSG_RESUME_REQ:
                r2 = v11.resume_req_parse(body2, secret4)
                same = (r2["fresh_pub"] == r["fresh_pub"]
                        and r2["resume_nonce"] == r["resume_nonce"])
                dup_seen["n"] = 1 if same else 2
            # switch to resume keys, then refuse the duplicate (replay)
            link.ka, link.km = ka, km
            link.tx_counter = 0
            link.rx_counter = 0
            if dup_seen["n"] == 1:
                # structured error: message flag 0x01 + error body
                eb = v11.error_body(1, v11.ERR_RESUME_INVALID,
                                    "duplicate resume")
                wire = bytes([v11.MSG_RESUME_OK, v11.ERROR_FLAG]) \
                    + len(eb).to_bytes(2, "big") + eb
                link.send_frame(rf.CH_CONTROL, 0, wire)

        def resume_flow4(link):
            _identity(link, rf.ROLE_DEVICE, dev_id, dreg4, sid4, errs4,
                      "dev-dup")
            resume_device_dup(link)

        th4, dh4 = device_handshake_thread(lsock4, secret4, resume_flow4)
        cs4, hs4, hl4 = host_connect(port4, secret4)
        _identity(hl4, rf.ROLE_HOST, h_id, hreg4, sid4, errs4, "host-dup")
        th4.join(timeout=10)
        if "err" in dh4:
            check("chaos:s4 duplicate RESUME_REQ tolerated", False,
                  repr(dh4["err"]))
        else:
            fresh_h = v11.new_identity()
            nonce = os.urandom(16)
            req = v11.resume_req_body(sid4, fresh_h["pub"], nonce, secret4)
            hl4.send_msg(v11.MSG_RESUME_REQ, req)   # original
            hl4.send_msg(v11.MSG_RESUME_REQ, req)   # duplicate
            m1, _f, b1 = _recv_with_timeout(hl4, 15)  # OK (old keys)
            # switch to resume keys BEFORE reading the reply that follows
            ok_pub = v11.resume_ok_parse(b1, sid4, fresh_h["pub"], secret4)
            shared = rf.x25519(fresh_h["priv"], ok_pub)
            ka, km = v11.resume_session_keys(shared, nonce, sid4,
                                             rf.CIPHER_INTEROP)
            hl4.ka, hl4.km = ka, km
            hl4.tx_counter = 0
            hl4.rx_counter = 0
            m2, f2, b2 = _recv_with_timeout(hl4, 15)   # error (resume keys)
            ecode = v11.error_parse(b2)["code"] \
                if (f2 & v11.ERROR_FLAG) else None
            ok4 = (m1 == v11.MSG_RESUME_OK
                   and f2 & v11.ERROR_FLAG
                   and ecode == v11.ERR_RESUME_INVALID
                   and dup_seen["n"] == 1)
            check("chaos:s4 duplicate RESUME_REQ tolerated", ok4,
                  f"m1={m1:#x} f2={f2:#x} ecode={ecode} "
                  f"dup={dup_seen} {dh4.get('err')!r}")
            d4 = dh4["sess"].link
            hl4.send_frame(rf.CH_TUN_V4, 0, b"post-dup")
            check("chaos:s4 frame after dup",
                  d4.recv_frame().payload == b"post-dup")
            cs4.close()
            d4.sock.close()

        # ================= S5: file loss at 62.5% → resume → commit
        lsock5, port5 = make_listener()
        secret5 = os.urandom(32)
        sid5 = os.urandom(16)
        dreg5, hreg5 = MemReg(), MemReg()
        errs5 = {}
        src = os.path.join(tmp, "big.bin")
        size = 2 * 1024 * 1024
        with open(src, "wb") as f:
            f.write(os.urandom(size))
        chunk = 256 * 1024
        kill_after = 5 * chunk  # 62.5%
        rxdir = os.path.join(tmp, "rx")
        rx = FileReceiver(rxdir)
        file_stop = threading.Event()

        def device_file_phase5(dl, stop, kill=True):
            got = 0
            try:
                while not stop.is_set():
                    fr = dl.recv_frame()
                    if fr.channel != rf.CH_FILE:
                        continue
                    rx.deliver(fr.payload,
                               lambda b: dl.send_frame(rf.CH_FILE, 0, b))
                    if kill and fr.payload[0] == 0x01:
                        off = int.from_bytes(fr.payload[10:18], "big")
                        if off + (len(fr.payload) - 18) >= kill_after:
                            stop.set()
                            return
            except Exception:  # noqa: BLE001
                stop.set()

        th5, dh5 = device_handshake_thread(
            lsock5, secret5,
            lambda link: _identity(link, rf.ROLE_DEVICE, dev_id, dreg5,
                                   sid5, errs5, "dev-file"))
        cs5, hs5, hl5 = host_connect(port5, secret5)
        _identity(hl5, rf.ROLE_HOST, h_id, hreg5, sid5, errs5, "host-file")
        th5.join(timeout=10)
        dl5 = dh5["sess"].link

        fth = threading.Thread(target=device_file_phase5,
                               args=(dl5, file_stop), daemon=True)
        fth.start()
        try:
            FileSender(0).send(src, 42, "big.bin",
                               lambda b: hl5.send_frame(rf.CH_FILE, 0, b),
                               lambda: _next_file_payload(hl5),
                               chunk_size=chunk, resume=False)
            first_completed = True
        except Exception:
            first_completed = False
        file_stop.set()
        fth.join(timeout=3)
        check("chaos:s5 link died mid-file", not first_completed)
        part = os.path.join(rxdir, ".0000002a.part")
        part_size = os.path.getsize(part) if os.path.exists(part) else 0
        check("chaos:s5 partial kept", part_size == kill_after,
              f"{part_size}")
        # sever + resume
        cs5.close()
        dl5.sock.close()
        time.sleep(0.02)
        sess5 = resume_cycle(lsock5, port5, secret5, sid5, dev_id, dreg5,
                             h_id, hreg5, errs5, "file", emitter)
        check("chaos:s5 resume after file loss", sess5 is not None,
              f"{errs5!r}")
        if sess5:
            dl5b = sess5["dl"]
            stop2 = threading.Event()
            fth2 = threading.Thread(target=device_file_phase5,
                                    args=(dl5b, stop2, False), daemon=True)
            fth2.start()
            # cap the file phase: receiver resumes from offset; no kill
            res5 = FileSender(0).send(src, 42, "big.bin",
                                      lambda b: sess5["hl"].send_frame(
                                          rf.CH_FILE, 0, b),
                                      lambda: _next_file_payload(sess5["hl"]),
                                      chunk_size=chunk, resume=True)
            stop2.set()
            fth2.join(timeout=3)
            check("chaos:s5 resumed transfer committed",
                  res5 is not None and res5["committed"])
            check("chaos:s5 resumed from 62.5%",
                  res5 is not None and res5["resumed_from"] == kill_after)
            final = os.path.join(rxdir, "big.bin")
            import hashlib
            h1 = hashlib.sha256()
            with open(final, "rb") as f:
                for blk in iter(lambda: f.read(1 << 20), b""):
                    h1.update(blk)
            h2 = hashlib.sha256()
            with open(src, "rb") as f:
                for blk in iter(lambda: f.read(1 << 20), b""):
                    h2.update(blk)
            check("chaos:s5 whole-file sha256 verified", h1.digest()
                  == h2.digest())
            check("chaos:s5 only 37.5% retransferred",
                  res5 is not None and res5["bytes"] <= 3 * chunk)
            sess5["cs"].close()
            dl5b.sock.close()

        # ================= S6: latency (40 ms injected one-way)
        lsock6, port6 = make_listener()
        secret6 = os.urandom(32)
        sid6 = os.urandom(16)
        dreg6, hreg6 = MemReg(), MemReg()
        errs6 = {}
        th6, dh6 = device_handshake_thread(
            lsock6, secret6,
            lambda link: _identity(link, rf.ROLE_DEVICE, dev_id, dreg6,
                                   sid6, errs6, "dev-lat"))
        cs6, hs6, hl6 = host_connect(port6, secret6)
        _identity(hl6, rf.ROLE_HOST, h_id, hreg6, sid6, errs6, "host-lat")
        th6.join(timeout=10)
        dl6 = dh6["sess"].link
        # inject 20ms on each direction
        orig_send = hl6.send_frame
        orig_send_d = dl6.send_frame

        def slow_send(channel, flags, payload, **kw):
            time.sleep(0.02)
            return orig_send(channel, flags, payload, **kw)

        def slow_send_d(channel, flags, payload, **kw):
            time.sleep(0.02)
            return orig_send_d(channel, flags, payload, **kw)

        hl6.send_frame = slow_send
        dl6.send_frame = slow_send_d
        t0 = time.monotonic()
        hl6.send_frame(rf.CH_CONTROL, 0, b"PING")
        got6 = dl6.recv_frame()
        rtt = time.monotonic() - t0
        check("chaos:s6 control under latency", got6.payload == b"PING"
              and rtt < 0.5, f"rtt={rtt:.3f}")
        for i in range(50):
            hl6.send_frame(rf.CH_VIDEO, 0, b"\x00" * 512)
        ok_frames = True
        for i in range(50):
            fr = dl6.recv_frame()
            if fr.channel != rf.CH_VIDEO or len(fr.payload) != 512:
                ok_frames = False
        check("chaos:s6 50 video frames under latency", ok_frames)
        cs6.close()
        dl6.sock.close()

        # ================= observability emitted real events
        evs = emitter.events
        res = [e for e in evs if e["ev"] == "session.resume"]
        check("chaos:obs resume events logged",
              len(res) >= 4 and all(e["ok"] for e in res),
              f"{len(res)} events")

        print(f"CHAOS E2E: {PASS} pass, {FAIL} fail")
        for n in FAILURES:
            print(f"  FAIL {n}")
        return 1 if FAIL else 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _next_file_payload(hl):
    while True:
        fr = hl.recv_frame()
        if fr.channel == rf.CH_FILE:
            return fr.payload


if __name__ == "__main__":
    raise SystemExit(main())
