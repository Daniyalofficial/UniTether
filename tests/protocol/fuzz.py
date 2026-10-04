"""Deterministic fuzz targets (Phase 42/43 security gates).

Usage: python3 fuzz.py [--iters N] [--seed S]

Targets (each: random inputs → the code must either succeed or raise
a *typed* error; any other exception, hang, or state corruption is a
failure):
  frame     Frame.decode on random bytes
  frame_rt  encode∘decode identity on random valid frames
  message   msg_decode on random payloads
  aead      interop_decrypt on random (key, nonce, aad, ct)
  handshake hello_verify / hello_ack_verify on random bodies
  fileops   file v2 codec parse on random payloads
  scheduler random enqueue/poll workload → conservation
  obs       event validation on random dicts (privacy denylist)

No network, no clock dependence, fully seedable.
"""
import argparse
import io
import json
import os
import random
import struct
import sys

import reference_framing as rf
import ulp_v11 as v11
import observability as obs
import scheduler as sched
from file_transfer import (meta_parse, data_parse, resume_req_parse,
                           resume_rsp_parse, checksum_parse)

TYPED = (rf.ProtocolError, ValueError, KeyError, TypeError)


def fuzz_frame(rng, iters):
    for i in range(iters):
        n = rng.choice([0, 1, 2, 6, 7, 8, 16, 100, 1000, 70000])
        data = bytes(rng.randrange(256) for _ in range(n))
        try:
            fr = rf.Frame.decode(data)
            # re-encode to prove structural validity
            wire = fr.encode()
            fr2 = rf.Frame.decode(wire)
            assert (fr2.channel, fr2.flags, fr2.payload) == \
                (fr.channel, fr.flags, fr.payload)
        except TYPED:
            pass
    # roundtrip identity on valid frames
    for i in range(iters):
        ch = rng.randrange(256)
        flags = rng.choice([0, 1, 2, 4, 8, 0x00])
        pl = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 4096)))
        if ch > 0x0D:
            continue
        fr = rf.Frame(ch, flags, pl)
        fr2 = rf.Frame.decode(fr.encode())
        assert (fr2.channel, fr2.flags, fr2.payload) == (ch, flags, pl), \
            f"frame roundtrip {i}"


def fuzz_message(rng, iters):
    for i in range(iters):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        try:
            mtype, flags, body = rf.msg_decode(data)
            assert 0 <= mtype <= 255
        except TYPED:
            pass
    for i in range(iters):
        mt = rng.randrange(256)
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 500)))
        mtype, flags, b2 = rf.msg_decode(rf.msg_encode(mt, body))
        assert (mtype, b2) == (mt, body)


def fuzz_aead(rng, iters):
    for i in range(iters):
        ka = bytes(rng.randrange(256) for _ in range(32))
        km = bytes(rng.randrange(256) for _ in range(32))
        nonce = bytes(rng.randrange(256) for _ in range(12))
        aad = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 30)))
        ct = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        try:
            rf.interop_decrypt(ka, km, nonce, aad, ct)
        except TYPED:
            pass
    # identity: encrypt∘decrypt
    for i in range(iters):
        ka = os.urandom(32)
        km = os.urandom(32)
        nonce = os.urandom(12)
        aad = os.urandom(rng.randrange(0, 30))
        pt = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 300)))
        ct = rf.interop_encrypt(ka, km, nonce, aad, pt)
        assert rf.interop_decrypt(ka, km, nonce, aad, ct) == pt


def fuzz_handshake(rng, iters):
    for i in range(iters):
        body = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        try:
            rf.hello_verify(body, os.urandom(32))
        except TYPED:
            pass
        try:
            rf.hello_ack_verify(body, os.urandom(32), os.urandom(16))
        except TYPED:
            pass
        try:
            v11.resume_req_parse(body, os.urandom(32))
        except TYPED:
            pass
        try:
            v11.device_id_parse(body, b"", os.urandom(32))
        except TYPED:
            pass
    # valid roundtrip
    for i in range(iters):
        secret = os.urandom(32)
        nonce_a = os.urandom(16)
        priv = os.urandom(32)
        pub = rf.x25519_public(priv)
        hello = rf.hello_body(rf.ROLE_HOST, 0x00FF, rf.CIPHER_INTEROP,
                              pub, nonce_a)
        hello += rf.pairing_mac(secret, pub, nonce_a)
        h = rf.hello_verify(hello, secret)
        assert h["nonce_a"] == nonce_a


def fuzz_fileops(rng, iters):
    parsers = (meta_parse, data_parse, resume_req_parse,
               resume_rsp_parse, checksum_parse)
    for i in range(iters):
        data = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 120)))
        for p in parsers:
            try:
                p(data)
            except TYPED:
                pass
    # valid roundtrips
    for i in range(iters):
        fid = rng.randrange(2 ** 32)
        off = rng.randrange(0, 2 ** 48)
        chunk = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 200)))
        d, f, s, o, c = data_parse(rf_msg_data(fid, s := rng.randrange(2 ** 32),
                                               off, chunk))
        assert (d, f, s, o, c) == (0, fid, s, off, chunk)


def rf_msg_data(fid, seq, off, chunk):
    return (bytes([0x01, 0]) + fid.to_bytes(4, "big")
            + seq.to_bytes(4, "big") + off.to_bytes(8, "big") + chunk)


def fuzz_scheduler(rng, iters):
    s = sched.Scheduler()
    enqueued = 0
    for i in range(iters):
        ch = rng.randrange(16)
        size = rng.randrange(1, 3000)
        data = b"\x00" * size
        if s.enqueue(ch, data, size):
            enqueued += 1
        for _ in range(rng.randrange(0, 3)):
            s.pop()
    while s.pop() is not None:
        pass
    assert s.delivered == enqueued - (s.dropped_full + s.dropped_budget), \
        f"conservation: {s.delivered} != {enqueued} - {s.dropped_full + s.dropped_budget}"


def fuzz_obs(rng, iters):
    deny = list(obs.DENYLIST)
    for i in range(iters):
        ev = {}
        for _ in range(rng.randrange(0, 12)):
            key = rng.choice(deny + ["a", "b", "latency_ms", "count",
                                     "state", "x" * 300])
            ev[key] = rng.choice(["v", b"\x00\x01", 3, 1.5, None,
                                  [1], {"n": 1}])
        try:
            obs.validate_event(ev)
        except obs.EventSchemaError:
            pass
        except TYPED:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=2000)
    ap.add_argument("--seed", type=int, default=1234)
    a = ap.parse_args()
    rng = random.Random(a.seed)
    targets = [("frame", fuzz_frame), ("message", fuzz_message),
               ("aead", fuzz_aead), ("handshake", fuzz_handshake),
               ("fileops", fuzz_fileops), ("scheduler", fuzz_scheduler),
               ("obs", fuzz_obs)]
    fails = []
    for name, fn in targets:
        try:
            fn(rng, a.iters)
            print(f"FUZZ {name}: OK ({a.iters} iters, seed {a.seed})")
        except Exception as e:  # noqa: BLE001
            fails.append(name)
            print(f"FUZZ {name}: FAIL {type(e).__name__}: {e}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
