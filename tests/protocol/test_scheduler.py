#!/usr/bin/env python3
"""Scheduler tests (Phase 9) + property tests (Phase 39)."""
import os
import random
import struct
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "protocol"))

import reference_framing as rf  # noqa: E402
from scheduler import (  # noqa: E402
    DEFAULT_WEIGHTS, PRIO_CONTROL, PRIO_FILE, PRIO_INPUT, Scheduler)

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
    # ---- strict ordering when queues are disjoint
    s = Scheduler()
    s.enqueue(rf.CH_FILE, b"F" * 100)
    s.enqueue(rf.CH_CONTROL, b"C" * 10)
    s.enqueue(rf.CH_INPUT, b"I" * 50)
    order = [s.pop(), s.pop(), s.pop()]
    check("sched:priority order", order == [b"C" * 10, b"I" * 50, b"F" * 100],
          str(order))

    # ---- starvation bound: CONTROL never waits > max(weights) pops
    # under a continuous FILE flood
    s = Scheduler()
    maxw = max(DEFAULT_WEIGHTS.values())
    for trial in range(20):
        for i in range(200):
            s.enqueue(rf.CH_FILE, b"file-" + str(i).encode() + b"_" * 40)
        s.enqueue(rf.CH_CONTROL, b"ctrl")
        waited = 0
        while True:
            got = s.pop()
            if got == b"ctrl":
                break
            waited += 1
            # keep the flood going
            s.enqueue(rf.CH_FILE, b"more_" * 20)
        check(f"sched:starvation bound trial {trial}",
              waited <= maxw, f"waited {waited}")
        # drain
        while s.pop() is not None:
            pass

    # ---- backpressure: budget cap drops + counts
    s = Scheduler(budget_bytes=1024, max_items=1000)
    ok1 = s.enqueue(rf.CH_FILE, b"x" * 500)
    ok2 = s.enqueue(rf.CH_FILE, b"x" * 500)
    ok3 = s.enqueue(rf.CH_FILE, b"x" * 500)
    check("sched:budget drop", ok1 and ok2 and not ok3
          and s.dropped_budget == 1)
    s2 = Scheduler(budget_bytes=10 ** 9, max_items=5)
    for i in range(10):
        s2.enqueue(rf.CH_FILE, b"x" * 10)
    check("sched:item cap", s2.pending() == 5 and s2.dropped_full == 5)

    # ---- fairness: every non-empty priority served in a bounded window
    s = Scheduler()
    for ch in (rf.CH_FILE, rf.CH_VIDEO, rf.CH_AUDIO_IN, rf.CH_INPUT,
               rf.CH_CONTROL):
        for i in range(50):
            s.enqueue(ch, b"p" * 10)
    seen = {}
    for step in range(500):
        item = s.pop()
        if item is None:
            break
        # infer priority from content? use channel mapping via size tag:
        # simpler: count steps until each priority count delivered
    # (rebuild with tracking)
    s = Scheduler()
    tags = []
    for ch, tag in ((rf.CH_FILE, "F"), (rf.CH_VIDEO, "V"),
                    (rf.CH_AUDIO_IN, "A"), (rf.CH_INPUT, "I"),
                    (rf.CH_CONTROL, "C")):
        for i in range(40):
            s.enqueue(ch, tag.encode() * 10)
    first_seen = {}
    step = 0
    while s.pending():
        item = s.pop()
        step += 1
        t = item[0:1]
        if t not in first_seen:
            first_seen[t] = step
    check("sched:all priorities served", set(first_seen) ==
          {b"C", b"I", b"A", b"V", b"F"}, str(first_seen))
    check("sched:control first", first_seen.get(b"C") == 1,
          str(first_seen))

    # =================================================== PROPERTY TESTS
    rng = random.Random(20260925)

    # P1: frame roundtrip encode(decode(f)) == f for random frames
    for _ in range(400):
        ch = rng.randint(0, 0x0D)
        flags = rng.choice([0, 1, 2, 3, 4, 5, 8, 9, 16])
        ln = rng.choice([0, 1, 6, 7, 8, 127, 128, 129, 32767, 32768,
                         32769, 0x7FFF, 0x8001, 0xFFFF, 0x100000 - 1])
        payload = bytes(rng.getrandbits(8) for _ in range(ln))
        f = rf.Frame(ch, flags, payload)
        wire = f.encode()
        d = rf.Frame.decode(wire)
        check(f"prop:frame {ch:#x} {flags:#x} len={ln}",
              d.channel == ch and d.payload == payload
              and wire == f.encode() and len(wire) in (7 + ln, 11 + ln),
              f"ch={ch} flags={flags:#x} len={ln}")

    # P2: 0x8000 boundary correctness
    f = rf.Frame(5, 0, b"z" * 0x7FFF)
    check("prop:boundary 0x7fff",
          rf.Frame.decode(f.encode()).payload == b"z" * 0x7FFF)
    f = rf.Frame(5, 0, b"z" * 0x8000)
    check("prop:boundary 0x8000",
          rf.Frame.decode(f.encode()).payload == b"z" * 0x8000)
    f = rf.Frame(5, 0, b"z" * 0x100000)
    check("prop:boundary 1MiB",
          rf.Frame.decode(f.encode()).payload == b"z" * 0x100000)

    # P3: message roundtrip for every mtype 1..16 with random body
    for _ in range(200):
        mt = rng.randint(0x01, 0x10)
        body = bytes(rng.getrandbits(8) for _ in range(rng.randint(0, 300)))
        enc = rf.msg_encode(mt, body)
        d_mt, _fl, d_body = rf.msg_decode(enc)
        check("prop:message", d_mt == mt and d_body == body,
              f"mtype={mt:#x} len={len(body)}")

    # P4: crypto invariants — encrypt/decrypt identity + tamper fails
    key_a = os.urandom(32)
    key_m = os.urandom(32)
    for _ in range(50):
        nonce = struct.pack(">QI", rng.getrandbits(64), rng.getrandbits(32))
        aad = os.urandom(rng.randint(0, 60))
        pt = os.urandom(rng.randint(0, 500))
        ct = rf.interop_encrypt(key_a, key_m, nonce, aad, pt)
        check("prop:aead identity",
              rf.interop_decrypt(key_a, key_m, nonce, aad, ct) == pt)
        bad = bytearray(ct)
        bad[rng.randrange(len(bad))] ^= 1
        try:
            rf.interop_decrypt(key_a, key_m, nonce, aad, bytes(bad))
            check("prop:aead tamper", False)
        except Exception:
            check("prop:aead tamper", True)

    # P5: session-key separation (aead != mac) and HKDF determinism
    shared = os.urandom(32)
    na, nb = os.urandom(16), os.urandom(16)
    k1 = rf.session_keys(shared, na, nb, 1)
    k2 = rf.session_keys(shared, na, nb, 1)
    check("prop:keys deterministic", k1 == k2)
    check("prop:keys separated", k1[0] != k1[1])
    k3 = rf.session_keys(shared, na, nb, 2)
    check("prop:keys cipher-bound", k1 != k3)

    # P6: scheduler property — delivered count == enqueued - dropped
    s = Scheduler(budget_bytes=4096, max_items=64)
    enq = 0
    for _ in range(300):
        if s.enqueue(rng.choice([0, 1, 2, 3, 4, 5, 9]), b"q" * rng.randint(1, 60)):
            enq += 1
    delivered = 0
    while s.pop() is not None:
        delivered += 1
    check("prop:scheduler conservation",
          delivered == enq == s.delivered,
          f"enq={enq} del={delivered}")

    print(f"SCHEDULER+PROPERTIES: {PASS} pass, {FAIL} fail")
    for x in FAILURES[:20]:
        print("  FAIL", x)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
