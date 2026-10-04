#!/usr/bin/env python3
"""Observability tests: schema enforcement + privacy fuzz (Phase 32)."""
import os
import random
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
from observability import (DENYLIST, Emitter, EventSchemaError,
                           Metrics, validate_event)  # noqa: E402

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
    em = Emitter()

    # happy path
    e = em.state("CONNECTED", "NEGOTIATING", session="ab12",
                 device="cd34", transport="tcp", ulp="1.1")
    check("obs:state event", e["ev"] == "session.state"
          and e["state"] == "CONNECTED" and e["v"] == 1)
    em.handshake(True, 12.5, 1, session="ab12")
    em.resume(True, 1, 512, session="ab12")
    em.file_op("start", 7, 1024)
    check("obs:catalog events", len(em.events) == 4)

    # privacy: denied fields
    for bad_field in DENYLIST:
        try:
            validate_event({"v": 1, "ts": 0, "sev": "info", "ev": "x",
                            bad_field: "hi"})
            check(f"obs:deny {bad_field}", False)
        except EventSchemaError:
            check(f"obs:deny {bad_field}", True)
    try:
        validate_event({"v": 1, "ts": 0, "sev": "info", "ev": "x",
                        "ctx": {"sms": "hello"}})
        check("obs:deny ctx", False)
    except EventSchemaError:
        check("obs:deny ctx", True)

    # privacy: long strings / binary
    try:
        validate_event({"v": 1, "ts": 0, "sev": "info", "ev": "x",
                        "note": "y" * 129})
        check("obs:string cap", False)
    except EventSchemaError:
        check("obs:string cap", True)
    try:
        validate_event({"v": 1, "ts": 0, "sev": "info", "ev": "x",
                        "data": b"\x01\x02"})
        check("obs:binary cap", False)
    except EventSchemaError:
        check("obs:binary cap", True)

    # shape
    for missing in ("v", "ts", "sev", "ev"):
        evt = {"v": 1, "ts": 0, "sev": "info", "ev": "x"}
        del evt[missing]
        try:
            validate_event(evt)
            check(f"obs:require {missing}", False)
        except EventSchemaError:
            check(f"obs:require {missing}", True)
    try:
        validate_event({"v": 2, "ts": 0, "sev": "info", "ev": "x"})
        check("obs:schema version", False)
    except EventSchemaError:
        check("obs:schema version", True)
    try:
        validate_event({"v": 1, "ts": 0, "sev": "loud", "ev": "x"})
        check("obs:severity set", False)
    except EventSchemaError:
        check("obs:severity set", True)

    # emitter refuses bad events (does not raise past validate)
    try:
        em.emit("bad", sev="info", sms="nope")
        check("obs:emitter refuses", False)
    except EventSchemaError:
        check("obs:emitter refuses", True)

    # metrics
    m = Metrics()
    m.counter("session_connect_total")
    m.counter("session_connect_total")
    m.gauge("rtt_ms", 12)
    m.histogram("session_handshake_ms", 8.3)
    m.histogram("session_handshake_ms", 120.0)
    snap = m.snapshot()
    check("obs:counters", snap["counters"]["session_connect_total"] == 2)
    check("obs:gauges", snap["gauges"]["rtt_ms"] == 12)
    check("obs:histogram", snap["histograms"]["session_handshake_ms"]["n"] == 2)

    # privacy fuzz: random events must either validate or be refused —
    # never leak a denied/binary field through a valid event
    rng = random.Random(7)
    names = ["session", "device", "transport", "ulp", "state",
             "rtt_ms", "fps", "cpu_pct", "bytes_in", "note", "sms",
             "clipboard", "file_data", "screen_frame", "audio_pcm",
             "secret", "token"]
    leaked = 0
    for _ in range(3000):
        evt = {"v": 1, "ts": 0, "sev": rng.choice(["debug", "info", "warn",
                                                   "error", "fatal"])}
        for n in rng.sample(names, rng.randint(1, 5)):
            kind = rng.random()
            if kind < 0.5:
                evt[n] = rng.choice(["ok", "a" * rng.randint(1, 300), "x"])
            elif kind < 0.75:
                evt[n] = rng.randint(0, 1 << 40)
            elif kind < 0.9:
                evt[n] = b"\x01" * rng.randint(1, 50)
            else:
                evt[n] = {"nested": 1}
        try:
            validate_event(evt)
            # any valid event still must not contain denied/binary
            for k, v in evt.items():
                if k in DENYLIST or isinstance(v, (bytes, bytearray)):
                    leaked += 1
        except EventSchemaError:
            pass
    check("obs:fuzz no leaks", leaked == 0, f"leaked={leaked}")

    print(f"OBSERVABILITY: {PASS} pass, {FAIL} fail")
    for x in FAILURES[:20]:
        print("  FAIL", x)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
