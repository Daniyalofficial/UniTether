#!/usr/bin/env python3
"""Session manager lifecycle tests (deterministic clock)."""
import os
import sys

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
from observability import Emitter  # noqa: E402
from reconnect import ReconnectPolicy  # noqa: E402
from session_manager import SessionManager  # noqa: E402
from session_state import IllegalTransition  # noqa: E402

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
    clock = [0.0]
    em = Emitter(clock=lambda: clock[0])
    mgr = SessionManager("abcd1234ef567890", clock=lambda: clock[0],
                         emitter=em,
                         policy=ReconnectPolicy(base_s=1.0, factor=2.0,
                                                cap_s=8.0, seed=5))

    # happy path
    mgr.discovered()
    check("smgr:pairing", mgr.sm.state == "PAIRING")
    mgr.pairing_accepted()
    check("smgr:connecting", mgr.sm.state == "CONNECTING")
    mgr.link_established()
    check("smgr:authenticating", mgr.sm.state == "AUTHENTICATING")
    mgr.handshake_ok()
    check("smgr:negotiating", mgr.sm.state == "NEGOTIATING")
    mgr.negotiation_ok()
    check("smgr:connected", mgr.sm.state == "CONNECTED")
    check("smgr:can_recv", mgr.sm.can_recv())

    states = [e for e in em.events if e["ev"] == "session.state"]
    check("smgr:5 state events", len(states) == 5, str(len(states)))
    check("smgr:event fields",
          states[0]["from_state"] == "DISCOVERING"
          and states[0]["state"] == "PAIRING"
          and states[0]["session"] == "abcd1234ef56")
    hs = [e for e in em.events if e["ev"] == "session.handshake"]
    check("smgr:handshake event", len(hs) == 1 and hs[0]["ok"] is True)

    # cycle 1: loss → attempt ok → reconnect
    clock[0] += 10
    mgr.link_lost()
    check("smgr:reconnecting", mgr.sm.state == "RECONNECTING")
    d1 = mgr.attempt(ok=True)
    check("smgr:backoff base", 0.8 <= d1 <= 1.2, str(d1))
    clock[0] += d1
    mgr.link_established()
    mgr.handshake_ok()
    mgr.negotiation_ok()
    check("smgr:reconnected", mgr.sm.state == "CONNECTED")

    # cycle 2: loss → attempt fails → attempt ok (backoff grows)
    clock[0] += 1
    mgr.link_lost()
    d2 = mgr.attempt(ok=False)
    check("smgr:failed attempt stays RECONNECTING",
          mgr.sm.state == "RECONNECTING")
    check("smgr:backoff grows", d2 > d1, f"{d2} !> {d1}")
    clock[0] += d2
    d3 = mgr.attempt(ok=True)
    check("smgr:backoff grows again", d3 > d2, f"{d3} !> {d2}")
    clock[0] += d3
    mgr.link_established()
    mgr.handshake_ok()
    mgr.negotiation_ok()
    check("smgr:reconnected 2", mgr.sm.state == "CONNECTED")

    # resume events recorded
    res = [e for e in em.events if e["ev"] == "session.resume"]
    check("smgr:resume events", len(res) == 3
          and res[0]["ok"] is True and res[1]["ok"] is False
          and res[2]["ok"] is True, str(len(res)))

    # clean stop
    mgr.stopped()
    check("smgr:closed", mgr.sm.state == "CLOSED")
    mgr2 = SessionManager("abcd1234ef567890",
                          policy=ReconnectPolicy(seed=1))
    check("smgr:rebind after close", mgr2.sm.state == "DISCOVERING")

    # attempt() only legal in RECONNECTING
    mgr4 = SessionManager("aabb", policy=ReconnectPolicy(seed=1))
    try:
        mgr4.attempt(True)
        check("smgr:attempt guard", False)
    except IllegalTransition:
        check("smgr:attempt guard", True)

    # exhaustion: 3 attempts, all fail → FAILED
    mgr3 = SessionManager("feedbeef",
                          policy=ReconnectPolicy(max_attempts=3, seed=2,
                                                 base_s=0.1, cap_s=0.5))
    mgr3.discovered(); mgr3.pairing_accepted(); mgr3.link_established()
    mgr3.handshake_ok(); mgr3.negotiation_ok()
    mgr3.link_lost()
    check("smgr:e1", mgr3.attempt(False) is not None)
    check("smgr:e2", mgr3.attempt(False) is not None)
    check("smgr:e3", mgr3.attempt(False) is not None)
    d = mgr3.attempt(False)
    check("smgr:exhaustion delay None", d is None)
    check("smgr:exhausted → FAILED", mgr3.sm.state == "FAILED",
          mgr3.sm.state)
    check("smgr:terminal", mgr3.sm.terminal)

    print(f"SESSION MANAGER: {PASS} pass, {FAIL} fail")
    for x in FAILURES:
        print("  FAIL", x)
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
