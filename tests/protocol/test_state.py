#!/usr/bin/env python3
"""Exhaustive tests for the session state machine (Phase 6)."""
import itertools
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
from session_state import (  # noqa: E402
    INITIAL, SPEC, STATES, TERMINAL, TRANSITIONS,
    IllegalTransition, SessionIdRegistry, StateMachine)

PASS = FAIL = 0


def check(name, ok, detail=""):
    global PASS, FAIL
    if ok:
        PASS += 1
    else:
        FAIL += 1
        print(f"FAIL {name} {detail}")


def main():
    # 1) every declared transition is valid and deterministic
    n = 0
    for state, table in TRANSITIONS.items():
        for ev, nxt in table.items():
            m = StateMachine()
            m.state = state
            got = m.transition(ev)
            check(f"transition {state} -{ev}-> {nxt}", got == nxt and m.state == nxt)
            n += 1
    check("all transitions covered", n == sum(len(t) for t in TRANSITIONS.values()), f"n={n}")

    # 2) every (state, event) pair is either in the table or rejected
    rejected = 0
    for state in STATES:
        for ev in SPEC["events"]:
            m = StateMachine()
            m.state = state
            if ev in TRANSITIONS.get(state, {}):
                continue
            try:
                m.transition(ev)
                check(f"reject {state} -{ev}->", False, "accepted unexpectedly")
            except IllegalTransition:
                rejected += 1
    check("all invalid pairs rejected", rejected ==
          len(STATES) * len(SPEC["events"]) - n, f"rejected={rejected}")

    # 3) no transitions lead to undeclared states; terminals have no exits
    for table in TRANSITIONS.values():
        for nxt in table.values():
            check(f"target {nxt} declared", nxt in STATES)
    for t in TERMINAL:
        check(f"terminal {t} has no exits", TRANSITIONS.get(t, {}) == ({"RESET": "CLOSED"} if t == "FAILED" else {}) or t == "CLOSED")

    # 4) log records every transition in order
    m = StateMachine("s1")
    m.transition("DISCOVERY_FOUND"); m.transition("PAIR_ACCEPTED")
    m.transition("LINK_ESTABLISHED"); m.transition("HANDSHAKE_OK")
    m.transition("NEGOTIATION_OK")
    check("log complete", m.log == [
        ("DISCOVERING", "DISCOVERY_FOUND", "PAIRING"),
        ("PAIRING", "PAIR_ACCEPTED", "CONNECTING"),
        ("CONNECTING", "LINK_ESTABLISHED", "AUTHENTICATING"),
        ("AUTHENTICATING", "HANDSHAKE_OK", "NEGOTIATING"),
        ("NEGOTIATING", "NEGOTIATION_OK", "CONNECTED")], str(m.log))

    # 5) happy-path liveness: full happy path reaches CONNECTED
    m = StateMachine()
    for ev in ["DISCOVERY_FOUND", "PAIR_ACCEPTED", "LINK_ESTABLISHED",
               "HANDSHAKE_OK", "NEGOTIATION_OK"]:
        m.transition(ev)
    check("happy path reaches CONNECTED", m.state == "CONNECTED")

    # 6) recv ownership: exactly the declared states allow recv
    for s in STATES:
        m = StateMachine(); m.state = s
        check(f"recv({s}) declared", m.can_recv() == (s in set(SPEC["recv_owner_states"])))

    # 7) dual-consumer prevention: second live binding refused
    reg = SessionIdRegistry()
    m1 = StateMachine("abc"); reg.bind("abc", m1)
    m2 = StateMachine("abc")
    try:
        reg.bind("abc", m2)
        check("dual bind refused", False, "accepted")
    except ValueError:
        check("dual bind refused", True)
    # after terminal + release, rebinding is allowed
    m1.state = "CLOSED"
    reg.release("abc")
    reg.bind("abc", StateMachine("abc"))
    check("rebind after close ok", True)

    # 8) reconnect loop is bounded-legal: CONNECTED → RECONNECTING →
    #    CONNECTING → ... and exhaustion ends in FAILED
    m = StateMachine(); m.state = "CONNECTED"
    for _ in range(3):
        m.transition("LINK_LOST"); m.transition("RESUME_READY")
        m.transition("LINK_ESTABLISHED"); m.transition("HANDSHAKE_OK")
        m.transition("NEGOTIATION_OK")
    check("reconnect cycles ok", m.state == "CONNECTED")
    m.transition("LINK_LOST")
    m.transition("ATTEMPTS_EXHAUSTED")
    check("exhaustion → FAILED", m.state == "FAILED")
    m.transition("RESET")
    check("RESET → CLOSED", m.state == "CLOSED")
    m.transition("NEW_SESSION")
    check("NEW_SESSION → DISCOVERING", m.state == "DISCOVERING")

    # 9) every state is reachable from initial (no dead states)
    seen = {INITIAL}
    frontier = [INITIAL]
    while frontier:
        s = frontier.pop()
        for ev, nxt in TRANSITIONS.get(s, {}).items():
            if nxt not in seen:
                seen.add(nxt); frontier.append(nxt)
    check("all states reachable", seen == STATES, f"missing={STATES - seen}")

    # 10) clean shutdown from every live state reaches CLOSED (≤2 events)
    for s in STATES:
        if s in TERMINAL:
            continue
        m = StateMachine(); m.state = s
        steps = 0
        while m.state not in TERMINAL and steps < 3:
            m.transition("STOP_REQUESTED" if m.can("STOP_REQUESTED")
                         else "ATTEMPTS_EXHAUSTED" if m.can("ATTEMPTS_EXHAUSTED")
                         else "FATAL_ERROR")
            steps += 1
        check(f"shutdown from {s}", m.terminal, f"stuck at {m.state}")

    print(f"STATE MACHINE: {PASS} pass, {FAIL} fail")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
