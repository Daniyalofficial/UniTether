"""Connection/session state machine (ULP, Phase 6).

Single source of truth: tests/protocol/state_machine.json (shared by the
Python, Node, Rust and Kotlin implementations — each test suite
cross-checks its table against this file).

Properties guaranteed by construction:
  * deterministic: same state+event → same next state, always
  * observable:  every transition is recorded in `log`
  * testable:    exhaustive transition-table tests in test_state.py
  * single recv owner: one session_id may be bound to at most one live
    state machine (`SessionIdRegistry`), and the machine exposes
    `can_recv()` — the only legal state from which control frames are
    consumed. No second consumer can exist for the same session.
"""
import json
import os
import threading

_HERE = os.path.dirname(__file__)
with open(os.path.join(_HERE, "state_machine.json"), "r", encoding="utf-8") as _f:
    SPEC = json.load(_f)

INITIAL = SPEC["initial"]
TERMINAL = set(SPEC["terminal"])
STATES = set(SPEC["states"])
TRANSITIONS = SPEC["transitions"]
RECV_OWNER_STATES = set(SPEC["recv_owner_states"])


class IllegalTransition(Exception):
    """An event that is not valid in the current state."""


class StateMachine:
    def __init__(self, session_id: str = ""):
        self.state = INITIAL
        self.session_id = session_id
        self.log = []  # [(from_state, event, to_state), ...]
        self._lock = threading.Lock()

    def can(self, event: str) -> bool:
        return event in TRANSITIONS.get(self.state, {})

    def can_recv(self) -> bool:
        """True only in states where the owner may consume control frames."""
        return self.state in RECV_OWNER_STATES

    def transition(self, event: str, **ctx) -> str:
        with self._lock:
            nxt = TRANSITIONS.get(self.state, {}).get(event)
            if nxt is None:
                raise IllegalTransition(
                    f"event {event!r} invalid in state {self.state!r}")
            frm = self.state
            self.state = nxt
            self.log.append((frm, event, nxt))
            return nxt

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL

    def __repr__(self) -> str:
        return f"StateMachine({self.state}, {len(self.log)} transitions)"


class SessionIdRegistry:
    """Dual-consumer prevention: one session_id → at most one live
    state machine. Binding a session that is still owned by a
    non-terminal machine is an error."""

    def __init__(self):
        self._owner = {}
        self._lock = threading.Lock()

    def bind(self, session_id: str, machine: StateMachine) -> None:
        with self._lock:
            cur = self._owner.get(session_id)
            if cur is not None and not cur.terminal:
                raise ValueError(
                    f"session {session_id!r} already bound to a live "
                    f"machine in state {cur.state!r}")
            self._owner[session_id] = machine

    def release(self, session_id: str) -> None:
        with self._lock:
            self._owner.pop(session_id, None)
