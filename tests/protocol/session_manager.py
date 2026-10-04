"""Session manager: state machine + events + reconnect policy (A2/A7/A9).

Owns the session lifecycle; the ONLY component allowed to consume
control frames (recv ownership via StateMachine.can_recv +
SessionIdRegistry). Deterministic under an injected clock — the
manager itself never sleeps; callers execute the returned backoff.
"""
import time

from observability import Emitter  # noqa: E402
from reconnect import ReconnectPolicy  # noqa: E402
from session_state import (  # noqa: E402
    SessionIdRegistry, StateMachine, IllegalTransition)


class SessionManager:
    def __init__(self, session_id: str, clock=time.monotonic,
                 emitter: Emitter = None, policy: ReconnectPolicy = None,
                 registry: SessionIdRegistry = None):
        self.sm = StateMachine(session_id)
        self.session_id = session_id
        self.clock = clock
        self.emitter = emitter or Emitter(clock=clock)
        self.policy = policy or ReconnectPolicy()
        self._registry = registry or SessionIdRegistry()
        self._registry.bind(session_id, self.sm)
        self._transport = None
        self._device_identity = None

    # ----------------------------------------------------------- lifecycle
    def set_transport(self, transport) -> None:
        self._transport = transport

    def discovered(self) -> None:
        self._advance("DISCOVERY_FOUND")

    def pairing_accepted(self) -> None:
        self._advance("PAIR_ACCEPTED")

    def link_established(self) -> None:
        self._advance("LINK_ESTABLISHED")

    def handshake_ok(self) -> None:
        self._advance("HANDSHAKE_OK")

    def negotiation_ok(self) -> None:
        self._advance("NEGOTIATION_OK")
        self.emitter.emit(
            "session.handshake", ok=True,
            latency_ms=getattr(self._transport, "handshake_ms", 0.0),
            cipher=1, session=self.session_id[:12],
            device=(self._device_identity or "")[:12])

    def link_lost(self) -> None:
        """LINK_LOST → RECONNECTING (from CONNECTED/DEGRADED)."""
        self._advance("LINK_LOST")

    def attempt(self, ok: bool):
        """One reconnect attempt from RECONNECTING.

        Consumes one backoff slot; ok=True ⇒ RESUME_READY (→ CONNECTING,
        caller then runs handshake/resume); ok=False ⇒ stay
        RECONNECTING (log only). Returns the delay that preceded this
        attempt, or None when the budget was exhausted (→ FAILED).
        Backoff is intentionally NOT reset on success; call
        `reset_backoff()` after a stable holdover period."""
        if self.sm.state != "RECONNECTING":
            raise IllegalTransition(
                f"attempt() invalid in state {self.sm.state}")
        try:
            delay = self.policy.next_delay()
        except StopIteration:
            self._advance("ATTEMPTS_EXHAUSTED")
            self.emitter.emit("session.resume", sev="error", ok=False,
                              attempt=self.policy.attempts_used(),
                              backoff_ms=0,
                              session=self.session_id[:12])
            return None
        if ok:
            self._advance("RESUME_READY")
        self.emitter.emit("session.resume", ok=ok,
                          attempt=self.policy.attempts_used(),
                          backoff_ms=int(delay * 1000),
                          session=self.session_id[:12])
        return delay

    def link_failed(self) -> None:
        """A handshake failed in CONNECTING/AUTHENTICATING."""
        self._advance("LINK_FAILED")

    def reset_backoff(self) -> None:
        self.policy.reset()

    def resume_ready(self) -> None:
        self._advance("RESUME_READY")

    def stopped(self) -> None:
        if self.sm.can("STOP_REQUESTED"):
            self._advance("STOP_REQUESTED")
        self._advance("CLOSE_TIMEOUT")
        self._registry.release(self.session_id)

    # ----------------------------------------------------------- internals
    def _advance(self, event: str) -> str:
        frm = self.sm.state
        nxt = self.sm.transition(event)
        self.emitter.state(nxt, frm, session=self.session_id[:12],
                           transport=getattr(self._transport, "name", "tcp"))
        return nxt
