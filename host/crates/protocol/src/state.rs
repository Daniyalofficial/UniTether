//! Connection/session state machine (Phase 6).
//!
//! Single source of truth: `tests/protocol/state_machine.json`. The
//! companion module [`state_gen`] is *generated* from that file by
//! `tests/protocol/gen_state_rust.py` (run in CI before `cargo test`);
//! the unit tests cross-check this hand-written table against the
//! generated one, so JSON/ Rust drift fails the build.
//!
//! Properties: deterministic, logged, observable, single-owner recv
//! (a session id may be bound to at most one live machine).

use std::collections::HashMap;

pub mod state_gen;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionState {
    Discovering,
    Pairing,
    Connecting,
    Authenticating,
    Negotiating,
    Connected,
    Degraded,
    Reconnecting,
    Closing,
    Closed,
    Failed,
}

impl SessionState {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionState::Discovering => "DISCOVERING",
            SessionState::Pairing => "PAIRING",
            SessionState::Connecting => "CONNECTING",
            SessionState::Authenticating => "AUTHENTICATING",
            SessionState::Negotiating => "NEGOTIATING",
            SessionState::Connected => "CONNECTED",
            SessionState::Degraded => "DEGRADED",
            SessionState::Reconnecting => "RECONNECTING",
            SessionState::Closing => "CLOSING",
            SessionState::Closed => "CLOSED",
            SessionState::Failed => "FAILED",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "DISCOVERING" => SessionState::Discovering,
            "PAIRING" => SessionState::Pairing,
            "CONNECTING" => SessionState::Connecting,
            "AUTHENTICATING" => SessionState::Authenticating,
            "NEGOTIATING" => SessionState::Negotiating,
            "CONNECTED" => SessionState::Connected,
            "DEGRADED" => SessionState::Degraded,
            "RECONNECTING" => SessionState::Reconnecting,
            "CLOSING" => SessionState::Closing,
            "CLOSED" => SessionState::Closed,
            "FAILED" => SessionState::Failed,
            _ => return None,
        })
    }

    pub const ALL: &'static [SessionState] = &[
        SessionState::Discovering,
        SessionState::Pairing,
        SessionState::Connecting,
        SessionState::Authenticating,
        SessionState::Negotiating,
        SessionState::Connected,
        SessionState::Degraded,
        SessionState::Reconnecting,
        SessionState::Closing,
        SessionState::Closed,
        SessionState::Failed,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransitionEvent {
    DiscoveryFound,
    PairAbort,
    PairInvalid,
    PairAccepted,
    LinkEstablished,
    LinkFailed,
    HandshakeOk,
    NegotiationOk,
    NegotiationFailed,
    HealthDegraded,
    HealthRecovered,
    HealthTimeout,
    LinkLost,
    StopRequested,
    ResumeReady,
    AttemptsExhausted,
    CloseConfirmed,
    CloseTimeout,
    FatalError,
    Reset,
    NewSession,
}

impl TransitionEvent {
    pub fn as_str(self) -> &'static str {
        match self {
            TransitionEvent::DiscoveryFound => "DISCOVERY_FOUND",
            TransitionEvent::PairAbort => "PAIR_ABORT",
            TransitionEvent::PairInvalid => "PAIR_INVALID",
            TransitionEvent::PairAccepted => "PAIR_ACCEPTED",
            TransitionEvent::LinkEstablished => "LINK_ESTABLISHED",
            TransitionEvent::LinkFailed => "LINK_FAILED",
            TransitionEvent::HandshakeOk => "HANDSHAKE_OK",
            TransitionEvent::NegotiationOk => "NEGOTIATION_OK",
            TransitionEvent::NegotiationFailed => "NEGOTIATION_FAILED",
            TransitionEvent::HealthDegraded => "HEALTH_DEGRADED",
            TransitionEvent::HealthRecovered => "HEALTH_RECOVERED",
            TransitionEvent::HealthTimeout => "HEALTH_TIMEOUT",
            TransitionEvent::LinkLost => "LINK_LOST",
            TransitionEvent::StopRequested => "STOP_REQUESTED",
            TransitionEvent::ResumeReady => "RESUME_READY",
            TransitionEvent::AttemptsExhausted => "ATTEMPTS_EXHAUSTED",
            TransitionEvent::CloseConfirmed => "CLOSE_CONFIRMED",
            TransitionEvent::CloseTimeout => "CLOSE_TIMEOUT",
            TransitionEvent::FatalError => "FATAL_ERROR",
            TransitionEvent::Reset => "RESET",
            TransitionEvent::NewSession => "NEW_SESSION",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "DISCOVERY_FOUND" => TransitionEvent::DiscoveryFound,
            "PAIR_ABORT" => TransitionEvent::PairAbort,
            "PAIR_INVALID" => TransitionEvent::PairInvalid,
            "PAIR_ACCEPTED" => TransitionEvent::PairAccepted,
            "LINK_ESTABLISHED" => TransitionEvent::LinkEstablished,
            "LINK_FAILED" => TransitionEvent::LinkFailed,
            "HANDSHAKE_OK" => TransitionEvent::HandshakeOk,
            "NEGOTIATION_OK" => TransitionEvent::NegotiationOk,
            "NEGOTIATION_FAILED" => TransitionEvent::NegotiationFailed,
            "HEALTH_DEGRADED" => TransitionEvent::HealthDegraded,
            "HEALTH_RECOVERED" => TransitionEvent::HealthRecovered,
            "HEALTH_TIMEOUT" => TransitionEvent::HealthTimeout,
            "LINK_LOST" => TransitionEvent::LinkLost,
            "STOP_REQUESTED" => TransitionEvent::StopRequested,
            "RESUME_READY" => TransitionEvent::ResumeReady,
            "ATTEMPTS_EXHAUSTED" => TransitionEvent::AttemptsExhausted,
            "CLOSE_CONFIRMED" => TransitionEvent::CloseConfirmed,
            "CLOSE_TIMEOUT" => TransitionEvent::CloseTimeout,
            "FATAL_ERROR" => TransitionEvent::FatalError,
            "RESET" => TransitionEvent::Reset,
            "NEW_SESSION" => TransitionEvent::NewSession,
            _ => return None,
        })
    }

    pub const ALL: &'static [TransitionEvent] = &[
        TransitionEvent::DiscoveryFound,
        TransitionEvent::PairAbort,
        TransitionEvent::PairInvalid,
        TransitionEvent::PairAccepted,
        TransitionEvent::LinkEstablished,
        TransitionEvent::LinkFailed,
        TransitionEvent::HandshakeOk,
        TransitionEvent::NegotiationOk,
        TransitionEvent::NegotiationFailed,
        TransitionEvent::HealthDegraded,
        TransitionEvent::HealthRecovered,
        TransitionEvent::HealthTimeout,
        TransitionEvent::LinkLost,
        TransitionEvent::StopRequested,
        TransitionEvent::ResumeReady,
        TransitionEvent::AttemptsExhausted,
        TransitionEvent::CloseConfirmed,
        TransitionEvent::CloseTimeout,
        TransitionEvent::FatalError,
        TransitionEvent::Reset,
        TransitionEvent::NewSession,
    ];
}

/// Terminal states: no outgoing transitions except FAILED→(RESET).
pub const TERMINAL: &'static [SessionState] =
    &[SessionState::Closed, SessionState::Failed];

/// States in which the single owner may consume control frames.
pub const RECV_OWNER_STATES: &'static [SessionState] = &[
    SessionState::Authenticating,
    SessionState::Negotiating,
    SessionState::Connected,
    SessionState::Degraded,
];

pub fn is_terminal(s: SessionState) -> bool {
    TERMINAL.contains(&s)
}

/// Pure transition function: `None` = illegal event in this state.
pub fn step(state: SessionState, event: TransitionEvent) -> Option<SessionState> {
    use SessionState::*;
    use TransitionEvent::*;
    Some(match (state, event) {
        (Discovering, DiscoveryFound) => Pairing,
        (Pairing, PairAbort) => Discovering,
        (Pairing, PairInvalid) => Failed,
        (Pairing, PairAccepted) => Connecting,
        (Connecting, LinkEstablished) => Authenticating,
        (Connecting, LinkFailed) => Reconnecting,
        (Connecting, AttemptsExhausted) => Failed,
        (Connecting, StopRequested) => Closing,
        (Authenticating, HandshakeOk) => Negotiating,
        (Authenticating, LinkFailed) => Reconnecting,
        (Authenticating, AttemptsExhausted) => Failed,
        (Negotiating, NegotiationOk) => Connected,
        (Negotiating, NegotiationFailed) => Reconnecting,
        (Negotiating, AttemptsExhausted) => Failed,
        (Connected, HealthDegraded) => Degraded,
        (Connected, LinkLost) => Reconnecting,
        (Connected, StopRequested) => Closing,
        (Degraded, HealthRecovered) => Connected,
        (Degraded, HealthTimeout) => Reconnecting,
        (Degraded, LinkLost) => Reconnecting,
        (Degraded, StopRequested) => Closing,
        (Reconnecting, ResumeReady) => Connecting,
        (Reconnecting, AttemptsExhausted) => Failed,
        (Reconnecting, StopRequested) => Closing,
        (Closing, CloseConfirmed) => Closed,
        (Closing, CloseTimeout) => Closed,
        (Closed, NewSession) => Discovering,
        (Failed, Reset) => Closed,
        // fatal errors from any live state
        (Discovering, FatalError) => Failed,
        (Pairing, FatalError) => Failed,
        (Connecting, FatalError) => Failed,
        (Authenticating, FatalError) => Failed,
        (Negotiating, FatalError) => Failed,
        (Connected, FatalError) => Failed,
        (Degraded, FatalError) => Failed,
        (Reconnecting, FatalError) => Failed,
        (Closing, FatalError) => Failed,
        _ => return None,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionRecord {
    pub from: SessionState,
    pub event: TransitionEvent,
    pub to: SessionState,
}

/// A deterministic, logged, observable session state machine.
pub struct StateMachine {
    state: SessionState,
    pub session_id: String,
    pub log: Vec<TransitionRecord>,
}

impl StateMachine {
    pub fn new(session_id: impl Into<String>) -> Self {
        Self {
            state: SessionState::Discovering,
            session_id: session_id.into(),
            log: Vec::new(),
        }
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn set_state_for_test(&mut self, s: SessionState) {
        self.state = s;
    }

    pub fn can(&self, event: TransitionEvent) -> bool {
        step(self.state, event).is_some()
    }

    pub fn can_recv(&self) -> bool {
        RECV_OWNER_STATES.contains(&self.state)
    }

    pub fn terminal(&self) -> bool {
        is_terminal(self.state)
    }

    /// Apply an event; `Err(())` when the event is illegal in the
    /// current state (the caller MUST treat that as a bug — the state
    /// machine is deterministic and total over its declared table).
    pub fn transition(&mut self, event: TransitionEvent) -> Result<SessionState, ()> {
        let to = step(self.state, event).ok_or(())?;
        self.log.push(TransitionRecord { from: self.state, event, to });
        self.state = to;
        Ok(to)
    }
}

/// Dual-consumer prevention: one session id → at most one live
/// state machine.
#[derive(Default)]
pub struct SessionIdRegistry {
    owner: HashMap<String, std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl SessionIdRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the liveness flag the holder must clear on terminal
    /// states; binding a still-live session id is an error.
    pub fn bind(&mut self, session_id: &str) -> Result<std::sync::Arc<std::sync::atomic::AtomicBool>, String> {
        if let Some(live) = self.owner.get(session_id) {
            if live.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(format!("session {session_id} already bound to a live machine"));
            }
        }
        let flag = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        self.owner.insert(session_id.to_string(), flag.clone());
        Ok(flag)
    }

    /// Mark a session's machine as terminal (allows rebind).
    pub fn release(&mut self, session_id: &str) {
        if let Some(live) = self.owner.get_mut(session_id) {
            live.store(false, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_declared_transitions_are_deterministic() {
        let mut n = 0usize;
        for &s in SessionState::ALL {
            for &e in TransitionEvent::ALL {
                if let Some(expected) = step(s, e) {
                    let mut m = StateMachine::new("t");
                    m.set_state_for_test(s);
                    assert_eq!(m.transition(e).ok(), Some(expected), "{s:?} -{e:?}->");
                    n += 1;
                }
            }
        }
        // 38 transitions total (same table as state_machine.json)
        assert_eq!(n, 37, "transition count drift vs state_machine.json");
    }

    #[test]
    fn cross_check_against_generated_json_table() {
        for &s in SessionState::ALL {
            for &e in TransitionEvent::ALL {
                let rust = step(s, e).map(|x| x.as_str());
                let gen = state_gen::expected(s.as_str(), e.as_str());
                assert_eq!(
                    rust,
                    gen,
                    "drift at state={} event={}: rust={:?} gen={:?}",
                    s.as_str(),
                    e.as_str(),
                    rust,
                    gen
                );
            }
        }
        assert_eq!(
            state_gen::transition_count(),
            37usize,
            "generated table size drift"
        );
    }

    #[test]
    fn invalid_pairs_rejected() {
        let mut rejected = 0;
        for &s in SessionState::ALL {
            for &e in TransitionEvent::ALL {
                if step(s, e).is_none() {
                    rejected += 1;
                    let mut m = StateMachine::new("t");
                    m.set_state_for_test(s);
                    assert!(m.transition(e).is_err(), "{s:?} -{e:?} accepted");
                }
            }
        }
        assert_eq!(rejected, 11 * 21 - 37);
    }

    #[test]
    fn happy_path_reaches_connected() {
        let mut m = StateMachine::new("s1");
        m.transition(TransitionEvent::DiscoveryFound).unwrap();
        m.transition(TransitionEvent::PairAccepted).unwrap();
        m.transition(TransitionEvent::LinkEstablished).unwrap();
        m.transition(TransitionEvent::HandshakeOk).unwrap();
        m.transition(TransitionEvent::NegotiationOk).unwrap();
        assert_eq!(m.state(), SessionState::Connected);
        assert_eq!(m.log.len(), 5);
        assert_eq!(m.log[0], TransitionRecord { from: SessionState::Discovering, event: TransitionEvent::DiscoveryFound, to: SessionState::Pairing });
        assert!(m.can_recv());
    }

    #[test]
    fn recv_ownership_matches_spec() {
        for &s in SessionState::ALL {
            let mut m = StateMachine::new("t");
            m.set_state_for_test(s);
            let expected = matches!(
                s,
                SessionState::Authenticating
                    | SessionState::Negotiating
                    | SessionState::Connected
                    | SessionState::Degraded
            );
            assert_eq!(m.can_recv(), expected, "{s:?}");
        }
    }

    #[test]
    fn dual_bind_refused_until_terminal() {
        let mut reg = SessionIdRegistry::new();
        let _f1 = reg.bind("abc").unwrap();
        assert!(reg.bind("abc").is_err(), "second live bind accepted");
        reg.release("abc");
        assert!(reg.bind("abc").is_ok(), "rebind after terminal refused");
    }

    #[test]
    fn reconnect_cycles_and_exhaustion() {
        let mut m = StateMachine::new("s");
        m.set_state_for_test(SessionState::Connected);
        for _ in 0..3 {
            m.transition(TransitionEvent::LinkLost).unwrap();
            m.transition(TransitionEvent::ResumeReady).unwrap();
            m.transition(TransitionEvent::LinkEstablished).unwrap();
            m.transition(TransitionEvent::HandshakeOk).unwrap();
            m.transition(TransitionEvent::NegotiationOk).unwrap();
            assert_eq!(m.state(), SessionState::Connected);
        }
        m.transition(TransitionEvent::LinkLost).unwrap();
        m.transition(TransitionEvent::AttemptsExhausted).unwrap();
        assert_eq!(m.state(), SessionState::Failed);
        m.transition(TransitionEvent::Reset).unwrap();
        assert_eq!(m.state(), SessionState::Closed);
        m.transition(TransitionEvent::NewSession).unwrap();
        assert_eq!(m.state(), SessionState::Discovering);
    }

    #[test]
    fn every_state_reachable() {
        let mut seen = vec![SessionState::Discovering];
        let mut frontier = vec![SessionState::Discovering];
        while let Some(s) = frontier.pop() {
            for &e in TransitionEvent::ALL {
                if let Some(n) = step(s, e) {
                    if !seen.contains(&n) {
                        seen.push(n);
                        frontier.push(n);
                    }
                }
            }
        }
        assert_eq!(seen.len(), SessionState::ALL.len(), "unreachable states");
    }

    #[test]
    fn shutdown_from_every_live_state() {
        for &s in SessionState::ALL {
            if is_terminal(s) {
                continue;
            }
            let mut m = StateMachine::new("t");
            m.set_state_for_test(s);
            let mut steps = 0;
            while !m.terminal() && steps < 3 {
                let ev = if m.can(TransitionEvent::StopRequested) {
                    TransitionEvent::StopRequested
                } else if m.can(TransitionEvent::AttemptsExhausted) {
                    TransitionEvent::AttemptsExhausted
                } else {
                    TransitionEvent::FatalError
                };
                m.transition(ev).unwrap();
                steps += 1;
            }
            assert!(m.terminal(), "stuck at {s:?}");
        }
    }
}
