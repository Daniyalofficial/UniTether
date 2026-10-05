package com.unilink.core

/**
 * Connection/session state machine (Phase 6) — conformance port of
 * tests/protocol/state_machine.json (shared with Python/Node/Rust).
 * Deterministic, logged, single-owner recv (canRecv()).
 */
sealed class SessionState {
    object Discovering : SessionState()
    object Pairing : SessionState()
    object Connecting : SessionState()
    object Authenticating : SessionState()
    object Negotiating : SessionState()
    object Connected : SessionState()
    object Degraded : SessionState()
    object Reconnecting : SessionState()
    object Closing : SessionState()
    object Closed : SessionState()
    object Failed : SessionState()

    val name: String get() = when (this) {
        is Discovering -> "DISCOVERING"
        is Pairing -> "PAIRING"
        is Connecting -> "CONNECTING"
        is Authenticating -> "AUTHENTICATING"
        is Negotiating -> "NEGOTIATING"
        is Connected -> "CONNECTED"
        is Degraded -> "DEGRADED"
        is Reconnecting -> "RECONNECTING"
        is Closing -> "CLOSING"
        is Closed -> "CLOSED"
        is Failed -> "FAILED"
    }

    companion object {
        val RECV_OWNER_STATES = setOf(
            SessionState::Authenticating, SessionState::Negotiating,
            SessionState::Connected, SessionState::Degraded)

        fun fromName(s: String): SessionState? = when (s) {
            "DISCOVERING" -> Discovering; "PAIRING" -> Pairing
            "CONNECTING" -> Connecting; "AUTHENTICATING" -> Authenticating
            "NEGOTIATING" -> Negotiating; "CONNECTED" -> Connected
            "DEGRADED" -> Degraded; "RECONNECTING" -> Reconnecting
            "CLOSING" -> Closing; "CLOSED" -> Closed
            "FAILED" -> Failed; else -> null
        }
    }
}

enum class TransitionEvent {
    DISCOVERY_FOUND, PAIR_ABORT, PAIR_INVALID, PAIR_ACCEPTED,
    LINK_ESTABLISHED, LINK_FAILED, HANDSHAKE_OK, NEGOTIATION_OK,
    NEGOTIATION_FAILED, HEALTH_DEGRADED, HEALTH_RECOVERED, HEALTH_TIMEOUT,
    LINK_LOST, STOP_REQUESTED, RESUME_READY, ATTEMPTS_EXHAUSTED,
    CLOSE_CONFIRMED, CLOSE_TIMEOUT, FATAL_ERROR, RESET, NEW_SESSION
}

class IllegalTransition(message: String) : RuntimeException(message)

data class TransitionRecord(val from: SessionState, val event: TransitionEvent, val to: SessionState)

class StateMachine(var state: SessionState = SessionState.Discovering,
                   val sessionId: String = "") {
    val log = mutableListOf<TransitionRecord>()

    fun can(event: TransitionEvent): Boolean = step(state, event) != null
    fun canRecv(): Boolean = state in SessionState.RECV_OWNER_STATES

    fun transition(event: TransitionEvent): SessionState {
        val to = step(state, event)
            ?: throw IllegalTransition("event ${event.name} invalid in state ${state.name}")
        log.add(TransitionRecord(state, event, to))
        state = to
        return to
    }

    val terminal: Boolean
        get() = state is SessionState.Closed || state is SessionState.Failed

    companion object {
        fun step(state: SessionState, event: TransitionEvent): SessionState? =
            when (state) {
                is SessionState.Discovering -> when (event) {
                    TransitionEvent.DISCOVERY_FOUND -> SessionState.Pairing
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Pairing -> when (event) {
                    TransitionEvent.PAIR_ABORT -> SessionState.Discovering
                    TransitionEvent.PAIR_INVALID -> SessionState.Failed
                    TransitionEvent.PAIR_ACCEPTED -> SessionState.Connecting
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Connecting -> when (event) {
                    TransitionEvent.LINK_ESTABLISHED -> SessionState.Authenticating
                    TransitionEvent.LINK_FAILED -> SessionState.Reconnecting
                    TransitionEvent.ATTEMPTS_EXHAUSTED -> SessionState.Failed
                    TransitionEvent.STOP_REQUESTED -> SessionState.Closing
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Authenticating -> when (event) {
                    TransitionEvent.HANDSHAKE_OK -> SessionState.Negotiating
                    TransitionEvent.LINK_FAILED -> SessionState.Reconnecting
                    TransitionEvent.ATTEMPTS_EXHAUSTED -> SessionState.Failed
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Negotiating -> when (event) {
                    TransitionEvent.NEGOTIATION_OK -> SessionState.Connected
                    TransitionEvent.NEGOTIATION_FAILED -> SessionState.Reconnecting
                    TransitionEvent.ATTEMPTS_EXHAUSTED -> SessionState.Failed
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Connected -> when (event) {
                    TransitionEvent.HEALTH_DEGRADED -> SessionState.Degraded
                    TransitionEvent.LINK_LOST -> SessionState.Reconnecting
                    TransitionEvent.STOP_REQUESTED -> SessionState.Closing
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Degraded -> when (event) {
                    TransitionEvent.HEALTH_RECOVERED -> SessionState.Connected
                    TransitionEvent.HEALTH_TIMEOUT -> SessionState.Reconnecting
                    TransitionEvent.LINK_LOST -> SessionState.Reconnecting
                    TransitionEvent.STOP_REQUESTED -> SessionState.Closing
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Reconnecting -> when (event) {
                    TransitionEvent.RESUME_READY -> SessionState.Connecting
                    TransitionEvent.ATTEMPTS_EXHAUSTED -> SessionState.Failed
                    TransitionEvent.STOP_REQUESTED -> SessionState.Closing
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Closing -> when (event) {
                    TransitionEvent.CLOSE_CONFIRMED -> SessionState.Closed
                    TransitionEvent.CLOSE_TIMEOUT -> SessionState.Closed
                    TransitionEvent.FATAL_ERROR -> SessionState.Failed
                    else -> null
                }
                is SessionState.Closed -> when (event) {
                    TransitionEvent.NEW_SESSION -> SessionState.Discovering
                    else -> null
                }
                is SessionState.Failed -> when (event) {
                    TransitionEvent.RESET -> SessionState.Closed
                    else -> null
                }
            }
    }
}
