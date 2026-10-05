// Connection/session state machine — Node conformance port (Phase 6).
// Single source of truth: tests/protocol/state_machine.json — the test
// suite cross-checks this module's table against the file.

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SPEC = JSON.parse(
  readFileSync(path.join(__dirname, "..", "..", "tests", "protocol", "state_machine.json"), "utf8")
);

export const INITIAL = SPEC.initial;
export const TERMINAL = new Set(SPEC.terminal);
export const STATES = new Set(SPEC.states);
export const TRANSITIONS = SPEC.transitions;
export const RECV_OWNER_STATES = new Set(SPEC.recv_owner_states);

export class IllegalTransition extends Error {}

export class StateMachine {
  constructor(sessionId = "") {
    this.state = INITIAL;
    this.sessionId = sessionId;
    this.log = [];
  }
  can(event) {
    return Object.prototype.hasOwnProperty.call(TRANSITIONS[this.state] || {}, event);
  }
  canRecv() {
    return RECV_OWNER_STATES.has(this.state);
  }
  transition(event) {
    const nxt = (TRANSITIONS[this.state] || {})[event];
    if (nxt === undefined) {
      throw new IllegalTransition(`event ${event} invalid in state ${this.state}`);
    }
    const from = this.state;
    this.state = nxt;
    this.log.push([from, event, nxt]);
    return nxt;
  }
  get terminal() {
    return TERMINAL.has(this.state);
  }
}

export class SessionIdRegistry {
  constructor() { this._owner = new Map(); }
  bind(sessionId, machine) {
    const cur = this._owner.get(sessionId);
    if (cur && !cur.terminal) {
      throw new Error(`session ${sessionId} already bound to a live machine in state ${cur.state}`);
    }
    this._owner.set(sessionId, machine);
  }
  release(sessionId) { this._owner.delete(sessionId); }
}

export function selfTest(check) {
  // 1) every declared transition is valid and deterministic
  let n = 0;
  for (const [state, table] of Object.entries(TRANSITIONS)) {
    for (const [ev, nxt] of Object.entries(table)) {
      const m = new StateMachine();
      m.state = state;
      const got = m.transition(ev);
      check(`sm:${state}-${ev}->${nxt}`, got === nxt && m.state === nxt);
      n++;
    }
  }
  check("sm:all transitions covered", n === Object.values(TRANSITIONS).reduce((a, t) => a + Object.keys(t).length, 0));

  // 2) every (state, event) pair is either in the table or rejected
  let rejected = 0;
  for (const state of STATES) {
    for (const ev of SPEC.events) {
      const m = new StateMachine();
      m.state = state;
      if ((TRANSITIONS[state] || {})[ev] !== undefined) continue;
      try { m.transition(ev); check(`sm:reject ${state}-${ev}`, false, "accepted"); }
      catch (e) { if (e instanceof IllegalTransition) rejected++; }
    }
  }
  check("sm:all invalid pairs rejected", rejected === STATES.size * SPEC.events.length - n);

  // 3) targets declared; terminal semantics
  for (const table of Object.values(TRANSITIONS)) {
    for (const nxt of Object.values(table)) check(`sm:target ${nxt}`, STATES.has(nxt));
  }

  // 4) log order
  const m = new StateMachine("s1");
  for (const ev of ["DISCOVERY_FOUND", "PAIR_ACCEPTED", "LINK_ESTABLISHED", "HANDSHAKE_OK", "NEGOTIATION_OK"]) m.transition(ev);
  check("sm:log order", m.log.length === 5 && m.log[0][0] === "DISCOVERING" && m.log[4][2] === "CONNECTED");

  // 5) happy path
  const m2 = new StateMachine();
  for (const ev of ["DISCOVERY_FOUND", "PAIR_ACCEPTED", "LINK_ESTABLISHED", "HANDSHAKE_OK", "NEGOTIATION_OK"]) m2.transition(ev);
  check("sm:happy path", m2.state === "CONNECTED");

  // 6) recv ownership
  for (const s of STATES) {
    const m = new StateMachine(); m.state = s;
    check(`sm:recv(${s})`, m.canRecv() === RECV_OWNER_STATES.has(s));
  }

  // 7) dual-consumer prevention
  const reg = new SessionIdRegistry();
  const a = new StateMachine("abc"); reg.bind("abc", a);
  let refused = false;
  try { reg.bind("abc", new StateMachine("abc")); } catch { refused = true; }
  check("sm:dual bind refused", refused);
  a.state = "CLOSED"; reg.release("abc"); reg.bind("abc", new StateMachine("abc"));
  check("sm:rebind after close", true);

  // 8) reconnect cycles + exhaustion
  const m3 = new StateMachine(); m3.state = "CONNECTED";
  for (let i = 0; i < 3; i++) {
    m3.transition("LINK_LOST"); m3.transition("RESUME_READY");
    m3.transition("LINK_ESTABLISHED"); m3.transition("HANDSHAKE_OK");
    m3.transition("NEGOTIATION_OK");
  }
  check("sm:reconnect cycles", m3.state === "CONNECTED");
  m3.transition("LINK_LOST"); m3.transition("ATTEMPTS_EXHAUSTED");
  check("sm:exhaustion → FAILED", m3.state === "FAILED");
  m3.transition("RESET");
  check("sm:RESET → CLOSED", m3.state === "CLOSED");
  m3.transition("NEW_SESSION");
  check("sm:NEW_SESSION → DISCOVERING", m3.state === "DISCOVERING");

  // 9) reachability
  const seen = new Set([INITIAL]);
  const frontier = [INITIAL];
  while (frontier.length) {
    const s = frontier.pop();
    for (const nxt of Object.values(TRANSITIONS[s] || {})) if (!seen.has(nxt)) { seen.add(nxt); frontier.push(nxt); }
  }
  check("sm:all states reachable", seen.size === STATES.size);

  // 10) shutdown from every live state
  for (const s of STATES) {
    if (TERMINAL.has(s)) continue;
    const m = new StateMachine(); m.state = s;
    let steps = 0;
    while (!m.terminal && steps < 3) {
      if (m.can("STOP_REQUESTED")) m.transition("STOP_REQUESTED");
      else if (m.can("ATTEMPTS_EXHAUSTED")) m.transition("ATTEMPTS_EXHAUSTED");
      else m.transition("FATAL_ERROR");
      steps++;
    }
    check(`sm:shutdown from ${s}`, m.terminal);
  }
}
