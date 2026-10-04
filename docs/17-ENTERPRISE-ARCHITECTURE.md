# 17 — Enterprise Architecture (Audit + Target)

Status: **audit complete, target defined**. Implementation proceeds in the
vertical slices listed in §6; each slice lands with tests before the next
starts. Every "implemented" claim below is backed by a runnable test in
`tests/` unless explicitly marked otherwise.

## 1. What exists today (verified)

| Layer (current) | Where | Evidence |
|---|---|---|
| Protocol (ULP v1) | `host/crates/protocol`, `tests/protocol/reference_framing.py` (reference), `tests/node/ulplink.mjs` (port), `device/.../core/*.kt` (port) | 83/83 Python vectors, 49/49 Node, 22/22 Node↔Python real-TCP E2E |
| Crypto | same four implementations | RFC 7748 vectors, HKDF, INTEROP AEAD (documented construction, §4 of docs/18) |
| Session | `host/crates/transport/src/session.rs` (+ Python/Node/Kotlin ports) | handshake + encrypted loop in E2E |
| Transport (concrete) | TCP/LAN + ADB forward (Android `DeviceTransport`, host `transport::FramedConn`) | E2E runs over real TCP |
| Tunnel | `host/crates/tunnel` (TUN), `device/.../tunnel/TunnellingService.kt` (VPNService) | dual-stack E2E (IPv4+IPv6 echo with checksum verification) |
| Proxy | `host/crates/proxy` (HTTP/SOCKS5 over `CH_PROXY`) | conformance vectors for wire ops 0x01–0x05 |
| Media | H.264 mirror + Opus audio + input (device), camera | code + conformance vectors for channel payloads |
| GUI | `host/gui` (Tauri 2 + Svelte 4) | frontend builds (CI job `gui`) |
| Conformance/E2E | `tests/` | `make test` |

**Audit findings (gaps vs. enterprise bar):**

1. **No explicit transport abstraction.** The host session is constructed
   around a `FramedConn` bound to one TCP socket; ADB is a pre-transport
   socket forward, not a first-class transport. A QUIC/relay transport
   cannot be added without touching the session. → Slice A1 (Transport trait).
2. **No connection state machine.** States are implicit in control flow
   (`connected` bool + lock ordering). The dual-recv bug (fixed in
   `unitether/src/main.rs` by the `session_over` flag) was a symptom of
   exactly this: no single owner of the receive side, no transition log. →
   Slice A2 (state machine, Phase 6).
3. **No resource limits enforced in the Rust host.** `MAX_PAYLOAD` (1 MiB)
   is checked in framing, but queue depths, concurrent proxy connections,
   and auth attempt counts are unbounded. → Slice A3 (Limits, Phase 8).
4. **No reconnect/resumption.** `MSG_RESUME` (0x0E) is reserved with no wire
   format; a Wi-Fi drop ends the session. → Slice A4 (resume protocol +
   backoff manager, Phases 7/14).
5. **No channel scheduling.** Frames are sent in caller order; a file
   transfer can delay control frames. → Slice A5 (priority scheduler,
   Phase 9).
6. **No device identity.** Pairing uses a shared 32-byte secret; there is no
   stable per-device public key, no revocation, no trust state. → Slice A6
   (identity + trust, Phases 2/3), as ULP v1.1 extensions (backwards
   compatible — see docs/21).
7. **File transfer has no integrity/resume.** Data frames carry an offset
   but no per-file checksum; a torn transfer cannot resume. → Slice A7
   (file v2, Phase 12).
8. **No structured errors.** `ProtocolError`/`AuthError` are bare
   exceptions; no stable codes, no correlation IDs. → Slice A8 (Phase 46).
9. **No observability plumbing.** No session_id, no structured events, no
   metrics beyond periodic STATS. → Slice A9 (Phase 32).
10. **GUI has no diagnostics/onboarding/permission views.** → Slice A10
    (Phases 47–49), wired to real backend commands only.
11. **Cloud/relay/enterprise: design only.** Intentionally not built —
    local-first is the product (docs/19, docs/25 mark every item *planned*).

## 2. Target layer architecture

```mermaid
flowchart TB
    subgraph L11[11. Cloud — OPTIONAL]
        C1[Identity/Registry] --> C2[Relay coordinator]
        C2 --> C3[Org mgmt / Policy / Audit]
    end
    subgraph L10[10. GUI]
        G1[Tauri desktop] 
    end
    subgraph L9[9. App/Services]
        S1[Tunnel mgmt] S2[Proxy] S3[File engine] S4[Media services] S5[Diagnostics]
    end
    subgraph L8[8. Capability layer]
        K1[Capability registry + permission gate]
    end
    subgraph L7[7. Media layer]
        M1[Video adaptive] M2[Audio engine] M3[Input]
    end
    subgraph L6[6. Routing/Tunnel]
        T1[TUN/VPN routing] T2[DNS]
    end
    subgraph L5[5. Transport abstraction]
        TR1[ADB] TR2[TCP/LAN] TR3[QUIC exp.] TR4[Relay exp.]
    end
    subgraph L4[4. Session layer]
        SE1[State machine] SE2[Resume] SE3[Scheduler/QoS] SE4[Rate limits]
    end
    subgraph L3[3. Crypto]
        CR1[X25519] CR2[HKDF] CR3[AEAD] CR4[Identity keys]
    end
    subgraph L2[2. Protocol — ULP]
        P1[Framing] P2[Messages] P3[Versioning] P4[Errors]
    end
    P1 --> CR1
    SE1 --> P1
    TR1 --> SE1
    T1 --> SE1
    M1 --> SE1
    G1 --> S1
    C1 -. optional .-> G1
```

**Dependency rule:** arrows point downward only. The protocol layer
(2) must not import any transport type; the session layer (4) depends on
the `Transport` trait, never on TCP; the GUI (10) depends on service
commands (9), never on protocol bytes; cloud (11) is additive — the full
local path (2–9) must build and run with cloud code deleted.

## 3. Module map (current → target crate/package)

| Target layer | Rust host | Python/Node reference | Android |
|---|---|---|---|
| 2 Protocol | `unilink-protocol` (new `version.rs`, `error.rs` modules) | `reference_framing.py` (new `ulp_v11` section) + `ulp_session_state.py` | `core/UlpMessages.kt`, `core/UlpFrame.kt` |
| 3 Crypto | `unilink-protocol::crypto` | `reference_framing.py` crypto fns | `core/UlpCrypto.kt` |
| 4 Session | `unilink-transport` (new `state.rs`, `limits.rs`, `scheduler.rs`, `reconnect.rs`) | `ulp_link.py` + new `session_manager.py` | `core/UlpSession.kt`, new `SessionManager.kt` |
| 5 Transport | `unilink-transport::transport` (new `Transport` trait; `tcp.rs`, `adb.rs`; `quic.rs` experimental) | n/a (reference uses raw sockets as "the transport") | `transport/DeviceTransport.kt` (implements trait) |
| 6 Tunnel | `unilink-tunnel` | — | `tunnel/TunnellingService.kt` |
| 7 Media | — (media lives on device + GUI) | channel payload reference codecs | `mirror/`, `audio/`, `input/` |
| 8 Capability | `unilink-protocol::caps` (bitmask codec) | `caps` section in vectors | `core/Capabilities.kt` (new) |
| 9 Services | `unilink-unitether` CLI commands | harnesses | `MainActivity.kt` supervisor |
| 10 GUI | `host/gui/src-tauri` | — | — |
| 11 Cloud | *planned* (docs/19, docs/25) | — | — |

## 4. Non-negotiable invariants (enforced by tests)

1. **Byte-stability of ULP v1.** Every existing vector in
   `protocol/vectors/*.json` must continue to pass unchanged. v1.1
   extends via new message types + feature bits, never by re-encoding v1
   bytes.
2. **Local-only operation.** The full feature set minus cloud works with
   zero network egress beyond the direct device link (E2E suite proves
   this — it runs on 127.0.0.1).
3. **Single owner of the receive side.** Exactly one component consumes
   control frames per session; the state machine owns routing. Regression
   test: the dual-consumer scenario must be impossible by construction
   (state machine test A2-7).
4. **No unbounded growth from network input.** Every parser has a limit
   and a negative test proving it (Phase 8/37).
5. **Forward compatibility.** Unknown message types and unknown feature
   bits are ignored with a logged event, never a hard error (except
   reserved-ranges that must reject).

## 5. What is explicitly NOT in this delivery (documented, not fake)

QUIC transport, NAT traversal, relay service, cloud identity, admin
console, public REST API implementation, plugin runtime, automation
engine, AI features, billing. These have design documents (19/22/25) and
are marked *planned* everywhere they appear. The GUI/CLI will not display
fake cloud state.

## 6. Vertical slices (execution order)

| Slice | Phases | Deliverable | Gate (evidence) |
|---|---|---|---|
| A1 | 1, 13 | `Transport` trait + TCP impl behind session | Rust unit tests (CI) + unchanged E2E |
| A2 | 6 | State machine (Rust + Python + Node + Kotlin) | transition-table tests, all 3 runnable suites green |
| A3 | 8 | Limits (frames, queues, auth attempts, concurrency) | negative tests: oversized/over-limit rejected |
| A4 | 5, 7, 14 | Version negotiation, `MSG_DEVICE_ID/AUTH`, `MSG_RESUME` wire format, backoff+jitter reconnect manager | new vectors + E2E resume test + chaos harness (fault injection) |
| A5 | 9 | Priority scheduler + backpressure | scheduler tests: control never starved |
| A6 | 2, 3 | Device identity + trust registry (local file) + revocation + rate limiting of pairing | identity tests, revocation test, throttle test |
| A7 | 12 | File v2: RESUME op, SHA-256 integrity, atomic write, pause/cancel | vectors + resume-after-tear test |
| A8 | 46 | Structured errors (stable codes) in all 4 impls | error-code round-trip tests |
| A9 | 32, 60 | Structured events + metrics catalog + privacy rules | schema tests, no-content-in-telemetry test |
| A10 | 47–51 | GUI: design tokens, onboarding, device cards, diagnostics, permission center (real data only) | frontend build + command wiring review |
| A11 | 37–41, 54 | Security suite, mutation fuzz, property tests, chaos + soak harness, expanded CI | all jobs green, fuzz 0 crashes in smoke |
| A12 | 50, 62, 69 | i18n consistency checker, test matrix YAML, README rewrite | checker green on CI |
| A13 | 72 | docs/27 final readiness report | full suite run, honest status table |

## 7. Evolution path

v0.1 (this repo) → **v0.2 (slices A1–A13, this delivery)** → v1.0
(stable ULP v1.1 + SDK) → v2.0 (QUIC + capability fabric + enterprise
cloud, per docs/21 §5). Protocol compatibility matrix in docs/21 §4.
