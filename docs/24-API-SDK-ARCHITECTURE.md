# 24 — Public API & SDK Architecture

Status: **design + Rust core SDK surface defined**. REST API and JS
bindings are **not implemented** (cloud-dependent, Phase 18); the
Rust/Android SDK surface below IS implemented in-repo (it is the
existing crate interface, now documented as the stable API).

## 1. API stability policy (Phase 67)

| Tier | Prefix | Breaking changes |
|---|---|---|
| Internal | `unilink_protocol::internal` | never stable |
| Experimental | `unilink_protocol::v11` (marked) | may change in minors, flagged |
| Stable | crate root exports of `unilink-protocol` / `unilink-transport` | SemVer; breaking = major only |
| Enterprise | (v2) `/api/v1/enterprise/*` | SLA-bound, separate versioning |

Documented guarantees: (a) frame/message byte layouts of published
ULP versions are stable per docs/21; (b) `Session::send/recv`,
`Tunneler::connect`, capability bitcodes are stable in the stable tier;
(c) error codes (A8) are append-only.

## 2. Rust core SDK (implemented — this is `host/crates`)

```rust
use unilink_transport::{Session, Transport, TcpTransport};
use unilink_tunnel::{Tunneller, TunnelConfig};
use unilink_protocol::{Caps, Cipher, Error, SessionState};

let mut t = TcpTransport::connect("192.168.1.50:41880").await?; // A1
let mut s = Session::connect_host(&mut t, &secret, Caps::default()).await?;
assert_eq!(s.state(), SessionState::Connected);          // A2
let tun = Tunneller::new(&s, TunnelConfig::default()).await?; // dual-stack
let stream = tun.connect(IpAddr::from([1_1,1,1]), 443).await?;
```

Stable surface (A1/A2 make this true — trait + state are the new
stable APIs). Everything else in-crate is marked `#[doc(hidden)]`
until promoted.

## 3. JS/TS SDK (planned, v1.0)

`@unilink/sdk` = Tauri-side wrapper + browser-free Node build over the
same core (napi-rs). Surface: `discover()`, `pair()`, `connect()`,
`capabilities()`, `files()`, `network()`, `on(event)`. Stability:
semver, breaking = major. **Not built yet — do not ship.**

## 4. REST API (planned, v2, with cloud)

- Base `/api/v1/`; auth: org API key (header `X-UniTether-Key`) +
  per-user tokens; request ID `X-Request-Id` (echoed, used in audit);
  consistent errors `{code, message, request_id, retryable}`;
  pagination `?cursor=`/`limit≤200`; idempotency `Idempotency-Key` for
  mutations (device registration, policy publish);
  rate limits per docs/25 §6; versioning: additive within v1, `/api/v2`
  for breaks, 12-month coexistence.
- Resources: devices, sessions, policies, audit, usage, orgs/teams/users.
- **Never** exposes DB row shapes; response schemas in OpenAPI (v2).

## 5. Automation / plugin / AI interfaces (planned — Phase 26/27/28)

- **Plugins (v2):** manifest `{name, version, permissions[], capabilities[], deps[]}`,
  sandboxed process (seccomp/worker thread with capability proxy),
  default-deny IPC (docs/25 §6). No plugin can touch session keys.
- **Automation (v2):** `event → rule(conditions) → action` with
  permission-scoped actions; rules stored in org policy; execution
  audited. Local automation (Phase 27 on the device) reuses the same
  shape over CH_USER — design only.
- **AI (v2, optional):** diagnostics assistant + natural-language
  device search over *metadata only* (names, capabilities, state) —
  never content; explicit consent; local model option.
