# 23 — Observability

Status: event schema + metrics catalog **defined and implemented in
slice A9** (Python reference + Rust host, structured JSON-line events);
GUI display in A10. Telemetry to any remote endpoint is **off by
default and requires explicit consent** (Phase 29 privacy center).

## 1. Structured events (implemented, A9)

Every log/event line is JSON with this envelope (schema v1, stable):

```json
{"v":1,"ts":1714000000.123,"sev":"info","ev":"session.state",
 "session":"3f2a…","device":"8c1d…","transport":"tcp","ulp":"1.0",
 "state":"CONNECTED","from_state":"AUTHENTICATING","err":null,
 "ctx":{"rtt_ms":12}}
```

Fields:
- `session` — 12-hex prefix of session_id (v1: derived from handshake
  transcript; v1.1: the negotiated `session_id`).
- `device` — device_id prefix (v1.1) or name-hash (v1).
- `ulp` — negotiated protocol version ("1.0"/"1.1").
- `sev` — `debug|info|warn|error|fatal`.
- `err` — structured error (code, retryable) when `sev>=warn` (A8).
- `ctx` — per-event fields; **content fields are forbidden** (enforced
  by schema test: no string field > 128 chars, no fields named
  sms/clipboard/file_data/screen/audio_bytes).

Event catalog (emitted today after A9): `session.state` (every
transition, Phase 6), `session.handshake` (latency, cipher, version),
`session.resume` (attempt, ok, backoff_ms), `transport.drop`,
`transport.reselect`, `channel.sched` (queue depths, starvation count),
`file.op` (start/resume/progress-throttle/done, bytes, sha256 ok),
`pairing.attempt` (ok/throttled/revoked — no secret material),
`diagnostic.step` (Phase 31 output).

## 2. Metrics catalog (Phase 32)

| Metric | Type | Source | Privacy |
|---|---|---|---|
| `session_handshake_ms` | histogram | host+device | safe |
| `session_connect_total{result}` | counter | host | safe |
| `session_reconnect_total{attempt}` | counter | host | safe |
| `rtt_ms` / `loss_x100` | gauge | STATS channel (existing) | safe |
| `tunnel_bytes{dir,fam}` | counter | tunnel | safe (counts only) |
| `video_fps` / `video_latency_ms` | gauge | mirror pipeline | safe |
| `audio_underrun_total` | counter | audio engine | safe |
| `file_bytes{dir}` / `file_errors_total` | counter | file engine | safe (no names by default; names only in local logs, never remote) |
| `cpu_pct` / `mem_bytes` / `battery_pct` | gauge | device | safe |
| `crash_total` | counter | crash handler (A9 design) | safe (stack redacted, Phase 33) |
| `crash_free_sessions` | derived | A9 | safe |

**Rule: no content, ever.** Telemetry never carries SMS, clipboard,
files, screen frames, camera frames, or audio. Enforcement: schema test
(A9) + code review checklist.

## 3. Crash reporting (Phase 33)

- Android: `Thread.setDefaultUncaughtExceptionHandler` wrapper → event
  `crash` with version/platform/model/transport/feature/state; stack
  trace **redacted** (paths outside the app package → `…`); upload is
  consent-gated (off by default).
- Rust host: catch_unwind per worker + `panic::set_hook` → local
  `~/.local/share/unilink/crash-<ts>.json` (local always; remote
  consent-gated).
- No third-party crash service in v0.x (privacy-first); the event format
  is upload-compatible (Phase 24 API).

## 4. Local logs & redaction

- Host: `~/.local/share/unilink/unilink.log` (JSON lines, 5 MiB × 3
  rotation). GUI "Logs" view tails it (A10).
- Android: Logcat tag `UniTether` at INFO by default; DEBUG behind a
  settings flag. No frame payloads at any level.
- Redaction test (A9): a fuzzer-driven event emitter must never produce
  a field violating the schema.

## 5. Diagnostics engine (Phase 31)

`unitether diagnose <addr>` (host CLI, A9/A10) + GUI "Diagnostics" tab —
runs real checks, returns structured results with recommendations:
device reachable (TCP), pairing valid, handshake (cipher/version),
transport (latency baseline), DNS (via tunnel), IPv4/IPv6 echo (existing
E2E probes), MTU (binary search), packet loss (lossy link harness
locally), permissions (Android reports per-permission state over
CH_USER), VPN active, MediaProjection active, camera/audio present,
proxy bound. Output: JSON + human summary ("High packet loss on Wi-Fi —
try ADB/USB transport").
