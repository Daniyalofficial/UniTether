# 19 — Scalability Architecture

Status: **design only**. Nothing in this document is implemented. The
relay/cloud layer is optional and additive (docs/17 §2, layer 11). Local
operation scales as: one host session per phone (the product surface).

## 1. Scaling dimensions

| Dimension | v0.x reality | v2 target | Notes |
|---|---|---|---|
| Hosts per phone | 1 (1 active ULP session; phone-side `MAX_CONCURRENT_SESSIONS = 1` by design, A3) | N with capability partitioning (device fabric, docs/25 §6) | multiple *computers* pairing to one phone is the enterprise ask |
| Phones per org | 1:1 user | 10k+ per org | registry sharding |
| Relay throughput | n/a | 10 Gbps aggregate, stateless | §3 |
| Control-plane QPS | n/a | 1k QPS per region | standard |
| Session duration | unbounded (E2E soak 72 h target, A11) | same | leak tests |

## 2. What does NOT need to scale (deliberate)

- The protocol core: per-session state is O(1) + bounded queues (A3
  limits make memory per session constant and known).
- The Android app: single-process, one session; no internal sharding
  needed. Media pipelines are single-instance (one VirtualDisplay, one
  Opus stream) — that is a product constraint, not a scalability defect.
- The GUI: desktop app, no multi-tenant concern.

## 3. Relay architecture (v2 target)

```
Device ── E2E keys ──► [Relay A: stateless router]
                          │  routes encrypted ULP frames only
                          │  per-session byte accounting, rate limits
Host   ◄──────────────── [Relay B: same pool, region-aware]
        (host/device never share the same relay instance)
```

- **Stateless data path.** Relay holds at most: session_id → (device
  endpoint, host endpoint, quota bucket, created_at). Session keys are
  E2E (X25519 between endpoints); relay never decrypts, never buffers
  payload beyond one frame, never persists content (docs/18 T15).
- **Horizontal scale:** any relay can route any session; session→relay
  binding is chosen at connect time (STUN-like discovery, docs/25 §4) and
  stored in the registry (read-mostly, cacheable).
- **Resilience:** relay restart drops the data path; endpoints detect
  (ping timeout, A4 backoff) and re-discover — logical session resumes
  via `MSG_RESUME` (A4). RTO target: < 30 s re-establishment.
- **Abuse controls:** per-org byte quotas, per-device session limits,
  per-IP pairing rate limits, SYN flood protection (A11 design, Phase 58).
- **Regional routing:** Anycast edge → nearest region relay pool; E2E
  encryption makes routing location a latency choice, not a trust choice
  (orgs can pin regions via policy, docs/25 §5).

## 4. Registry / control plane (v2 target)

- **Sharding:** org → consistent-hash shard (128 shards initial); device
  records keyed by `org_id + device_id`; org records by `org_id`.
- **Isolation:** every query carries `org_id`; row-level enforcement
  (prepared statements with mandatory org filter) — no cross-tenant
  reads by construction (docs/25 §3).
- **DB split (docs/25 §7):** identity / devices / orgs / billing /
  audit / telemetry in separate schemas (or instances); audit is
  append-only; telemetry is partitioned by day, TTL 90 days (config).
- **Cache (Phase 35):** org policy (TTL 60 s, invalidation on publish),
  device capability summary (TTL 5 min). Never cached: secrets, pairing
  state, audit, any content.

## 5. Backpressure & resource model (implemented in A3/A5, scales to relay)

- Per-session bounded queues per channel priority (A5): total per-session
  buffer cap 8 MiB (configurable) → memory per session is bounded and
  constant regardless of network behavior.
- Scheduler (A5) weights: CONTROL 8 : INPUT 4 : AUDIO 3 : VIDEO 2 : FILE 1
  (default; org policy can override in v2).
- Relay inherits the same per-session accounting → an abusive session
  cannot exhaust relay memory beyond its buffer cap.

## 6. Capacity planning assumptions (to be benchmarked, not assumed)

Measured in A11 (benchmarks/): per-core framing+crypto rate (Python
reference ≈ 3k encrypted RT/s at 1 KB on CI hardware; Rust target ≥ 10×),
per-session CPU at 4K60 video + 25 Mbps tunnel. These numbers gate CI
regressions; they are the input to relay sizing. **No production
throughput claim is made before a Rust benchmark runs in CI.**

## 7. Scaling test plan (v2)

- Load: k6 script (planned) driving N relay-routed sessions through the
  E2E harness; thresholds: p99 control RT < 5 ms relay-added, 0 drops
  under 10 Gbps, buffer caps hold.
- Soak: 72 h at 50% nominal load; no leak (RSS slope < 0.1 %/h), no
  queue growth, reconnect rate < 0.1 %.
- Chaos (A11, local): fault injection on the direct link; (v2) relay
  partition + failover drills.
