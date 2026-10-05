# 20 — Production Readiness

Status: **scorecard**. "Pass" means runnable evidence exists in this
repository (command shown). "Plan" means designed, not built.

## 1. Scorecard (v0.1 → v0.2)

| Area | v0.1 evidence | v0.2 target | How it's proven |
|---|---|---|---|
| Protocol correctness | 83/83 vectors, 49/49 Node, 22/22 E2E | + v1.1 extensions, unknown-field tests | `make test` |
| Security (protocol) | MAC/tag negative paths in vectors | full `tests/security/` suite, fuzz smoke | CI job `security` |
| Reliability (reconnect) | none (session dies on link loss) | backoff+jitter, resume, chaos harness | `tests/chaos/` green |
| Resource safety | frame max 1 MiB enforced in framing | all limits + negative tests | `tests/security/limits.py` |
| Scheduling | none (FIFO) | priority scheduler, starvation tests | `tests/property/scheduler.py` |
| File integrity | none | SHA-256 + resume vectors | vectors + tear test |
| Observability | periodic STATS only | structured events, metrics catalog, no-content rule | schema test |
| Errors | bare exceptions | stable codes, retryable flags, correlation IDs | round-trip tests |
| i18n | 6 locales both sides, manual parity | automated key/placeholder/RTL checks | `tests/i18n/check_i18n.py` |
| CI | 5 jobs (conformance, rust, android, gui, bench) | + security, fuzz, property, i18n, sbom, audit jobs | workflow runs |
| Supply chain | no lockfiles/SBOM | lockfiles, audit jobs, SBOM, checksums | CI artifacts |
| GUI production | functional, no onboarding/diagnostics | onboarding, device cards, diagnostics, permission center (real data) | build + manual checklist in docs/27 |
| Perf gate | loopback bench (gate PASS) | + crypto micro-bench, thresholds in CI | CI job `benchmarks` |
| Soak/chaos | none | 5-min scaled soak + chaos matrix (72 h in CI nightly) | CI artifacts |
| Enterprise (cloud) | none | **plan only** (docs/19/22/25) | not a v0.2 gate |

## 2. Definition of "production" per surface

- **Local tethering (core product):** production-ready when every row in
  §1 through "Perf gate" is green in CI for 5 consecutive stable-channel
  builds.
- **Desktop GUI:** same + manual QA checklist (docs/27 §5) executed on
  Windows/macOS/Linux.
- **Android app:** same + one manufacturer-matrix smoke (docs/27 §6) —
  with the honest caveat that a single dev phone ≠ Android (Phase 42).
- **Enterprise cloud:** NOT production-ready. Designed (docs/19/22/25).
  Shipping it requires the build-out those docs specify. No SLA is
  claimed.

## 3. Known limitations (carried into v0.2, explicit)

1. INTEROP AEAD replay property (docs/18 §3.2) — mitigated per-channel in
   A4/A7, accepted for tunnel (IP-layer de-dup) — documented, not hidden.
2. QR pairing is unauthenticated (name-verify UX only) — A6/A10 improve.
3. No compression (flag reserved, never used) — by design until a
   bounded-decode codec ships (A3 rejects the flag on receive).
4. Android `SmsReplier` needs default-SMS-app on Android 9+ (UX flow).
5. Rust host not runnable in the authoring sandbox — CI is the authority
   for Rust; Python/Node suites are the authority for protocol bytes.
6. Single active session per phone (product constraint).
7. GUI `csp: null` until A10.

## 4. Release gates (Phase 54/55)

A release build is produced only when, in order: FORMAT → LINT → UNIT →
INTEGRATION → PROTOCOL → E2E → SECURITY → FUZZ-SMOKE → BENCH → BUILD →
PACKAGE → SBOM/audit → RELEASE-VALIDATION all pass. Channels: dev/
nightly/beta/stable; staged rollout policy in docs/25 §8.
