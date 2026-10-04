# 22 — Disaster Recovery

Status: local DR **implemented in design + tests (A4/A6)**; cloud DR is
**design only** (no cloud service exists yet — nothing to back up).

## 1. Local operation (exists today / v0.2)

| Failure | Impact | Recovery | Status |
|---|---|---|---|
| Wi-Fi/ADB drop | session down | automatic reconnect, backoff+jitter (A4); `MSG_RESUME` re-keys and replays CONFIG/TUN_UP; files resume (A7) | [I] A4 |
| Host process crash | session down | same as above (device keeps identity + resumable session) | [I] A4 |
| Phone reboot | session down, resumable | autostart (BootReceiver) re-listens; host reconnects + resumes | [I] existing + A4 |
| Pairing secret loss (device wiped) | cannot resume | re-pair (QR); **old identity revoked on next pair** (A6) | [I] A6 |
| Stolen/compromised device | trust anchor exposed | user revokes device from host (A6 trust registry: revoke → session rejected with `REVOKED`); new identity generated | [I] A6 |
| Corrupted trust registry file | trust state lost | registry file is atomic-written (tmp+rename, A6) with SHA-256 footer; on corruption → safe-fail to "re-pair" (no auto-trust) | [I] A6 |
| Battery death mid-transfer | torn file | file v2 checksum → receiver discards incomplete; resume (A7) | [I] A7 |

**RPO local: 0** (no persistent service state beyond registry/files, all
durable). **RTO local: seconds** (measured in chaos harness, A11).

## 2. Cloud services (v2 target — design, NOT built)

Assumed services: identity, registry, relay pool, org/audit store.

- **Backups:** registry/orgs/billing → multi-region replicated store,
  PITR 35 days (target). Audit → append-only, replicated, immutable.
  Relay → stateless, nothing to back up (endpoint table is rebuildable
  from registry).
- **Multi-region:** active-active for registry reads (org-sharded,
  docs/19 §4); relay pools per region; failover = re-discovery, E2E
  sessions re-establish via RESUME (A4). No cross-region session
  migration in v2 (documented limit).
- **Key recovery:** org admins hold encrypted recovery keys for the
  *registry* (not for E2E session keys — those are unrecoverable by
  design; losing the pairing secret = re-pair, which is acceptable and
  documented).
- **RPO/RTO targets (v2, contractual only when SLA shipped):** registry
  RPO ≤ 1 min (replication lag), RTO ≤ 15 min (region failover); relay
  RPO 0 (stateless), RTO = client reconnect (≤ 30 s); audit RPO ≤ 5 min.
- **Incident response:** runbook per service (v2); severity levels;
  comms template; blameless postmortem within 5 business days.
- **No SLA is claimed in v0.x.** The targets above are design inputs,
  not commitments.

## 3. Recovery test plan

- Local: chaos matrix (A11) includes "host process kill mid-transfer",
  "phone reboot (simulated by closing the listening socket pair)",
  "IP change (simulated by rebind)", "DNS failure (tunnel DNS fallback
  test)".
- Cloud (v2): game-day drills quarterly: region kill, store corruption
  restore from PITR, key recovery drill. Not executable today — no
  cloud exists; documented as v2 acceptance criteria.
