# 25 — Enterprise Architecture (Multi-Tenancy, RBAC, Policy, Audit)

Status: **design only** (Phases 18–23, 57–60). None of this is
implemented in v0.2; it is specified so the build-out is unambiguous.
The local product remains complete without any of it.

## 1. Domain model

```
Organization ─< Team ─< Member (user, role)
Organization ─< Device (identity from ULP v1.1, trust state, group)
Organization ─< Policy (scope: org|team|group|device, versioned)
Device ─< Session (protocol session_id, transport, duration)
Organization ─< AuditEvent (append-only)
Organization ─< Subscription (plan, quotas) ─< UsageMetering
```

Tenant isolation: `org_id` is a mandatory filter on every read; stored
with row-level security where the store supports it; cross-tenant
access is a P1 incident (docs/18).

## 2. RBAC (Phase 20)

| Role | device.read | device.manage | device.revoke | session.view | policy.manage | audit.read | billing.manage |
|---|---|---|---|---|---|---|---|
| Owner | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| Admin | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |
| Security Admin | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | – |
| Device Manager | ✔ | ✔ | – | ✔ | – | – | – |
| Member | ✔ | – | – | ✔ (own) | – | – | – |
| Viewer | ✔ | – | – | ✔ | – | – | – |

Permissions are the unit of authorization (not roles); roles are
permission bundles. Custom roles: allowed for org admins (union of
known permissions only — no dynamic grants).

## 3. Policy engine (Phase 21)

Policy = versioned JSON document, evaluated deterministically
(pure function `evaluate(policy_set, subject, action, resource_ctx) →
Allow|Deny(reason)`; first-match-wins by specificity: device > group >
team > org). Controls (each independently grantable):

tethering, file.transfer, clipboard.sync, camera.use, mic.use,
notifications.mirror, sms.reply, remote.input, screen.share,
cloud.relay, external.proxy, automation.run, ai.diagnostics.

Policy publish → audit event `POLICY_CHANGED` → devices fetch on next
session (v2 push) → **enforced in the session layer** (capability gate,
docs/25 §6), not in the GUI. Evaluation is logged (decision + matched
rule ID) for audit.

## 4. Relay coordination (Phase 16/17)

Discovery service answers "relay for session S" (region-aware,
load-aware); relays register heartbeat + capacity; abuse signals
(throttle events) feed the per-org quota ledger. Relay is optional:
org policy `cloud.relay=off` forces direct-only; local users never
touch this surface.

## 5. Org configuration

org.json (policy-managed): defaults (DNS, MTU, video ladder, audio
profile, language), device groups (auto-tag by name/capability),
allowed transports, relay region pin, log retention.

## 6. Capability fabric (Phases 65/66)

Each device advertises a 64-bit capability vector (ULP v2 HELLO;
v1.1 carries the 32-bit v1 set in `MSG_DEVICE_ID.caps`):
NETWORK(0) DISPLAY(1) CAMERA(2) MIC(3) AUDIO(4) INPUT(5) STORAGE(6)
MESSAGING(7) NOTIFICATIONS(8) AUTOMATION(9) … App/peer requests
capabilities via policy-checked grants: `app.camera.read`,
`app.files.write`, `app.clipboard.read`, `app.screen.capture` —
default-deny, explicit grant, revocable, audited (grant = audit event
with correlation ID). This is the DEVICE↔DEVICE evolution path; v0.2
keeps phone→PC direction and records the fabric as the v2 shape.

## 7. Data platform (Phases 34/35)

Schemas: `identity` (orgs/users/roles), `devices` (registry),
`orgs` (policy/teams), `billing` (subs/usage/invoices), `audit`
(append-only, partitioned by month), `telemetry` (partitioned by day,
TTL 90 d). Migrations: numbered, forward-only in CI, reversible
downs for one minor. Indexes: (org_id, device_id), (org_id, ts),
(session_id). No unbounded scans: every list endpoint paginated;
analytical queries → telemetry store only. Caching: org policy (60 s),
device caps (5 min); invalidation on publish; never cache secrets/
audit/content.

## 8. Release & rollout (Phases 52/55)

Signed releases (host: minisign-style detached signatures + SHA256SUMS;
Android: Play/App release signing; GUI: tauri bundle sigs). Channels:
dev/nightly/beta/stable with per-org channel policy; staged rollout
(% by org, by region); rollback = repoint channel. Protocol
compatibility: min client version per server release (docs/21 §4),
old clients get a structured `ERROR(UPGRADE_REQUIRED)` — never a
mystery failure.

## 9. Billing (Phase 59)

Plans: Free (local-only, 1 device), Pro (multi-device, relay quota),
Business (teams, policies), Enterprise (SSO, audit export, SLA).
Billing is a separate service reading the usage ledger — protocol and
session code never import billing. Plan enforcement = quota ledger
checked at session start (soft) and at publish (hard).
