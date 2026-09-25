# Contributing to UniTether

Thank you! UniTether is Apache-2.0 licensed, community-driven, and
deliberately built on top of (and in acknowledgment of) Gnirehtet.

## Ground rules

1. **No root, ever.** Nothing in the Android app may require root or
   adb-shell escalation. If your PR needs it, it is out of scope.
2. **Protocol changes are spec-first.** Change `docs/02-PROTOCOL.md` and
   `protocol/vectors/` in the same PR as the code. CI fails if vectors
   and reference implementations disagree.
3. **License headers.** New files must carry the Apache-2.0 header
   (templates in each crate's `LICENSE-HEADER` file).
4. **Tests with code.** Core crates must keep ≥80 % line coverage
   (tarpaulin gate in CI).
5. **Docs with features.** User-visible behavior gets a README/docs touch.

## Development

```bash
# Host core (Rust 1.79+)
cd host && cargo test --workspace

# Protocol conformance (Python 3.11+ and Node 20+ only, no deps)
python3 tests/e2e/run_e2e.sh
node tests/node/test.mjs

# Android (JDK 17, Android SDK 34)
cd device && ./gradlew assembleDebug lint

# GUI (Node 20+, Tauri prerequisites)
cd host/gui && npm install && npm run tauri dev
```

## Branches

- `main` — release-ready.
- `dev` — integration.
- `arena/*` — agent/session branches; merged via PR into `dev`.

## Reporting vulnerabilities

See `SECURITY.md`. Do not file public issues for security problems.
