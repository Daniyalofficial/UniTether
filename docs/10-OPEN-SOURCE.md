# 10 — Open Source vs Closed Source & Licensing

## Recommendation: **open source, Apache-2.0, with a dual-license escape hatch**

### Why open source wins here
1. **Category trust.** The audience (devs, privacy users) will not run
   a *closed* app that sits between their phone and their network.
   Gnirehtet/scrcpy/KDE Connect are all OSS; a closed "improvement"
   loses the credibility war before feature parity.
2. **The baseline is Apache-2.0.** Our architecture is explicitly
   derived from an Apache-2.0 project's *concept*; shipping closed
   while crediting an OSS baseline reads as extractive. Open-sourcing
   removes that friction permanently.
3. **Distribution leverage.** F-Droid + GitHub Releases + AUR +
   Homebrew + winget all *require* OSS. That's our install pipeline.
4. **Community as QA.** 4 OSes × 20+ Android OEM builds = impossible
   to test in-house; contributors test their own hardware.

### Why Apache-2.0 (not GPLv3)
| | Apache-2.0 | GPLv3 |
|---|---|---|
| Forks/corporate adoption | ✅ frictionless | ⚠ patent clause scares some |
| Compatible with our OSS deps | ✅ | ✅ (with care) |
| Can we later sell a closed derivative? | ❌ no (permissive = no lock-in) | ✅ yes |
| Matches Gnirehtet/scrcpy/KDE Connect | ✅ same license = easy cross-project PRs | ❌ |
| Patent grant to users | ✅ explicit | ✅ (enforceable clause) |

**Decision: Apache-2.0** (see `LICENSE`). The "sell a closed
derivative" case doesn't apply: our business is *not* the software
(see `09-MARKETING.md` — no cloud, no account); it's brand +
contributor goodwill + optional consulting.

### Dual-license escape hatch
Core stays Apache-2.0 forever. A **separate** enterprise layer (fleet
manager, MDM hooks, commercial support SLA) may ship under a
restrictive license *without* modifying the core (it consumes the core
via public interfaces). If that ever becomes real revenue, the core
can additionally be dual-licensed Apache-2.0 + EUPL-1.2 for patent
strengthening in the EU — a decision reserved for post-1.0 with a
governance doc.

### Attribution obligations (satisfied in-repo)
- `NOTICE` + `docs/14-ACKNOWLEDGMENTS.md` for Gnirehtet (Apache-2.0 §4).
- Copyright headers in all source files.
- `SECURITY.md` disclosure channel (good-faith, also required by the
  patent-grant's good-standing expectations).
