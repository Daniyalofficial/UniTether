# 14 — Acknowledging Gnirehtet (open-source etiquette)

UniTether's core idea — *reverse tethering via a no-root Android
`VPNService` bridged to a host TUN device over ADB* — comes directly
from **Gnirehtet** (Genymobile, Apache-2.0):
<https://github.com/Genymobile/gnirehtet>

We are explicit about this everywhere it matters:

1. **`NOTICE`** (repo root) — names Gnirehtet, its author, its
   license, and states the relationship (required by Apache-2.0 §4
   for derivative *concepts*; we copy no code, so it's courtesy +
   clarity, not obligation).
2. **README** — "Gnirehtet, grown up" + the comparison table keeps
   Gnirehtet's column honest (what it does, what it lacks, and what
   it *chose not to* do — its README says IPv6 isn't planned; we
   respect that scope and frame ourselves as an extension).
3. **This document** — deep dive for reviewers and contributors.
4. **Code comments** — where a file implements a Gnirehtet-known
   pattern (e.g., `localabstract:unilink` ↔ `localabstract:gnirehtet`),
   the header says so.
5. **Marketing** — every launch asset ("Show HN" title, blog post,
   press kit) credits Gnirehtet by name in the first screen.

## What we do NOT do
- We do **not** copy Gnirehtet source (zero shared code → zero
  §4 redistribution mechanics beyond attribution).
- We do **not** use the name "Gnirehtet", its logo, or its author's
  name in a way that implies endorsement (trademark/§6 care).
- We do **not** claim the *discovery* of the technique; we claim the
  extension (dual-stack, wireless, media, tooling).
- We do **not** fork-and-silence: if Gnirehtet were ever unmaintained
  but a maintainer asked for credit/fixes, we engage (the project is
  Apache-2.0; a joint PR to the upstream is always an option for
  security fixes).

## To the Gnirehtet author
If you're reading this: this project exists because yours worked.
The comparison tables are meant to show what the community wanted
next, not to diminish what you built.

## Other credit
- **scrcpy** (MIT): input event semantics and the ADB-socket
  handshake pattern we emulate for fidelity.
- **WinTun** (Apache-2.0), **libopus** (BSD), **MDNSResponder/mDNS**
  conventions: used as dependencies, credits in their own licenses.
- **KDE Connect** (GPLv3+): inspiration for notification/clipboard
  UX *patterns* (we implement independently, no code sharing —
  GPL would not allow code reuse, and we didn't need it).
