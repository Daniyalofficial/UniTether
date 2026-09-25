# 05 — Competitive Analysis

## 1. Feature matrix

Legend: ✅ full · ◐ partial/limited · ❌ absent

| Capability | **UniTether** | **Gnirehtet** (v2.5.1) | **AGB** | **Linksy** | **Tetrd** | **scrcpy** | **Vysor** | **AirDroid** | **KDE Connect** | **Deskreen** |
|---|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| Reverse tether (phone→PC net) | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ✅(cloud) | ❌ | ❌ |
| IPv6 | ✅ | ❌ | ❌ | ◐ | ❌ | ❌ | ❌ | ◐ |  | ❌ |
| USB + Wireless (Wi-Fi Direct/BT/LAN) | ✅ all 4 | USB only | USB only | LAN/cloud | USB only | USB/LAN | USB/cloud | LAN/cloud | LAN | LAN |
| No root required | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Auto-stop on disconnect | ✅ | ❌ |  | ◐ | ◐ | ✅ | ◐ | ◐ | ✅ | ◐ |
| Screen mirroring | ✅ <50 ms LAN | ❌ | ❌ | ◐(cloud) | ❌ | ✅(<20 ms) | ◐ | ◐ | ◐ | ❌(host→device) |
| Audio both directions | ✅ | ❌ | ❌ | ❌ | ❌ | ◐(mic→PC) | ◐ |  | ✅(speaker) | ◐ |
| Touch/mouse/keyboard injection | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ✅ | ◐ | ✅(keyboard) | ✅(host only) |
| Network throttling (2G–5G/loss/latency) | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| SOCKS5/HTTP proxy on host | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ◐ | ❌ | ❌ |
| ICMP / ping passthrough | ✅ | ❌ | ❌ |  | ❌ | ❌ | ❌ | ◐ |  | ❌ |
| Clipboard sync | ✅ | ❌ | ❌ | ✅ | ❌ | ❌ | ◐ | ✅ | ✅ | ❌ |
| File transfer | ✅ | ❌ | ❌ | ✅ | ❌ |  | ✅ | ✅ | ✅ | ❌ |
| Notification mirroring | ✅ | ❌ | ❌ |  | ❌ | ❌ | ◐ | ✅ | ✅ | ❌ |
| SMS / reply from desktop | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ◐ | ✅ | ❌ |
| Camera as webcam | ✅ | ❌ | ❌ | ✅(cloud) | ❌ | ✅ | ✅ | ✅ | ◐ | ❌ |
| GUI (Win/macOS/Linux) | ✅ | ❌ | ❌(Win only) | ✅(Web) | ❌ | ❌ | ✅ | ✅ | ✅ | ✅(Web) |
| Multi-device on one host | ✅ (5+) | ◐ | ❌ | ◐ |  | ◐ |  | ✅(cloud) | ✅ | ❌ |
| Open source, self-hostable | ✅ | ✅ | ✅ | ❌(closed) | ✅ | ✅ | ❌ | ❌ | ✅ | ✅ |
| Offline (no account/cloud) | ✅ | ✅ | ✅ | ❌ | ✅ | ✅ | ◐ | ❌ | ✅ | ✅ |
| IPv6 + 4K mirroring + QoS *in one* | ✅ | — | — | — | — | — | — | — | — | — |
| Actively maintained | ✅ | ❌(archived-ish) | ❌ | ✅ | ◐ | ✅ | ❌ | ✅ | ✅ | ◐ |

Sources: project READMEs/release notes as of 2026-09 (Gnirehtet v2.5.1
README states USB-only, IPv4-only, no IPv6 plans; scrcpy v2.x README;
KDE Connect feature list; AirDroid/Vysor/Linksy/Deskreen product pages).

## 2. Where each competitor wins (honest view)

- **scrcpy**: lowest mirroring latency and input fidelity (USB). It does
  *not* do networking at all. → We coexist; our input path will borrow
  scrcpy's event semantics.
- **KDE Connect**: best notification/clipboard UX *on Linux desktops*,
  but no tethering, no throttling, desktop-only, Linux-centric.
- **AirDroid / Vysor / Linksy**: cloud accounts, subscriptions, privacy
  ceiling. → Our differentiator: **fully local, no account, open source**.
- **Tetrd/AGB**: closer Gnirehtet forks, still IPv4/USB-only, tiny
  communities. → We absorb their user base with dual-stack + wireless.

## 3. How UniTether wins in every category we enter

1. **Networking**: only product with dual-stack + 4 transports + QoS
   shaper + proxy + ICMP. Gnirehtet forks lack wireless; cloud tools
   leak traffic through their servers.
2. **Media**: scrcpy-grade input + *networking at the same time* —
   no other product mirrors *and* tethers *and* shapes traffic.
3. **Productivity**: parity with KDE Connect/AirDroid but local +
   cross-platform (KDE Connect is weak on Windows; AirDroid is
   cloud-first).
4. **Trust**: open source, self-hostable, no account, audited crypto,
   local-only by default. AirDroid/Vysor cannot match this.
5. **Maintenance**: active CI + spec + conformance suite vs abandoned
   baselines — forks consolidate on a maintained core (that's us).

## 4. Gnirehtet's Apache-2.0 — what it means for us

- Gnirehtet is Apache-2.0 → we **may** use/modify/relicense-compatible
  reference, and we **must** preserve its copyright/NOTICE if we copy
  code. We have **copied no code**; we implement the *concept*
  (VPNService + TUN + ADB, which is also described in AOSP docs), so the
  obligation is attribution, not source sharing.
- Apache-2.0 is permissive and patent-granting → no copyleft trap for
  our Apache-2.0 (or future dual-licensed) project. See `10-OPEN-SOURCE.md`.
- Etiquette: README badge, `NOTICE` entry, `docs/14-ACKNOWLEDGMENTS.md`,
  and a credit line in every marketing asset (done in this repo).
