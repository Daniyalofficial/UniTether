# 09 — Marketing & Launch Plan

## Positioning
**"The open-source, local-first bridge between your phone and computer —
everything scrcpy shows, everything Gnirehtet tethers, nothing in the
cloud."**

Audiences (in priority order):
1. **Developers/QA** (power users): need throttling (2G/3G profiles),
   proxy, ping, multi-device. They are the evangelists.
2. **Power consumers**: remote access, screen mirroring for TV/2nd
   monitor, file transfer without accounts.
3. **Privacy-conscious users**: AirDroid refugees; "no cloud, no
   account, audited crypto" is the headline.

## Channels
| Channel | Tactic |
|---|---|
| GitHub | The repo is the landing page. README = pitch + 60 s demo GIF. First 500 stars via HN + r/programming + r/androiddev launch sequence. |
| Hacker News | "Show HN: UniTether — Gnirehtet, grown up (dual-stack + mirroring, no root)" — launch day, tech-lead on comment duty. |
| X/Twitter + Mastodon | Weekly build threads (1 per week, screenshot + 10 s clip). |
| YouTube | 3 tutorials pre-launch: pair in 2 min; tether IPv6; 4K mirroring benchmark. |
| Reddit | r/selfhosted, r/privacy, r/Android (native features, not "app of the day" spam). |
| F-Droid + GitHub Releases | APK/AAB distribution from day one (Play Store at v1.0). |
| Localization communities | Urdu/Arabic/Hindi/Chinese/Spanish community testers from Phase 3 (i18n in `15-I18N.md`). |

## Launch sequence (v1.0)
- **T-6 wks**: closed beta (100 devs, Discord), weekly crash-free
  reporting published.
- **T-2 wks**: press kit (demo video, benchmark vs Gnirehtet/scrcpy,
  security whitepaper = `SECURITY.md` + audit summary).
- **T-0**: HN + Reddit + socials same day; repo trending push; blog
  post "Why we started with Gnirehtet" (etiquette + credibility, see
  `14-ACKNOWLEDGMENTS.md`).
- **T+2 wks**: "state of the bridge" post with telemetry (opt-in only):
  devices connected, latency percentiles, battery/hour.
- **T+6 wks**: 1.0.1 with beta fixes; invite community PRs to i18n/docs.

## Metrics (north star: **weekly paired sessions, local-only**)
- Beta: crash-free ≥ 99 %, p95 mirror latency, battery/h, NPS ≥ 40.
- Public: installs, paired sessions, GitHub stars, beta→public
  retention (week 4 ≥ 30 %).
- Hard no: no paid cloud, no account, no data reselling — it's in the
  license, it's in the brand.

## Cost & runway
No servers (self-hosted Sentry only), device farm ≈ 6 phones ≈ $1.2 k,
marketing ≈ content time. 6-month runway ≈ 5.5 FTE × salary — covered
by [funding source TBD]; open-source community work reduces effective
QA load after v0.2.
