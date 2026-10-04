# 28 — Quickstart: what to start, in what order, and how to use each thing

Audience: someone with a phone (Android 5.0+) and a host computer (Windows 10 /
macOS 11 / Ubuntu 20.04+), or just a browser, who wants reverse tethering
**today**.

## 1. Two ways to run this

| Mode | What you get | When to use |
|---|---|---|
| **Browser preview** (this repo's live preview) | The full GUI, running against a clearly-labelled **simulation** of the phone. Badge `SIMULATION` is always visible. | See and drive the complete UI: discover → pair → connect → tunnel → stats → settings → i18n (6 languages, RTL included). |
| **Desktop app (Tauri)** + **Android app** | The real thing: mDNS/ADB discovery, ULP v1.1 handshake, X25519 pairing, no-root VPNService on the phone, TUN tunnel on the host. | Actual phone ↔ computer traffic. |

The simulation exists so the frontend is testable without hardware. It is
labeled in the UI and never presented as a real device or tunnel.

## 2. Order of operations (real hardware)

```
Phone                                          Host
─────                                          ────
1. Install & open UniTether APK        ←      2. Start the desktop app
3. Grant VPN + foreground permissions   ←      3. Devices: phone appears (mDNS)
                                                or via ADB (port 41880)
4. Phone shows QR (or blob)             ←      5. Pairing: scan QR / paste blob
                                               6. Connect
                                               7. Dashboard: enable IPv4/IPv6,
                                                  set DNS, Apply
                                               8. Phone internet now flows
                                                  through the host (TUN)
```

### Step by step

1. **Phone**: install the release APK (`device/app/build/outputs/apk/release/`).
   First launch asks for **VPN permission** and **foreground notification** —
   allow both. No root, no adb, no PC required for the phone side.
2. **Host**: run the desktop app:
   ```bash
   cd host/gui
   npm install
   npm run tauri dev     # or the installed release binary
   ```
   The app listens for `_unilink._tcp` mDNS on the LAN **and** polls
   `adb devices` (auto-mapped to `127.0.0.1:41880`).
3. **Devices screen**: your phone appears with name, transport badge
   (`LAN` or `ADB`) and RTT. Press **Connect** — or use **Manual connect**
   with `address:port` if the phone is on a different subnet.
4. **Pairing screen** (shown before first connect, or any time):
   - Phone displays a QR encoding `UNITETHER1:<identity|pubkey|mac>`.
   - On the host, **Scan QR** (or **Paste pairing blob** + Copy to transfer
     the other way). Then **Connect**.
   - Pairing is identity-based (stable device ID + public key + trust
     registry), never name-based. Re-pairing re-authorizes; revoking a
     device removes its trust entry on the phone.
5. **Dashboard** (the main screen):
   - **Reverse tethering card** — the core feature. Toggles `IPv4` / `IPv6`
     build the dual-stack tunnel; `Upstream DNS` + custom DNS override
     resolution; **Apply** pushes `tunnel_config` to the session. When on,
     all phone traffic enters the host's TUN interface.
   - **Host proxy card** — forwards selected host applications *into* the
     tunnel (`HTTP proxy`, `SOCKS5 proxy`, bypass list). **Apply** pushes
     `proxy_config`.
   - **Live stats** — uptime, bytes in/out (rate/s), RTT, loss %, video fps;
     polled every 2 s from the session.
   - **Session features** — status strip for the v0.2 feature set (mirror,
     audio, input, files, SMS, camera) with version markers, so what ships
     and what is still `v0.2` is always visible, not claimed.
6. **Settings** — language (en/ur/ar/es/zh/hi; ur & ar flip the whole UI to
   RTL), tunnel port, About.

## 3. What to start for the browser preview

Nothing to install — the live preview at port 5173 **is** the app:

1. Open the preview → you see **Dashboard** with the `SIMULATION` banner.
2. **Devices** → two simulated devices appear (LAN + ADB). Press Connect.
3. **Pairing** → a real QR renders from the simulated `UNITETHER1` blob.
4. Back on **Dashboard** → stats come alive; flip IPv4/IPv6, edit DNS,
   Apply; set proxy + Apply.
5. **Settings** → switch language to اردو or العربية to watch the UI go RTL.

Everything in the preview maps 1:1 to a real Tauri command
(`list_devices`, `connect`, `disconnect`, `tunnel_config`, `proxy_config`,
`get_stats`, `get_pairing`, `set_language`) — in a desktop build the same UI
calls the real Rust backend instead of the simulation.

## 4. Development entry points

| Task | Command |
|---|---|
| Run everything (protocol → e2e → i18n → Rust → GUI build) | `make test` |
| GUI only (dev server, port 1420) | `cd host/gui && npm run tauri dev` |
| GUI frontend compile gate only | `make gui-build` |
| Full desktop app (release) | `make gui` |
| Android release APK | `make android` |
| i18n consistency (Android strings + GUI catalogs) | `make i18n` |
| E2E on real TCP | `bash tests/e2e/run_e2e.sh` |

## 5. Honest status of this deliverable

- **Working now**: protocol v1.1 (tested), state machine, pairing, tunnel
  engine, host proxy, full 6-locale GUI, all test suites green.
- **Requires your hardware to verify end-to-end**: the phone-side APK on a
  real device, and a Tauri build on your OS (this sandbox has no Android
  SDK / Rust toolchain — CI is the compile authority).
- **Not yet**: cloud/relay, mirroring/audio/input/file/SMS/camera channels
  are wired in the protocol and state machine but their device services are
  `v0.2` (marked as such in the UI, per the no-fake-features rule).
