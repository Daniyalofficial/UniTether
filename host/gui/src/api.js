/**
 * Backend adapter.
 *
 * - Inside a Tauri build: every call goes to the real Rust backend
 *   (mDNS/ADB discovery, real ULP session, real TUN tunnel).
 * - Inside a plain browser (design preview / CI): a clearly-labeled
 *   SIMULATION provides the same command surface so the full UI can
 *   be exercised. The simulation badge is visible in the UI; no
 *   simulated result is ever presented as a real device or tunnel.
 */

const HAS_TAURI = typeof window !== "undefined" &&
  !!(window.__TAURI_INTERNALS__ || window.__TAURI__);

import { invoke } from "@tauri-apps/api/core";

// ------------------------------------------------------------------ simulation
const SIM_DEVICES = [
  { name: "Pixel 8 (simulated)", address: "192.168.1.42", port: 41880,
    transport: "lan", rtt_ms: 3 },
  { name: "ADB · demo-serial (simulated)", address: "127.0.0.1", port: 41880,
    transport: "adb", rtt_ms: 1 },
];

function simBackend() {
  const state = {
    connected: false,
    connecting: false,
    connectedSince: 0,
    tunnel: { ipv4: true, ipv6: true, dns_v4: "1.1.1.1", custom_dns: [] },
    proxy: { http: null, socks: null, bypass: [] },
    seed: 42,
    baseIn: 2.4 * 1024 * 1024,   // simulated throughput
    baseOut: 0.6 * 1024 * 1024,
  };
  const blob =
    "UNITETHER1:" +
    Array.from({ length: 48 }, () =>
      "0123456789abcdef"[Math.floor(state.seed++ * 7 % 16)]).join("");

  return {
    isSim: true,
    async list_devices() {
      await wait(400);
      return SIM_DEVICES.map((d) => ({ ...d }));
    },
    async connect(_address, _port, _blob) {
      await wait(900); // handshake + AUTH_OK
      if (!state.connected) {
        state.connected = true;
        state.connectedSince = Date.now();
      }
      return "connected (simulation)";
    },
    async disconnect() {
      await wait(200);
      state.connected = false;
    },
    async tunnel_config(ipv4, ipv6, dns_v4, custom_dns) {
      await wait(120);
      Object.assign(state.tunnel, { ipv4, ipv6, dns_v4, custom_dns });
    },
    async proxy_config(http, socks, bypass) {
      await wait(120);
      Object.assign(state.proxy, { http, socks, bypass });
    },
    async get_stats() {
      if (!state.connected) {
        return { connected: false, uptime_s: 0, bytes_in: 0, bytes_out: 0,
          rtt_ms: null, loss_pct: 0, fps: 0 };
      }
      // deterministic wobble so the dashboard feels alive
      const w = (Math.sin(Date.now() / 900) + 1) / 2;
      const up = state.connectedSince ? (Date.now() - state.connectedSince) / 1000 : 0;
      return {
        connected: true,
        uptime_s: Math.floor(up),
        bytes_in: Math.floor(state.baseIn * (0.8 + 0.4 * w)),
        bytes_out: Math.floor(state.baseOut * (0.8 + 0.4 * (1 - w))),
        rtt_ms: 2 + Math.floor(4 * w),
        loss_pct: 0,
        fps: 0,
      };
    },
    async get_pairing() {
      await wait(80);
      return blob;
    },
    async set_language(_lang) { /* front-end driven */ },
  };
}

function wait(ms) { return new Promise((r) => setTimeout(r, ms)); }

// ------------------------------------------------------------------ real backend
function tauriBackend() {
  return {
    isSim: false,
    list_devices: () => invoke("list_devices"),
    connect: (address, port, pairBlob) =>
      invoke("connect", { address, port, pairBlob }),
    disconnect: () => invoke("disconnect"),
    tunnel_config: (ipv4, ipv6, dnsV4, customDns) =>
      invoke("tunnel_config", { ipv4, ipv6, dnsV4, customDns }),
    proxy_config: (http, socks, bypass) =>
      invoke("proxy_config", { http, socks, bypass }),
    get_stats: () => invoke("get_stats"),
    get_pairing: () => invoke("get_pairing"),
    set_language: (lang) => invoke("set_language", { lang }),
  };
}

export const api = HAS_TAURI ? tauriBackend() : simBackend();
export const IS_SIM = api.isSim;
