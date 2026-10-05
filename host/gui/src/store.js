/** Shared session state for all views. */
import { writable, derived, get } from "svelte/store";
import { api } from "./api";

const devices = writable([]);
const scanning = writable(false);
const connection = writable({ state: "disconnected", detail: "" }); // disconnected | connecting | connected
const stats = writable({
  connected: false, uptime_s: 0, bytes_in: 0, bytes_out: 0,
  rtt_ms: null, loss_pct: 0, fps: 0,
});
const pairing = writable({ blob: "", loading: false });
const settings = writable({
  ipv4: true, ipv6: true, dns_v4: "1.1.1.1", custom_dns: "",
  proxy_http: "", proxy_socks: "", proxy_bypass: "",
  port: 41880,
});

let pollTimer = null;

export async function scan() {
  scanning.set(true);
  try {
    devices.set(await api.list_devices());
  } catch {
    devices.set([]);
  } finally {
    scanning.set(false);
  }
}

export async function connect(address, port, blob) {
  connection.set({ state: "connecting", detail: address || "" });
  try {
    await api.connect(address, port, blob || null);
    connection.set({ state: "connected", detail: address || "" });
    startPolling();
    return true;
  } catch (e) {
    connection.set({ state: "disconnected", detail: String(e) });
    return false;
  }
}

export async function disconnect() {
  try {
    await api.disconnect();
  } finally {
    connection.set({ state: "disconnected", detail: "" });
    stopPolling();
    stats.update((s) => ({ ...s, connected: false }));
  }
}

export function startPolling() {
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    try {
      stats.set(await api.get_stats());
    } catch {
      /* transient */
    }
  }, 2000);
}

export function stopPolling() {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
}

export async function loadPairing() {
  pairing.set({ blob: "", loading: true });
  try {
    pairing.set({ blob: await api.get_pairing(), loading: false });
  } catch {
    pairing.set({ blob: "", loading: false });
  }
}

export function applyTunnelSettings() {
  const s = get(settings);
  return api.tunnel_config(
    s.ipv4, s.ipv6, s.dns_v4,
    s.custom_dns ? s.custom_dns.split(",").map((x) => x.trim()).filter(Boolean) : []);
}

export function applyProxySettings() {
  const s = get(settings);
  return api.proxy_config(
    s.proxy_http || null, s.proxy_socks || null,
    s.proxy_bypass ? s.proxy_bypass.split(",").map((x) => x.trim()).filter(Boolean) : []);
}

export function connected() {
  return get(connection).state === "connected";
}

export { devices, scanning, connection, stats, pairing, settings };
