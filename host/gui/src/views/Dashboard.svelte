<script>
  import { connection, stats, settings, applyTunnelSettings, applyProxySettings, disconnect } from "../store";
  import { t } from "../i18n";

  function fmtBytes(bps) {
    if (!bps) return "0";
    if (bps >= 1e6) return (bps / 1e6).toFixed(1) + " MB/s";
    if (bps >= 1e3) return (bps / 1e3).toFixed(0) + " KB/s";
    return bps + " B/s";
  }
  function fmtUptime(s) {
    const h = Math.floor(s / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    if (h) return `${h}h ${m}m`;
    if (m) return `${m}m ${sec}s`;
    return `${sec}s`;
  }

  let tunnelMsg = "";
  let proxyMsg = "";

  async function applyTunnel() {
    try { await applyTunnelSettings(); tunnelMsg = t("applied"); }
    catch (e) { tunnelMsg = String(e); }
    setTimeout(() => (tunnelMsg = ""), 2500);
  }
  async function applyProxy() {
    try { await applyProxySettings(); proxyMsg = t("applied"); }
    catch (e) { proxyMsg = String(e); }
    setTimeout(() => (proxyMsg = ""), 2500);
  }
</script>

<div class="view-head">
  <h1>{t("nav_dashboard")}</h1>
  <div class="row">
    {#if $connection.state === "connected"}
      <span class="pill ok">● {t("status_connected")}</span>
      <button class="btn danger" on:click={disconnect}>{t("disconnect")}</button>
    {:else}
      <span class="pill">{t("status_idle")}</span>
    {/if}
  </div>
</div>

{#if $connection.state === "disconnected" && $connection.detail}
  <p class="error-text">{t("error_label")}: {$connection.detail}</p>
{/if}

{#if $connection.state === "connected"}
  <div class="grid-3" style="margin-bottom:14px">
    <div class="stat">
      <div class="label">{t("uptime")}</div>
      <div class="value">{fmtUptime($stats.uptime_s || 0)}</div>
    </div>
    <div class="stat">
      <div class="label">{t("bytes_in")} ▼</div>
      <div class="value">{fmtBytes($stats.bytes_in)}</div>
    </div>
    <div class="stat">
      <div class="label">{t("bytes_out")} ▲</div>
      <div class="value">{fmtBytes($stats.bytes_out)}</div>
    </div>
  </div>
  <div class="grid-3" style="margin-bottom:14px">
    <div class="stat">
      <div class="label">{t("rtt")}</div>
      <div class="value">
        {#if $stats.rtt_ms != null}
          {$stats.rtt_ms}<span class="unit">{t("ms")}</span>
        {:else}—{/if}
      </div>
    </div>
    <div class="stat">
      <div class="label">{t("loss")}</div>
      <div class="value">{$stats.loss_pct}<span class="unit">%</span></div>
    </div>
    <div class="stat">
      <div class="label">{t("fps")}</div>
      <div class="value">{$stats.fps || 0}<span class="unit">fps</span></div>
    </div>
  </div>
{/if}

<div class="grid-2" style="margin-bottom:14px">
  <section class="card">
    <h2>{t("tunnel_title")}</h2>
    <p class="desc">{t("tunnel_desc")}</p>

    <div class="row" style="margin-bottom:12px">
      <button class="toggle {$settings.ipv4 ? 'on' : ''}" role="switch" aria-checked={$settings.ipv4}
              on:click={() => settings.update(st => ({ ...st, ipv4: !st.ipv4 }))}>
        <span class="track"><span class="knob"></span></span> {t("tunnel_ipv4")}
      </button>
      <button class="toggle {$settings.ipv6 ? 'on' : ''}" role="switch" aria-checked={$settings.ipv6}
              on:click={() => settings.update(st => ({ ...st, ipv6: !st.ipv6 }))}>
        <span class="track"><span class="knob"></span></span> {t("tunnel_ipv6")}
      </button>
      <span class="pill {($settings.ipv4 || $settings.ipv6) ? 'ok' : ''}">
        {($settings.ipv4 || $settings.ipv6) ? t("tunnel_on") : t("tunnel_off")}
      </span>
    </div>

    <div class="field">
      <label for="f-dns">{t("dns")}</label>
      <input id="f-dns" class="mono" bind:value={$settings.dns_v4} placeholder="1.1.1.1" />
    </div>
    <div class="field">
      <label for="f-cdns">{t("custom_dns")}</label>
      <input id="f-cdns" class="mono" bind:value={$settings.custom_dns} placeholder="8.8.8.8, 1.0.0.1" />
    </div>
    <div class="row">
      <button class="btn" disabled={$connection.state !== "connected"} on:click={applyTunnel}>{t("apply")}</button>
      {#if tunnelMsg}<span class="muted">{tunnelMsg}</span>{/if}
    </div>
  </section>

  <section class="card">
    <h2>{t("proxy_title")}</h2>
    <p class="desc">{t("proxy_desc")}</p>
    <div class="field">
      <label for="f-ph">{t("proxy_http")}</label>
      <input id="f-ph" class="mono" bind:value={$settings.proxy_http} placeholder="http://127.0.0.1:8888" />
    </div>
    <div class="field">
      <label for="f-ps">{t("proxy_socks")}</label>
      <input id="f-ps" class="mono" bind:value={$settings.proxy_socks} placeholder="socks5://127.0.0.1:1080" />
    </div>
    <div class="field">
      <label for="f-pb">{t("proxy_bypass")}</label>
      <input id="f-pb" class="mono" bind:value={$settings.proxy_bypass} placeholder="localhost, 192.168.*" />
    </div>
    <div class="row">
      <button class="btn" disabled={$connection.state !== "connected"} on:click={applyProxy}>{t("apply")}</button>
      {#if proxyMsg}<span class="muted">{proxyMsg}</span>{/if}
    </div>
  </section>
</div>

<section class="card">
  <h2>{t("features")}</h2>
  <div class="feature-row"><span>▸</span> {t("feature_tether")}
    <span class="st pill {($settings.ipv4 || $settings.ipv6) && $connection.state === "connected" ? 'ok' : ''}">
      {$connection.state === "connected" && ($settings.ipv4 || $settings.ipv6) ? t("tunnel_on") : t("tunnel_off")}</span></div>
  <div class="feature-row"><span>▸</span> {t("feature_mirror")}
    <span class="st pill">v0.2</span></div>
  <div class="feature-row"><span>▸</span> {t("feature_audio")}
    <span class="st pill">v0.2</span></div>
  <div class="feature-row"><span>▸</span> {t("feature_input")}
    <span class="st pill">v0.2</span></div>
  <div class="feature-row"><span>▸</span> {t("feature_files")}
    <span class="st pill">v0.2</span></div>
  <div class="feature-row"><span>▸</span> {t("feature_sms")}
    <span class="st pill">v0.2</span></div>
  <div class="feature-row"><span>▸</span> {t("feature_camera")}
    <span class="st pill">v0.2</span></div>
</section>
