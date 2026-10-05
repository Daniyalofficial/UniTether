<script>
  import { devices, scanning, connection, scan, connect, disconnect } from "../store";
  import { t } from "../i18n";

  export let goto;

  let address = "";
  let port = 41880;
  let error = "";

  async function connectDevice(dev) {
    error = "";
    const ok = await connect(dev.address, dev.port, null);
    if (!ok) error = $connection.detail;
    else goto("dashboard");
  }

  async function connectManual() {
    error = "";
    const ok = await connect(address, port, null);
    if (!ok) error = $connection.detail;
    else goto("dashboard");
  }
</script>

<div class="view-head">
  <h1>{t("nav_devices")}</h1>
  <button class="btn ghost" on:click={scan} disabled={$scanning}>
    {t("scan_again")}
  </button>
</div>

{#if $scanning}
  <p class="muted">{t("searching")}</p>
{:else if $devices.length === 0}
  <p class="muted">{t("no_devices")}</p>
{:else}
  <div class="device-grid">
    {#each $devices as dev (dev.address + ":" + dev.port + dev.name)}
      <div class="device-card">
        <div class="top">
          <span class="name">{dev.name}</span>
          <span class="pill {dev.transport}">{dev.transport === "adb" ? t("adb") : t("lan")}</span>
        </div>
        <div class="meta">
          {dev.address}:{dev.port}
          {#if dev.rtt_ms != null} · {dev.rtt_ms} {t("ms")}{/if}
        </div>
        <div class="actions">
          {#if $connection.state === "connected" && $connection.detail === dev.address}
            <button class="btn danger" on:click={disconnect}>{t("disconnect")}</button>
          {:else}
            <button class="btn primary" disabled={$connection.state === "connecting"}
                    on:click={() => connectDevice(dev)}>
              {t("connect")}
            </button>
          {/if}
        </div>
      </div>
    {/each}
  </div>
{/if}

<section class="card" style="margin-top:16px">
  <div class="row">
    <div class="field" style="flex:1">
      <label for="f-addr">{t("address")}</label>
      <input id="f-addr" class="mono" bind:value={address} placeholder="192.168.1.50" />
    </div>
    <div class="field" style="width:110px">
      <label for="f-port">{t("port")}</label>
      <input id="f-port" type="number" bind:value={port} />
    </div>
    <button class="btn" style="margin-top:20px"
            disabled={$connection.state === "connecting" || $connection.state === "connected"}
            on:click={connectManual}>
      {t("manual")}
    </button>
  </div>
  {#if error}<p class="error-text">{t("error_label")}: {error}</p>{/if}
</section>
