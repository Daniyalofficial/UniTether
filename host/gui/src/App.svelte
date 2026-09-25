<script>
  import { onMount } from "svelte";
  import { invoke } from "@tauri-apps/api/core";
  import DeviceCard from "./components/DeviceCard.svelte";
  import PairingPanel from "./components/PairingPanel.svelte";
  import StatsPanel from "./components/StatsPanel.svelte";
  import { lang, setLanguage, t, LANGUAGES } from "./i18n";

  let currentLang = $lang;
  $: currentLang = $lang;

  let devices = [];
  let scanning = true;
  let connected = false;
  let address = "";
  let port = 41880;
  let pairBlob = "";
  let error = "";

  async function refresh() {
    try {
      devices = await invoke("list_devices");
    } catch {
      devices = [];
    }
    scanning = false;
  }

  async function connect(dev) {
    address = dev ? dev.address : address;
    port = dev ? dev.port : port;
    error = "";
    try {
      await invoke("connect", {
        address,
        port,
        pairBlob: pairBlob.trim() || null,
      });
      connected = true;
    } catch (e) {
      error = String(e);
    }
  }

  async function disconnect() {
    try {
      await invoke("disconnect");
    } finally {
      connected = false;
    }
  }

  onMount(() => {
    refresh();
    const timer = setInterval(refresh, 5000);
    return () => clearInterval(timer);
  });
</script>

<div class="layout">
  <header>
    <h1>UniTether</h1>
    <label class="lang">
      {t("language")}
      <select bind:value={currentLang} on:change={() => setLanguage(currentLang)}>
        {#each LANGUAGES as [code, label]}
          <option value={code}>{label}</option>
        {/each}
      </select>
    </label>
  </header>

  <section class="panel">
    <h2>{t("devices")}</h2>
    {#if scanning}
      <p class="muted">{t("searching")}</p>
    {:else if devices.length === 0}
      <p class="muted">{t("no_devices")}</p>
    {:else}
      <div class="grid">
        {#each devices as d (d.address + d.port + d.name)}
          <DeviceCard device={d} connected={connected} on:connect={() => connect(d)} on:disconnect={disconnect} />
        {/each}
      </div>
    {/if}
    <div class="manual">
      <label>{t("address")} <input bind:value={address} placeholder="192.168.1.50" /></label>
      <label>{t("port")} <input type="number" bind:value={port} /></label>
      <button class="secondary" disabled={connected} on:click={() => connect(null)}>{t("manual")}</button>
    </div>
  </section>

  <PairingPanel bind:pairBlob bind:error />

  <div class="row">
    <StatsPanel connected={connected} />
    <section class="panel">
      <h2>{t("features")}</h2>
      <p class="muted">{t("features_list")}</p>
    </section>
  </div>
</div>

<style>
  .layout {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 16px;
    max-width: 960px;
    margin: 0 auto;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  h1 { font-size: 20px; margin: 0; }
  h2 { font-size: 15px; margin: 0 0 10px; color: var(--accent); }
  .muted { color: var(--muted); }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
    gap: 10px;
  }
  .manual {
    display: flex;
    gap: 8px;
    margin-top: 12px;
    align-items: center;
  }
  .manual label {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--muted);
  }
  .row { display: flex; gap: 12px; }
  .row .panel { flex: 1; }
  .lang { display: flex; gap: 6px; align-items: center; color: var(--muted); }
</style>
