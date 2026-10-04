<script>
  import { onMount } from "svelte";
  import Dashboard from "./views/Dashboard.svelte";
  import Devices from "./views/Devices.svelte";
  import Pairing from "./views/Pairing.svelte";
  import Settings from "./views/Settings.svelte";
  import { lang, setLanguage, t, LANGUAGES } from "./i18n";
  import { connection, scan } from "./store";
  import { IS_SIM } from "./api";

  let view = "dashboard";

  const dotClass =
    $connection.state === "connected" ? "ok" :
    $connection.state === "connecting" ? "busy" : "";

  function goto(v) {
    view = v;
    if (v === "devices") scan();
  }

  onMount(() => {
    scan();
  });
</script>

<div class="shell">
  <aside class="sidebar">
    <div class="brand">
      <div class="logo">U</div>
      <div>
        <div class="name">{t("title")}</div>
        <div class="sub">{t("tagline")}</div>
      </div>
    </div>

    <button class="nav-item {view === 'dashboard' ? 'active' : ''}" on:click={() => goto("dashboard")}>
      <span class="ico">⌂</span> {t("nav_dashboard")}
    </button>
    <button class="nav-item {view === 'devices' ? 'active' : ''}" on:click={() => goto("devices")}>
      <span class="ico">▤</span> {t("nav_devices")}
    </button>
    <button class="nav-item {view === 'pairing' ? 'active' : ''}" on:click={() => goto("pairing")}>
      <span class="ico"></span> {t("nav_pairing")}
    </button>
    <button class="nav-item {view === 'settings' ? 'active' : ''}" on:click={() => goto("settings")}>
      <span class="ico">⚙</span> {t("nav_settings")}
    </button>

    <div class="spacer"></div>

    <label class="lang-field">
      <span>{t("language")}</span>
      <select bind:value={$lang} on:change={() => setLanguage($lang)}>
        {#each LANGUAGES as [code, label]}
          <option value={code}>{label}</option>
        {/each}
      </select>
    </label>

    <div class="status-chip">
      <span class="dot {dotClass}"></span>
      {#if $connection.state === "connected"}{t("status_connected")}
      {:else if $connection.state === "connecting"}{t("status_connecting")}
      {:else}{t("status_idle")}
      {/if}
    </div>
  </aside>

  <main class="main">
    <div class="main-inner">
      {#if IS_SIM}
        <div class="sim-note" role="note">
          <strong>{t("sim_badge")}:</strong> {t("sim_notice")}
        </div>
      {/if}

      {#if view === "dashboard"}
        <Dashboard />
      {:else if view === "devices"}
        <Devices goto={goto} />
      {:else if view === "pairing"}
        <Pairing goto={goto} />
      {:else}
        <Settings />
      {/if}
    </div>
  </main>
</div>

<style>
  .lang-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 0 10px 10px;
    font-size: 11.5px;
    color: var(--muted);
  }
  .lang-field select {
    background: var(--card);
    color: var(--text);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 5px 6px;
    font-size: 12.5px;
    font-family: inherit;
  }
</style>
