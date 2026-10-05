<script>
  import { createEventDispatcher } from "svelte";
  import { t } from "../i18n";

  export let device = {};
  export let connected = false;

  const dispatch = createEventDispatcher();
</script>

<div class="card">
  <div class="top">
    <strong>{device.name}</strong>
    <span class="badge {device.transport === 'adb' ? 'adb' : 'lan'}">
      {device.transport === 'adb' ? t("adb") : t("lan")}
    </span>
  </div>
  <div class="meta">
    <span>{device.address}:{device.port}</span>
    {#if device.rtt_ms != null}
      <span class="muted">{device.rtt_ms} {t("ms")}</span>
    {/if}
  </div>
  <div class="actions">
    {#if connected}
      <button on:click={() => dispatch("disconnect")}>{t("disconnect")}</button>
    {:else}
      <button on:click={() => dispatch("connect")}>{t("connect")}</button>
    {/if}
  </div>
</div>

<style>
  .card {
    background: var(--panel-2);
    border-radius: 8px;
    padding: 10px 12px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  .top { display: flex; justify-content: space-between; align-items: center; }
  .badge {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 10px;
    background: #274438;
    color: var(--accent);
  }
  .badge.adb { background: #443027; color: var(--warn); }
  .meta { display: flex; justify-content: space-between; color: var(--muted); font-size: 12px; }
  .muted { color: var(--muted); }
  .actions button { width: 100%; }
</style>
