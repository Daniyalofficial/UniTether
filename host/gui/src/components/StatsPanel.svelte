<script>
  import { onMount } from "svelte";
  import { t } from "../i18n";

  export let connected = false;

  let stats = { uptime_s: 0, bytes_in: 0, bytes_out: 0, rtt_ms: 0, loss_x100: 0, fps: 0 };
  let timer = null;

  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 / 1024).toFixed(1)} MB`;
    return `${(n / 1024 ** 3).toFixed(2)} GB`;
  }

  onMount(async () => {
    if (!connected) return;
    const { invoke } = await import("@tauri-apps/api/core");
    const pull = async () => {
      try { stats = await invoke("get_stats"); } catch { /* noop */ }
    };
    await pull();
    timer = setInterval(pull, 2000);
    return () => clearInterval(timer);
  });
</script>

<section class="panel">
  <h2>{t("stats")}</h2>
  {#if !connected}
    <p class="muted">{t("disconnected")}</p>
  {:else}
    <div class="grid">
      <div><span class="k">{t("uptime")}</span><span>{stats.uptime_s} {t("seconds")}</span></div>
      <div><span class="k">{t("bytes_in")}</span><span>{fmtBytes(stats.bytes_in)}</span></div>
      <div><span class="k">{t("bytes_out")}</span><span>{fmtBytes(stats.bytes_out)}</span></div>
      <div><span class="k">{t("rtt")}</span><span>{stats.rtt_ms} {t("ms")}</span></div>
      <div><span class="k">{t("loss")}</span><span>{(stats.loss_x100 / 100).toFixed(1)}%</span></div>
      <div><span class="k">{t("fps")}</span><span>{stats.fps} fps</span></div>
    </div>
  {/if}
</section>

<style>
  .grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
  }
  .grid div {
    background: var(--panel-2);
    border-radius: 8px;
    padding: 8px 10px;
    display: flex;
    flex-direction: column;
  }
  .k { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.04em; }
  .muted { color: var(--muted); }
  h2 { margin: 0 0 10px; font-size: 15px; color: var(--accent); }
</style>
