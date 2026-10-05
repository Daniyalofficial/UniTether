<script>
  import { onMount } from "svelte";
  import { t } from "../i18n";
  import QRCode from "qrcode";

  export let pairBlob = "";
  export let error = "";

  let qrDataUrl = "";

  async function renderQr() {
    if (!pairBlob.trim()) {
      qrDataUrl = "";
      return;
    }
    qrDataUrl = await QRCode.toDataURL(pairBlob, {
      width: 220,
      margin: 2,
      color: { dark: "#000000", light: "#ffffff" },
    });
  }
  $: renderQr();

  onMount(async () => {
    try {
      const { invoke } = await import("@tauri-apps/api/core");
      pairBlob = await invoke("get_pairing");
    } catch {
      // browser preview mode
    }
  });
</script>

<section class="panel">
  <h2>{t("pairing")}</h2>
  <p class="muted">{t("pairing_help")}</p>
  <div class="row">
    {#if qrDataUrl}
      <img src={qrDataUrl} alt="QR" width="220" height="220" />
    {/if}
    <div class="fields">
      <label>
        {t("paste")}
        <textarea rows="3" bind:value={pairBlob} placeholder="UNITETHER1:…"></textarea>
      </label>
      {#if error}
        <p class="error">{error}</p>
      {/if}
    </div>
  </div>
</section>

<style>
  .row { display: flex; gap: 16px; flex-wrap: wrap; }
  .fields { flex: 1; min-width: 260px; display: flex; flex-direction: column; gap: 8px; }
  label { display: flex; flex-direction: column; gap: 4px; color: var(--muted); }
  textarea {
    background: var(--panel-2);
    color: var(--text);
    border: 1px solid #2a3a31;
    border-radius: 6px;
    padding: 8px;
    font-family: monospace;
  }
  .muted { color: var(--muted); }
  .error { color: var(--danger); font-size: 12px; }
  img { border-radius: 8px; }
  h2 { margin: 0 0 6px; font-size: 15px; color: var(--accent); }
</style>
