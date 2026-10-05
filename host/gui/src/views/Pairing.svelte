<script>
  import { onMount } from "svelte";
  import QRCode from "qrcode";
  import { pairing, loadPairing, connection, connect } from "../store";
  import { t } from "../i18n";

  export let goto;

  let blob = "";
  let qrDataUrl = "";
  let error = "";
  let copied = false;

  onMount(() => refresh());

  async function refresh() {
    await loadPairing();
    const p = $pairing.blob;
    if (p) {
      try {
        qrDataUrl = await QRCode.toDataURL(p, {
          width: 220,
          margin: 1,
          color: { dark: "#0d1117", light: "#ffffff" },
        });
      } catch {
        qrDataUrl = "";
      }
    }
  }

  async function copyBlob() {
    try {
      await navigator.clipboard.writeText($pairing.blob);
      copied = true;
      setTimeout(() => (copied = false), 2000);
    } catch {
      /* clipboard unavailable */
    }
  }

  async function connectWithBlob() {
    error = "";
    const ok = await connect("", 41880, $pairing.blob || null);
    if (!ok) error = $connection.detail;
    else goto("dashboard");
  }
</script>

<div class="view-head">
  <h1>{t("nav_pairing")}</h1>
  <button class="btn ghost" on:click={refresh}>{t("scan_again")}</button>
</div>

<p class="muted" style="margin-top:0">{t("pairing_help")}</p>

<div class="grid-2">
  <section class="card">
    <h2>{t("scan_qr")}</h2>
    <p class="desc">{t("pairing_help")}</p>
    {#if $pairing.loading}
      <p class="muted">{t("searching")}</p>
    {:else if qrDataUrl}
      <div class="qr-wrap">
        <img src={qrDataUrl} alt="pairing QR" width="220" height="220" />
      </div>
    {:else}
      <p class="muted">{t("no_devices")}</p>
    {/if}
  </section>

  <section class="card">
    <h2>{t("paste")}</h2>
    <p class="desc">UNITETHER1:…</p>
    <div class="blob-box">{#if $pairing.blob}{$pairing.blob}{:else}—{/if}</div>
    <div class="row" style="margin-top:10px">
      <button class="btn ghost" disabled={!$pairing.blob} on:click={copyBlob}>
        {copied ? t("copied") : t("copy")}
      </button>
      <button class="btn primary" disabled={!$pairing.blob || $connection.state === "connecting"}
              on:click={connectWithBlob}>
        {t("connect")}
      </button>
    </div>
    {#if error}<p class="error-text" style="margin-top:8px">{t("error_label")}: {error}</p>{/if}
  </section>
</div>
