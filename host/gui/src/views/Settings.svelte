<script>
  import { lang, setLanguage, t, LANGUAGES } from "../i18n";
  import { settings } from "../store";
  import { IS_SIM } from "../api";
</script>

<div class="view-head">
  <h1>{t("nav_settings")}</h1>
</div>

<div class="grid-2">
  <section class="card">
    <h2>{t("language")}</h2>
    <p class="desc">6</p>
    <div class="row">
      {#each LANGUAGES as [code, label]}
        <button class="btn {$lang === code ? 'primary' : 'ghost'}"
                on:click={() => setLanguage(code)}>
          {label}
        </button>
      {/each}
    </div>
  </section>

  <section class="card">
    <h2>{t("port")}</h2>
    <p class="desc">ADB / LAN</p>
    <div class="field" style="max-width:180px">
      <label for="f-port">{t("port")}</label>
      <input id="f-port" type="number" bind:value={$settings.port} />
    </div>
  </section>
</div>

<section class="card" style="margin-top:14px">
  <h2>{t("about_title")}</h2>
  <p class="desc" style="margin-bottom:0">{t("about_text")}</p>
  <div class="row" style="margin-top:10px">
    <span class="pill">{t("version")} 0.2.0-dev</span>
    <span class="pill {IS_SIM ? '' : 'ok'}">{IS_SIM ? t("sim_badge") : "Tauri"}</span>
  </div>
</section>
