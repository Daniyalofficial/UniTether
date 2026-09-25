import { writable, derived, get } from "svelte/store";

import en from "./en.json";
import ur from "./ur.json";
import ar from "./ar.json";
import es from "./es.json";
import zh from "./zh.json";
import hi from "./hi.json";

const CATALOGS = { en, ur, ar, es, zh, hi };
const RTL = new Set(["ur", "ar"]);

const lang = writable(localStorage.getItem("unitether.lang") || "en");
const catalog = derived(lang, (l) => CATALOGS[l] || en);

export function t(key, vars) {
  const cat = get(catalog);
  let s = cat[key] ?? en[key] ?? key;
  if (vars) {
    for (const [k, v] of Object.entries(vars)) s = s.replace(`{${k}}`, v);
  }
  return s;
}

export function setLanguage(l) {
  if (!CATALOGS[l]) return;
  lang.set(l);
  localStorage.setItem("unitether.lang", l);
  document.documentElement.dir = RTL.has(l) ? "rtl" : "ltr";
  document.documentElement.lang = l;
}

lang.subscribe((l) => {
  document.documentElement.dir = RTL.has(l) ? "rtl" : "ltr";
  document.documentElement.lang = l;
});

export { lang, catalog };
export const LANGUAGES = [
  ["en", "English"],
  ["ur", "اردو"],
  ["ar", "العربية"],
  ["es", "Español"],
  ["zh", "中文"],
  ["hi", "हिन्दी"],
];
