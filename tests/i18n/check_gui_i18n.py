#!/usr/bin/env python3
"""GUI i18n consistency: host/gui/src/i18n/*.json + Svelte views.

Checks:
 1. all 6 locales present, valid JSON, non-empty values
 2. key sets identical across locales (en is reference)
 3. {placeholder} sets identical to en per key
 4. every t("key") used in Svelte views exists in en catalog
 5. RTL set in i18n/index.js matches {ur, ar}

Exit 0 = pass, 1 = fail.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
I18N = ROOT / "host" / "gui" / "src" / "i18n"
SRC = ROOT / "host" / "gui" / "src"
LOCALES = ["en", "es", "zh", "hi", "ur", "ar"]
FAILS = []
PASSES = []


def ok(msg):
    PASSES.append(msg)


def fail(msg):
    FAILS.append(msg)
    print("FAIL: " + msg)


def main():
    cats = {}
    for code in LOCALES:
        p = I18N / f"{code}.json"
        if not p.exists():
            fail(f"missing catalog {code}.json")
            continue
        try:
            data = json.loads(p.read_text(encoding="utf8"))
        except Exception as e:
            fail(f"{code}.json invalid JSON: {e}")
            continue
        for k, v in data.items():
            if not isinstance(v, str) or not v.strip():
                fail(f"{code}.{k} is empty or not a string")
        cats[code] = data
    if not cats:
        finish()

    # 2. key parity
    ref = sorted(cats["en"].keys()) if "en" in cats else []
    for code in LOCALES:
        if code not in cats:
            continue
        keys = sorted(cats[code].keys())
        missing = set(ref) - set(keys)
        extra = set(keys) - set(ref)
        if missing or extra:
            fail(f"{code} key set diverges: missing={sorted(missing)} extra={sorted(extra)}")
        else:
            ok(f"{code} has all {len(ref)} keys")

    # 3. placeholder parity
    ph = re.compile(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}")
    for code in LOCALES:
        if code not in cats or "en" not in cats:
            continue
        for k in cats["en"]:
            if k not in cats[code]:
                continue
            a = set(ph.findall(cats["en"][k]))
            b = set(ph.findall(cats[code][k]))
            if a != b:
                fail(f"placeholder mismatch {code}.{k}: en={sorted(a)} {code}={sorted(b)}")
    if not FAILS:
        ok("placeholders consistent across locales")

    # 4. t() usage in views resolves
    used = set()
    for svelte in SRC.rglob("*.svelte"):
        text = svelte.read_text(encoding="utf8")
        used |= set(re.findall(r'\bt\("([a-z0-9_]+)"', text))
    if "en" in cats:
        unknown = used - set(cats["en"].keys())
        if unknown:
            fail(f"views reference unknown i18n keys: {sorted(unknown)}")
        else:
            ok(f"all {len(used)} t() keys in views exist in en catalog")
    unused = set(cats.get("en", {})) - used
    if unused:
        print(f"NOTE: {len(unused)} catalog keys unused by views (allowed): {sorted(unused)[:8]}…")

    # 5. RTL set
    idx = (I18N / "index.js").read_text(encoding="utf8")
    m = re.search(r'new Set\(\[([^\]]*)\]\)', idx)
    rtl = set(re.findall(r'"([a-z]{2})"', m.group(1))) if m else set()
    if rtl == {"ur", "ar"}:
        ok("RTL set = {ur, ar}")
    else:
        fail(f"RTL set mismatch: {sorted(rtl)}")

    finish()


def finish():
    print(f"\nGUI i18n: {len(PASSES)} pass, {len(FAILS)} fail")
    sys.exit(1 if FAILS else 0)


if __name__ == "__main__":
    main()
