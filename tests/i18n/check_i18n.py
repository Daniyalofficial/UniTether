#!/usr/bin/env python3
"""i18n automated consistency checks (Phase 66).

Checks (all mechanical, no network):
  1. XML well-formedness of every res/values*/strings.xml
  2. key parity: every locale has EXACTLY the default key set
     (missing keys / extra keys reported)
  3. placeholder parity: per key, the ordered format-specifier
     sequence (%s, %d, %f, positional %N$s / %N$d / %N) must match
     the default string — Android throws at runtime otherwise
  4. plurals: per <plurals> key, the quantity-category set must
     match the default; 'other' required in every locale
  5. naming: resource keys ^[a-z][a-z0-9_]*$
  6. RTL: layouts/menus must use Start/End (never Left/Right)
     directional attributes; RTL locales (ar, ur) are flagged if
     a layout uses physical left/right attributes
  7. hardcoded UI strings: Kotlin must not setText/Toast/setTitle
     with raw string literals (must reference @string)

Exit 0 = all pass.
"""
import os
import re
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RES = os.path.join(ROOT, "device", "app", "src", "main", "res")
JAVA = os.path.join(ROOT, "device", "app", "src", "main", "java")

RTL_LOCALES = {"ar", "ur", "fa", "he"}
NAME_RE = re.compile(r"^[a-z][a-z0-9_]*$")
PLACEHOLDER_RE = re.compile(r"%(\d+\$)?[sdf]")
LEFT_RIGHT_RE = re.compile(
    r"(padding|layout_margin|layout_)(Left|Right)=\"")

PASS = []
FAIL = []


def check(name, ok, detail=""):
    (PASS if ok else FAIL).append((name, detail))


def parse(path):
    """Return ({string: text}, {plural: {cat: text}}, errors)."""
    strings, plurals, errors = {}, {}, []
    try:
        tree = ET.parse(path)
    except ET.ParseError as e:
        return strings, plurals, [f"XML parse error: {e}"]
    root = tree.getroot()
    for el in root:
        if el.tag == "string":
            name = el.get("name", "")
            strings[name] = (el.text or "")
            if not NAME_RE.match(name):
                errors.append(f"bad key name: {name!r}")
        elif el.tag == "plurals":
            name = el.get("name", "")
            cats = {}
            for item in el:
                if item.tag in ("item",):
                    cats[item.get("quantity", "")] = (item.text or "")
            plurals[name] = cats
            if not NAME_RE.match(name):
                errors.append(f"bad plural name: {name!r}")
            if "other" not in cats:
                errors.append(f"plural {name!r} missing 'other'")
    return strings, plurals, errors


def placeholders(text):
    return [m.group(0) for m in PLACEHOLDER_RE.finditer(text)]


def main():
    locale_files = {}
    for d in sorted(os.listdir(RES)):
        p = os.path.join(RES, d, "strings.xml")
        if os.path.isfile(p) and re.match(r"^values(-\w+(-\w+)?)?$", d):
            locale_files[d] = p
    if "values" not in locale_files:
        print("i18n: FAIL no default values/strings.xml")
        return 1

    data = {}
    for loc, path in locale_files.items():
        s, pl, errs = parse(path)
        data[loc] = (s, pl)
        check(f"xml:{loc}", not errs, "; ".join(errs))

    default_strings, default_plurals = data["values"]

    # ---- 2/3: key + placeholder parity
    for loc in sorted(k for k in data if k != "values"):
        strings, _ = data[loc]
        missing = set(default_strings) - set(strings)
        extra = set(strings) - set(default_strings)
        check(f"keys:{loc}", not missing and not extra,
              f"missing={sorted(missing)} extra={sorted(extra)}")
        for key in sorted(set(default_strings) & set(strings)):
            pd = placeholders(default_strings[key])
            pt = placeholders(strings[key])
            check(f"ph:{loc}:{key}", pd == pt,
                  f"default={pd} locale={pt}")

    # ---- 4: plurals
    for loc in sorted(k for k in data if k != "values"):
        _, plurals = data[loc]
        missing = set(default_plurals) - set(plurals)
        extra = set(plurals) - set(default_plurals)
        check(f"plurals:{loc}", not missing and not extra,
              f"missing={sorted(missing)} extra={sorted(extra)}")
        for key in sorted(set(default_plurals) & set(plurals)):
            cats_d = set(default_plurals[key])
            cats_l = set(plurals[key])
            check(f"plural-cats:{loc}:{key}", cats_d == cats_l,
                  f"default={sorted(cats_d)} locale={sorted(cats_l)}")

    # ---- 6: RTL-safe layouts
    bad_attrs = []
    for sub in ("layout", "layout-land", "menu", "xml"):
        d = os.path.join(RES, sub)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.endswith(".xml"):
                continue
            with open(os.path.join(d, fn), encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    m = LEFT_RIGHT_RE.search(line)
                    if m:
                        bad_attrs.append(f"{sub}/{fn}:{i} {m.group(0).rstrip(chr(34))}")
    check("rtl:layouts use Start/End", not bad_attrs, "; ".join(bad_attrs[:5]))
    # RTL locales present for at least ar + ur (product markets)
    have = {k.split("-", 1)[1].split("-")[0] if k != "values" else "default"
            for k in data}
    check("rtl:ar+ur locales present",
          {"ar", "ur"}.issubset(have), f"locales={sorted(have)}")

    # ---- 7: hardcoded UI strings in Kotlin
    hardcoded = []
    for dirpath, _dirs, files in os.walk(JAVA):
        for fn in sorted(files):
            if not fn.endswith(".kt"):
                continue
            path = os.path.join(dirpath, fn)
            with open(path, encoding="utf-8") as f:
                src = f.read()
            for m in re.finditer(
                    r'(setText|setTitle|setHint|Toast\.makeText\([^,]+,[^,]+,)'
                    r'\s*"([^"\\]{3,})"', src):
                lit = m.group(2)
                if re.fullmatch(r"[0-9a-fA-Fx .::%\-+]+", lit):
                    continue  # numeric/hex formatting, not UI copy
                rel = os.path.relpath(path, ROOT)
                hardcoded.append(f"{rel}: {m.group(1)}(\"{lit[:40]}\")")
    check("kotlin:no hardcoded UI strings", not hardcoded,
          "; ".join(hardcoded[:5]))

    print(f"i18n: {len(PASS)} pass, {len(FAIL)} fail "
          f"({len(data)} locales, {len(default_strings)} strings, "
          f"{len(default_plurals)} plurals)")
    for name, d in FAIL:
        print(f"  FAIL {name} {d}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
