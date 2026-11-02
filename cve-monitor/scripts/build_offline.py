#!/usr/bin/env python3
"""Tworzy jeden samodzielny plik HTML (strona + wbudowane dane), który działa bez serwera.

Użycie: python3 build_offline.py index.html news.json wynik.html
"""
import json
import sys

page, data_path, out = sys.argv[1:4]
html = open(page, encoding="utf-8").read()
data = json.load(open(data_path, encoding="utf-8"))
blob = json.dumps(data, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
marker = "<script>\n(() => {"
assert marker in html, "nie znaleziono miejsca na dane"
html = html.replace(marker, "<script>window.NEWS_DATA=" + blob + ";</script>\n" + marker, 1)
open(out, "w", encoding="utf-8").write(html)
print(f"Zapisano {out} ({len(html) / 1e6:.2f} MB, {len(data.get('items', []))} pozycji)")
