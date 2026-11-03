# doc
Dokumentacja

## Przegląd bezpieczeństwa – `index.html`

> **Obecnie strona pokazuje tylko wyszukiwarki CVE.** Przegląd newsów (kolumny 1 i 2) jest wyłączony
> stałą `NEWS_ENABLED = false` w `index.html` do czasu uruchomienia własnego pośrednika (`cors-proxy-worker.js`).
> Aby go włączyć: uruchom Workera, wpisz jego adres w `OWN_PROXY` i ustaw `NEWS_ENABLED = true`.
Strona zbiorcza „co się teraz dzieje w bezpieczeństwie”, w trzech kolumnach:

1. **Komunikaty CERT / CSIRT** – CERT Polska, CERT-EU, CERT-FR (biuletyny i alerty), BSI CERT-Bund
   (tylko ważność wysoka/krytyczna, maks. 10), NCSC-NL.
2. **Serwisy o bezpieczeństwie** – Sekurak, Niebezpiecznik, Zaufana Trzecia Strona, CyberDefence24,
   BleepingComputer, The Hacker News, SecurityWeek, The Record, Help Net Security, Krebs on Security, SANS ISC.
3. **Wyszukiwarki podatności (CVE)** – tylko linki: EUVD (ENISA), Vulnerability-Lookup (CIRCL), OpenCVE,
   CERT-FR, BSI, CERT Polska, NVD, CVE.org, CISA KEV, OSV.dev, GitHub Advisory Database.

### Jak to działa
- Strona to jeden plik `index.html` – bez serwera i bez GitHub Actions. Kanały RSS pobiera **przeglądarka**
  (JavaScript) przy otwarciu strony; wyniki są trzymane w pamięci przeglądarki 20 minut, a strona odświeża się co 30 minut.
- Tylko część serwisów pozwala przeglądarce pobrać kanał bezpośrednio (nagłówek CORS; w teście 2 z 17:
  CyberDefence24 i The Record). Pozostałe idą przez pośrednika:
  - **zalecane:** własny pośrednik na darmowym Cloudflare Workers – kod i instrukcja w `cors-proxy-worker.js`
    (przepuszcza tylko te 17 kanałów); jego adres wpisuje się w stałej `OWN_PROXY` w `index.html`,
  - zapasowo: publiczny allorigins.win – bywa zawodny i widzi adres IP odwiedzającego.
- Z kanałów brane są **tylko tytuł, link i data** – bez treści, opisów i obrazków. Kliknięcie otwiera oryginał.
- Listę źródeł zmienia się w tablicy `SOURCES` w `index.html`.

### Publikacja
GitHub → **Settings → Pages → Source: Deploy from a branch → `main` / `/ (root)`**.
Strona: https://twojadmin.github.io/doc/
