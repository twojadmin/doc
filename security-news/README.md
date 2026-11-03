# Przegląd bezpieczeństwa

Strona zbiorcza „co się teraz dzieje w bezpieczeństwie”, w trzech kolumnach:

1. **Komunikaty CERT / CSIRT** – CERT Polska, CERT-EU, CERT-FR (biuletyny i alerty), BSI CERT-Bund (tylko ważność wysoka/krytyczna, maks. 10), NCSC-NL.
2. **Serwisy o bezpieczeństwie** – Sekurak, Niebezpiecznik, Zaufana Trzecia Strona, CyberDefence24
   oraz BleepingComputer, The Hacker News, SecurityWeek, The Record, Help Net Security, Krebs on Security, SANS ISC.
3. **Wyszukiwarki podatności (CVE)** – tylko linki: EUVD (ENISA), Vulnerability-Lookup (CIRCL), OpenCVE,
   CERT-FR, BSI, CERT Polska, NVD, CVE.org, CISA KEV, OSV.dev, GitHub Advisory Database.
   Wpisany numer CVE lub produkt zamienia się w linki do wyników – strona niczego z tych serwisów nie pobiera.

## Zasady wykorzystania treści
Z publicznych kanałów RSS zapisywane są **tylko tytuł i link** (plus nazwa źródła i data). Nie kopiujemy treści,
opisów ani obrazków – kliknięcie otwiera oryginał u źródła. Źródła z otwartą licencją: CERT-EU (CC BY 4.0),
CERT-FR (Licence Ouverte 2.0), SANS ISC (CC BY-NC-SA 4.0). Pozostałe udostępniają publiczne kanały RSS;
wykorzystujemy je wyłącznie do podania tytułu i odnośnika.

## Jak to działa
- `scripts/fetch_news.py` (sam Python) pobiera kanały RSS i zapisuje `news.json` (tytuł, link, źródło, data; 14 dni).
  Lista źródeł: `SOURCES` na początku pliku.
- `index.html` wczytuje `news.json`: wyszukiwanie w tytułach, okres (24 h – 14 dni), włączanie/wyłączanie źródeł,
  oznaczanie nowych pozycji od ostatniej wizyty, tryb ciemny, widok na telefon.
- Workflow `.github/workflows/security-news.yml` odświeża dane co 2 godziny i publikuje stronę na GitHub Pages.
  Każdy przebieg zapisuje też `news.json` i `przeglad-bezpieczenstwa-offline.html` na gałęzi `cve-data`.

Lokalnie:
```bash
OUTPUT=security-news/news.json python3 security-news/scripts/fetch_news.py
python3 -m http.server -d security-news 8000   # http://localhost:8000
```
