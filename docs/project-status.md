# Starea proiectului

Verificat la 8 noiembrie 2026, pe `main` la `0ae1e5f`, cu comenzile din coloana
„Dovadă”. Toate comenzile sunt offline, cu excepția `network`, care citește
configurația IP fără să scaneze. Nicio scanare live nu a fost rulată pentru
acest document.

Suita: `python -m pytest -q -m "not native"` → 307 passed, 1 skipped
(`tests/test_ui_layout.py`, Playwright lipsește), 1 deselected (testul nativ).

## Cerințe obligatorii

| Cerința | Starea | Dovadă |
|---|---|---|
| FR-01 detectarea rețelei | Implementată; rulată pe Mac | `python -m netcheck network` → interfață, IP, prefix, subnet, gateway; `tests/test_scanner.py`, `tests/test_network_platforms.py` |
| FR-02 domeniu autorizat | Implementată | `python -m netcheck demo-refusals` → 4 refuzuri (IP public, țintă și `/16` Wi-Fi locație, fără `--confirm`), subprocess neapelat; `tests/test_scan_guardrails.py` (29 teste) |
| FR-03 dispozitive | Implementată | `netcheck/parser.py` + `netcheck/scoring.py`: IP, MAC mascat, vendor, hostname, tip estimat; `tests/test_parser_rules.py` |
| FR-04 porturi și servicii | Implementată; testată cu Nmap simulat | `tests/test_nmap_ports.py`, `tests/test_scan_execution.py` (top 1.000 TCP + UDP 53/123/161/1900/5353, timeout, XML verificat) |
| FR-05 analiză offline | Implementată | `python -m netcheck analyze tests/validation --out <dir>` → 8 fișiere în 0,09 s total (`/usr/bin/time -p`); `V7_broken.xml` → `ERROR`, fără excepție |
| FR-06 reguli (15 coduri) | Implementată | `diff` între `findings.csv` și `tests/validation/expected_findings.csv` → identic, 24/24 rânduri |
| FR-07 explicații | Implementată | `netcheck/catalog.json`: 15 coduri, câte 2 propoziții RO și EN; `tests/test_catalog.py` (14 teste) |
| FR-08 remedieri | Implementată | `netcheck/catalog.json`: 2–3 pași RO și EN per cod; atașate de `/api/import` și `/api/scans/{id}` |
| FR-09 scor | Implementată | `scores.csv` pe Validation Set → 90, 40, 45, 25, 50, 60, 100, ERROR; `tests/test_scoring_cli.py` |
| FR-10 istoric | Implementată | `netcheck/history.py` (SQLite); `compare(V6a, V6b)` → scor 60 → 100, findings rezolvate; `tests/test_history.py`, `tests/test_api.py` |
| FR-11 interfață | Implementată; servită local | `python -m netcheck serve` → `GET /` 200 pe `127.0.0.1:8000`; `tests/test_ui_api_contract.py` (22 teste) |
| FR-15 rezultate standard | Implementată | `analyze` scrie `findings.csv` și `scores.csv`; două rulări → fișiere identice (`cmp`) |

Findings, severitățile și scorul sunt produse doar de cod (`parser → rules →
scoring`), fără LLM. Learning Mode (`netcheck/learn/`) doar explică o scanare
deja calculată.

## Neverificat live

- **Scanarea reală pe hotspot** cu `scan --confirm` sau `lab-run`: nu am rulat-o
  pentru acest document. Durata unui `/24` sub cinci minute nu e măsurată.
- **BEFORE/AFTER din laborator:** `lab/before/` și `lab/after/` nu au XML-uri
  incluse în Git. Lipsește perechea cu scor în creștere.
- **Privilegiile macOS** (wrapper sudoers) și **Npcap pe Windows**: testate
  doar cu procese simulate.
- **Interfața în browser:** testele Playwright (`tests/test_ui_layout.py`) au
  fost sărite; accesibilitatea (16 px, tastatură, contrast AA) nu e verificată
  automat.
- **Learning Mode cu furnizor LLM real:** doar varianta locală de rezervă e
  acoperită de teste.
- **Detectarea rețelei pe Windows/Linux:** doar teste simulate.
- **Secrete:** `gitleaks git` și `gitleaks dir` (8.30.1) au rulat local cu
  exit 0, fără constatări. Workflow-ul CI pornește doar la pull request.
