# Project status

Verified on 8 November 2026, on `main` at `0ae1e5f`, using the commands in the
"Evidence" column. All commands are offline except `network`, which reads the
IP configuration without scanning. No live scan was run for this document.

Test suite: `python -m pytest -q -m "not native"` → 307 passed, 1 skipped
(`tests/test_ui_layout.py`, Playwright not installed), 1 deselected (native test).

## Mandatory requirements

| Requirement | Status | Evidence |
|---|---|---|
| FR-01 network detection | Implemented; run on the Mac | `python -m netcheck network` → interface, IP, prefix, subnet, gateway; `tests/test_scanner.py`, `tests/test_network_platforms.py` |
| FR-02 authorized scope | Implemented | `python -m netcheck demo-refusals` → 4 refusals (public IP, venue Wi-Fi target and `/16`, missing `--confirm`), subprocess not called; `tests/test_scan_guardrails.py` (29 tests) |
| FR-03 devices | Implemented | `netcheck/parser.py` + `netcheck/scoring.py`: IP, masked MAC, vendor, hostname, estimated type; `tests/test_parser_rules.py` |
| FR-04 ports and services | Implemented; tested with simulated Nmap | `tests/test_nmap_ports.py`, `tests/test_scan_execution.py` (top 1,000 TCP + UDP 53/123/161/1900/5353, timeout, verified XML) |
| FR-05 offline analysis | Implemented | `python -m netcheck analyze tests/validation --out <dir>` → 8 files in 0.09 s total (`/usr/bin/time -p`); `V7_broken.xml` → `ERROR`, no crash |
| FR-06 rules (15 codes) | Implemented | `diff` of `findings.csv` against `tests/validation/expected_findings.csv` → identical, 24/24 rows |
| FR-07 explanations | Implemented | `netcheck/catalog.json`: 15 codes, 2 sentences each in RO and EN; `tests/test_catalog.py` (14 tests) |
| FR-08 remediation | Implemented | `netcheck/catalog.json`: 2–3 steps per code in RO and EN; attached by `/api/import` and `/api/scans/{id}` |
| FR-09 score | Implemented | `scores.csv` on the Validation Set → 90, 40, 45, 25, 50, 60, 100, ERROR; `tests/test_scoring_cli.py` |
| FR-10 history | Implemented | `netcheck/history.py` (SQLite); `compare(V6a, V6b)` → score 60 → 100, resolved findings; `tests/test_history.py`, `tests/test_api.py` |
| FR-11 user interface | Implemented; served locally | `python -m netcheck serve` → `GET /` 200 on `127.0.0.1:8000`; `tests/test_ui_api_contract.py` (22 tests) |
| FR-15 standard outputs | Implemented | `analyze` writes `findings.csv` and `scores.csv`; two runs → identical files (`cmp`) |

Findings, severities and the score are produced only by code (`parser → rules →
scoring`), without an LLM. Learning Mode (`netcheck/learn/`) only explains a
scan that has already been computed.

## Not verified live

- **Real scan on the hotspot** with `scan --confirm` or `lab-run`: not run for
  this document. Scanning a `/24` in under five minutes has not been measured.
- **Lab BEFORE/AFTER:** `lab/before/` and `lab/after/` contain no XML files in
  Git. The pair with an improving score is still missing.
- **macOS privileges** (sudoers wrapper) and **Npcap on Windows**: tested only
  with simulated processes.
- **UI in a browser:** the Playwright tests (`tests/test_ui_layout.py`) were
  skipped; accessibility (16 px, keyboard, AA contrast) is not checked
  automatically.
- **Learning Mode with a real LLM provider:** only the local fallback is
  covered by tests.
- **Network detection on Windows/Linux:** simulated tests only.
- **Secrets:** `gitleaks git` and `gitleaks dir` (8.30.1) ran locally with
  exit 0 and no findings. The CI workflow runs only on pull requests.
