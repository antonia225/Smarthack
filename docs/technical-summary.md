# NetCheck — technical summary

## Lab

A macOS scanner laptop on the team's iPhone hotspot (`172.20.10.0/28` when last
checked); targets are the team's laptops and `lab/services/`. Addresses are
re-checked each session (`netcheck network`, no traffic) and recorded in
[`lab/session-template.md`](../lab/session-template.md).

## Architecture

Nmap XML → `parser.py` (defusedxml, 10 MB limit) → `rules.py` (fixed rules) →
`scoring.py` (100 − points; high 20, medium 10, low 5, info 0; floor 0) →
`catalog.json` (RO/EN explanation and fix steps). Findings, severities and score
come only from this code: deterministic, no LLM; the optional model only phrases
answers about an already computed scan. History: SQLite (`netcheck.db`).
FastAPI on `127.0.0.1` with `TrustedHostMiddleware` serves the UI. CLI `scan` and
`POST /api/scan` share one guardrail path (`service.scan()` →
`validate_scan_request()`): RFC1918 IPv4 only, at most `/24`, inside the
allowlist and the detected LAN, explicit confirmation; only then the fixed Nmap
command runs.

## Assumptions

A matching IP/interface/gateway means "our hotspot" (not owner authentication).
Without `lab/network.json` the allowlist is the connected subnet if ≤ `/24`;
larger networks (venue Wi-Fi) are refused.

## Limitations

- Live scan via the macOS sudo wrapper: not verified end to end; `/24` in 5 min: not measured.
- macOS: on the 300 s timeout only `sudo` is killed; the root `nmap` keeps
  running (seen once for 53 min) → `pgrep -l nmap`, `sudo kill <pid>`. Scan single IPs.
- `lab-run` writes to `lab/<label>/`, which the macOS wrapper rejects (from code, not run);
  use `scan <ip> --confirm` and copy the XML unchanged to `lab/before|after`.
- Windows/Linux network detection: simulated tests only. Live LLM: not verified.

## LLM use

Optional OpenAI-compatible provider, only if `NETCHECK_LLM_API_KEY` and
`NETCHECK_LLM_MODEL` are set. Sent: score, labels ("Device 1"), device type, IPs,
`protocol/port service`, finding codes, severities, corpus passages, the question
verbatim. Not sent: MAC, vendor, hostname, product/version, banners, HTTP titles.
Scan requests only become proposals needing manual confirmation. Any failure
falls back to the local catalogue and corpus. Pseudonymisation is not
anonymisation. See [`learning-mode.md`](learning-mode.md).

## Measured

On `0294d40` (PR #22 restore-official-rules, not yet merged):
- Validation Set: 24/24 findings, scores 90, 40, 45, 25, 50, 60, 100, ERROR,
  byte-identical to the official CSVs; repeat run identical (`cmp`).
- `analyze`, 8 files: 0.07–0.18 s wall time per run (4 runs, `/usr/bin/time -p`).
- `pytest -q -m "not native"`: 331 passed, 1 skipped (no Playwright), 1 deselected.

<!-- update after restore-official-rules (PR #22) is merged: replace commit labels with the merge commit -->
On `767b3c4` (`main` before PR #22) `UNKNOWN_DEVICE` is info/0, so V4 = 30, not 25.
BEFORE/AFTER lab results: pending (no live capture produced yet).
