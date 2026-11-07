# Smarthack / NetCheck

Prototype for the **Secure Networks, Simply Explained** challenge: scanning
an authorized network, explaining security risks, and verifying remediation.

The project currently includes network detection, lab authorization, the
scanner, offline Nmap XML analysis, findings, scoring, SQLite history, local
CLI/API access, and a web interface. See the [project status](docs/project-status.md)
for requirements and remaining work.

## Installation

Python 3.10+ is required. From the repository root, run:

```sh
python scripts/setup.py
```

On macOS, use `python3 scripts/setup.py` if only `python3` is available. In
Windows PowerShell, use `py -3 scripts/setup.py`. The script creates `.venv`,
installs `requirements-dev.txt`, and reports whether Nmap is missing.

`requirements-dev.txt` contains the application and test dependencies. Nmap
must be installed separately, including its `nmap-services` database; it is
not required for network detection alone. For the lab Docker/HTTP services,
follow the [service instructions](lab/services/README.md).

The commands below use `python` from the activated virtual environment
(`source .venv/bin/activate` on macOS/Linux). On Windows, replace `python`
with `.\.venv\Scripts\python.exe` without activating the environment.

## Network Detection and Authorization

Connect the scanner only to the team lab, then run:

```sh
python -m netcheck network
python -m netcheck configure-lab --allow 172.20.10.0/28 --confirm
```

`--allow` is optional. Without it, the CLI proposes the detected subnet but
still requires explicit `--confirm`:

```sh
python -m netcheck configure-lab
# Detected subnet proposal: 172.20.10.0/28
python -m netcheck configure-lab --confirm
```

Verify the proposal and confirm that you have permission to scan before
proceeding. Detecting an IP address does not prove network ownership.
`configure-lab` stores the allowlist and network configuration in
`lab/network.json`, which is excluded from Git, and refuses to overwrite an
existing configuration. To create a new configuration, deliberately remove
the old file and authorize the lab again. The global `--config PATH` option
must appear before the subcommand.

Scanning accepts only private RFC1918 IPv4/CIDR targets with at most 256
addresses, fully contained in the allowlist and authorized LAN. Public IPs,
targets outside the allowlist, and subnets larger than `/24` are rejected;
confirmation is mandatory. A network configuration change, including a DHCP
change to the scanner IP, causes the request to be rejected. CLI and API use
the same service function.

To demonstrate authorization refusals without Nmap:

```sh
python -m netcheck demo-refusals
```

The command demonstrates rejection of a public IP, a venue Wi-Fi target
(`10.240.0.5` and `10.240.0.0/16`), and a missing `--confirm`, then verifies
that `subprocess` was never called.

## Live Scanning and Local API

```sh
python -m netcheck scan --confirm
python -m netcheck scan 172.20.10.3 --confirm
python -m netcheck serve
```

Without a target, `scan --confirm` uses the authorized subnet from
`lab/network.json`; no subnet is hardcoded. Both forms use the same RFC1918,
allowlist, current-LAN, and confirmation validation.

Live execution uses TCP SYN and UDP scanning. On macOS, only the Nmap process
is elevated through a root-owned wrapper with strictly validated arguments.
`NOPASSWD` for the complete Nmap binary is not allowed because `--script` can
execute code as root. Install the mechanism manually with an administrator
account:

```sh
sudo sh scripts/macos/install-nmap-privileges.sh
visudo -c
python -m netcheck scan 172.20.10.3 --confirm
sudo sh scripts/macos/uninstall-nmap-privileges.sh
```

Installation creates `/var/tmp/netcheck-scans`; the wrapper accepts only
IPv4/CIDR targets and UUID XML files in that directory. Do not run the CLI,
analyzer, or web server with `sudo`; `sudo -n` is used only for the wrapper.
The macOS live configuration is implemented but **not live-verified** until
the manual steps are completed.

According to the official Nmap documentation, Windows does not require
Administrator when Npcap is loaded. Install Nmap with Npcap from the
[Nmap documentation](https://nmap.org/book/inst-windows.html) and verify on
the Windows laptop:

```text
nmap -n -sS -sU -p 53 172.20.10.2
```

If Nmap reports missing Npcap or privileges, the application returns a clear
Romanian/English message and HTTP 502 or CLI exit code 1. Npcap options still
require manual verification on the Windows laptop.

The scanner selects at least the top 1,000 TCP ports from the local
`nmap-services` database, including ties at the 1,000th frequency, plus
exactly UDP ports 53, 123, 161, 1900, and 5353. It uses service/version
detection, `http-title`, `-n`, and `--max-rate 100`. Scripts have a 30-second
timeout and the process has a 300-second timeout. The result is checked as
complete Nmap XML with secure parsing and a 10 MB limit. A timeout is a
failure, **not proof that scanning a `/24` in under five minutes was achieved**.

`scan` returns JSON and writes XML to a unique file in `scans/` on Windows or
`/var/tmp/netcheck-scans` on macOS, or to `--output-dir PATH` for unprivileged
or test runs. Raw XML may contain device data; the folder is local and
excluded from Git. The `scan` command reports Nmap execution; the API and
`analyze` command can then parse the XML and calculate findings and scores.

Only one scan may run at a time through the service in the same checkout,
including across CLI/API processes. The lock uses `.netcheck-scan.lock`,
which is excluded from Git. The file may remain after shutdown, but the lock
is released by the operating system. Do not delete it during execution.

`serve` listens only on `127.0.0.1:8000`. The API is intended for local use,
not network exposure. Interactive API documentation is available at `/docs`.
It does not replace the user interface required by the hackathon.

### Laboratory

For starting services and collecting BEFORE/AFTER captures, follow the
[laboratory instructions](lab/README.md) and
[laboratory services](lab/services/README.md). `LAB_BIND_IP` and
`LAB_DB_PASSWORD` are used only by `lab/services`; they are not settings read
by the NetCheck application and must not contain real values in the repository.

### Shutdown

Stop `serve` or a CLI scan with `Ctrl+C`. For laboratory services, follow the
shutdown section in [lab/services/README.md](lab/services/README.md).
Do not delete BEFORE/AFTER XML files; they are experiment results.

### File Analysis

Offline analysis does not start Nmap and works only with existing XML files:

```sh
python -m netcheck analyze tests/validation --out output
```

For each XML file, the application parses devices and ports, applies the
rules, calculates the score, and writes:

- `output/findings.csv` — file, IP, port, finding code, and severity;
- `output/scores.csv` — file and network score, or `ERROR` for invalid XML.

The internal result also includes devices, masked MAC addresses, estimated
device types, and the highest-risk finding.

### History and Web Interface

Imported analyses and successful live scans can be saved locally in
`netcheck.db`. The API provides scan listing, scan retrieval, comparison of
two scans, and history deletion. The local server also serves the web
interface from `netcheck/web/`, which displays the score, devices, findings,
remediation steps, and history.

### Learning Mode

Learning Mode answers questions about a saved scan from the local catalog and
the allowlisted corpus in `knowledge/sources.json`. It pseudonymizes devices
before an optional provider request and always falls back to local
documentation when no `NETCHECK_LLM_API_KEY` and `NETCHECK_LLM_MODEL` are
configured. Build the corpus with `python3 scripts/build_knowledge.py` when
internet access is available; the command uses only the Python standard
library. The [Phase 2a corpus](knowledge/README.md) contains 34 downloaded documents and
642 attributed passages, revision metadata and a deterministic bilingual BM25
index. Rebuild locally with `python scripts/build_knowledge.py --offline`.
The chat endpoint is `POST /api/ask`; architecture and limitations
are documented in [`docs/learning-mode.md`](docs/learning-mode.md).

The server reads process environment variables; it does not automatically load
`.env`. See [`.env.example`](.env.example). Both key and model enable external
requests, including the free-text question, IPs, services and pseudonymized
scan evidence. A missing downloaded corpus does not disable the provider.

The [verification record and exact demonstration steps](docs/learning-mode.md#verificare--8-noiembrie-2026)
distinguish offline tests, a successful 34-document corpus build, pending
browser checks and a live LLM call. Full RO/EN coverage and AA compliance are not yet demonstrated.

### IT provider report

`GET /api/report?a=<id>` returns a self-contained printable HTML report.
`GET /api/report?a=<before>&b=<after>` also includes the score change and
findings resolved between scans. The report excludes hostnames and contains
only masked MAC addresses.

### Secret Scanning

The gitleaks scripts check both the working tree and Git history:

```sh
sh scripts/macos/check-secrets.sh
```

```powershell
.\scripts\windows\check-secrets.ps1
```

Run the relevant platform script after installing gitleaks separately. Expected
result: exit code 0 with no reported secrets; a missing executable is an
explicit failure, not a success. CI runs the same check on push and pull
request.

- `GET /api/network`: detect the network without scanning.
- `POST /api/scan`: `{"target":"172.20.10.3","confirm":true}`.
- `confirm` accepts only the boolean `true`, not `"true"` or `1`.
- Requests cannot modify the allowlist, configuration, Nmap arguments, or
  output path.
- HTTP: 200 success; 403 authorization refusal; 409 unavailable/ambiguous
  network or scan already in progress; 422 invalid request; 500 local file
  error; 502 scan failure, including missing Nmap or invalid XML.
- CLI: 0 success; 1 execution/file error; 2 refusal, unavailable network,
  scan already in progress, or invalid arguments.

## Verification

```sh
python -m pip install -r requirements-dev.txt
python -m pytest -q -m "not native"
```

Normal tests simulate Nmap and do not generate scan traffic. To read the
actual local network configuration, still without scanning, set
`NETCHECK_NATIVE_TEST=1`:

```sh
NETCHECK_NATIVE_TEST=1 python -m pytest tests/test_network_native.py -q
```

The GitHub Actions matrix deliberately excludes tests marked `native`: hosted
runners use virtual or changing network topologies and cannot certify the
laboratory adapter. The deterministic suite runs on macOS, Windows, and Linux
without scan traffic or services. It needs no Nmap installation or administrator
privileges; database and lock files are isolated in temporary directories.
CI uses Linux/Python 3.10 and macOS + Windows/Python 3.13 instead of repeating
all OS/Python combinations. Workflows run only on pull requests (including new
commits) or manually via `workflow_dispatch`, never on `push`; direct pushes
without a PR require a manual run. New runs cancel older runs for the same PR.
Gitleaks is the single secret scanner, separate from the Python tests.

Network detection has been verified on the laboratory Mac. Windows/Linux have
backends and simulated tests; the CI workflow is configured, but each platform
must still be verified natively before the demonstration. See
[network detection](docs/network-detection.md) for details.

Tests cover network detection, guardrails, simulated scanning, XML parsing,
findings, scoring, history, and API endpoints.

Laboratory documentation and the preliminary HTTP capture are available in
[lab/README.md](lab/README.md). For remaining work, see the
[project status](docs/project-status.md).

### Finding explanations (RO/EN)

`netcheck/catalog.json` contains the 15 local explanations and remediation
lists. The catalog is validated and read once per process; restart the server
after editing it. Scan findings, severity and scores still come only from the
rule engine.

`POST /api/import`, `POST /api/scan`, and `GET /api/scans/{id}` attach `title`,
`explain`, and `fix` to each finding. Without `lang`, each field contains
`ro` and `en`; with `?lang=ro` or `?lang=en`, titles and explanations are
strings and `fix` is a list of steps. Other language values return HTTP 422.
The stored history remains the engine model, so existing scans also receive
the catalog explanations when retrieved. A missing or invalid catalog returns
HTTP 503 with a Romanian/English error, without saving a partial import.
