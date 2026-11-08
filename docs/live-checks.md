# Live checks — jury runbook

The 7 live checks, in order. Each one lists what is asked, what to run or click,
what must be visible, and plan B. Everything here was run offline on `main` at
`767b3c4` against a temporary server and temporary database. The exceptions are
marked **not verified**. Behaviour that depends on an open PR is marked
**(needs PR #N)**.

## Before the jury arrives

```sh
source .venv/bin/activate
python -m netcheck network          # must show the hotspot (e.g. 172.20.10.0/28), never 10.240.x
python -m netcheck serve            # then open http://127.0.0.1:8000 and click EN (bottom left)
```

- Do **not** click History → "Clear history" → "Delete everything". It deletes
  every saved scan in `netcheck.db`.
- Have the Test Set folder path ready and check it with `ls <TEST_SET_DIR>/*.xml`.
- Have a second terminal open for plan B commands.

## 1. Re-run on a Test Set file

**Asked:** analyse the jury's Test Set and produce the official outputs.

```sh
/usr/bin/time -p python -m netcheck analyze <TEST_SET_DIR> --out output-test
cat output-test/scores.csv
cat output-test/findings.csv
```

**Visible:** `scores.csv` has one row per file (`file,network_score`, with
`ERROR` for unreadable XML). `findings.csv` has `file,ip,port,finding_code,severity`.
The `real` line shows the time taken.

**Careful:** `analyze` reads only `*.xml` files directly inside the folder, not
subfolders. A wrong path still exits 0 and writes CSVs with only a header row.
If `scores.csv` has only the header, the path is wrong.

**UI alternative:** Import → "Choose XML files" → select all files. Each file
gets a card showing "Score N".

**Plan B:** if the UI does not start, the CLI output above is the evidence.

**Reference (Validation Set):** on `0294d40` (PR #22, not merged) the scores
are 90, 40, 45, 25, 50, 60, 100, ERROR. They are byte-identical to the official
CSVs, and 4 runs took 0.07–0.18 s each. On `main` `767b3c4`, V4 shows 30
instead of 25 (`UNKNOWN_DEVICE` is info/0) **(needs PR #22)**.

## 2. Juror finds the most dangerous device and the first step, UI only

**Asked:** without help, the juror says which device is most at risk and what to
do first.

**Clicks:** Home, or Import → click a file card. The "What you can do next"
list opens with a red row labelled "Start here · High". That row shows the
finding title, "First step: …" and the device's `IP:port`. On the map, every
device is labelled with its highest severity.

**Visible (verified with V2_smart_home.xml):** "Start here · High · RTSP
streaming service available · First step: Turn off video streaming in the device
settings if you do not use it. · 192.168.1.40:554".

**Careful:** on `767b3c4` the Import detail view collapses at 1280–1920 px wide
(the text runs one letter per line) **(needs PR #23)**. Home displays correctly,
but it only shows **live** scans.

**Plan B:**
`python -c "from netcheck.scoring import analyze_file; print(analyze_file('<FILE>')['top_risk'])"`
prints, for example, `{'ip': '192.168.1.30', 'code': 'RDP_EXPOSED', 'severity': 'high'}`.
Read the first step with the catalogue command in check 3.

## 3. Explanations and fixes for 3 findings chosen by the jury

**Clicks:** click the finding row, or the device on the map. The right panel,
"Device details", lists every finding for that device. Each one has a
severity, title · port, a plain-language explanation and a numbered "What you
can do" list. RO/EN switches at the bottom left. Optionally, click "Explain it ·
Learning Mode" and then a suggested question. With no LLM key configured, the
answer is labelled "From documentation" and starts "The assistant is not
available right now; here is what the documentation says:".

**Plan B (no server needed):**

```sh
python -c "from netcheck.catalog import load_catalog; e = load_catalog()['TELNET_OPEN']; print(e['title']['en']); print(e['explain']['en']); print(*e['fix']['en'], sep='\n')"
```

Replace `TELNET_OPEN` with any of the 15 codes (for example `DB_EXPOSED`,
`HTTP_ADMIN_CLEARTEXT`, `UNKNOWN_DEVICE`).

## 4. Guardrail refuses a public IP and the venue network

```sh
python -m netcheck demo-refusals
```

**Visible:** 4 lines starting "REFUZAT / REFUSED":
- public IP 8.8.8.8: "Only RFC1918 private networks are allowed";
- venue target 10.240.0.5: "Target is outside the allowlist";
- venue subnet 10.240.0.0/16: "Subnet too large; limit is /24";
- missing `--confirm`: "Scan confirmation is required".

The last line reads "subprocess was not called", and the exit code is 0.

**Optional, real CLI path:** `python -m netcheck scan 8.8.8.8 --confirm` exits
with code 2 and prints "Only RFC1918 private networks are allowed…". This was
checked with any `nmap`/`sudo` call blocked by a test patch; the unpatched
command was **not run**. If the laptop is on the venue Wi-Fi and
`lab/network.json` does not exist, `python -m netcheck scan --confirm` exits
with code 2 and prints "The connected network (10.240.0.0/16) is too large for
a hotspot and looks like the venue Wi-Fi…". This was checked with a simulated
venue network.

**Warning:** on the hotspot, `scan --confirm` with no target **starts a real
scan** of the whole hotspot subnet. Do not use it as a refusal demo.

**Plan B:** `python -m pytest -q tests/test_scan_guardrails.py` (29 passed).

## 5. A broken file gives a clear error without a crash

**Clicks:** Import → "Choose XML files" → choose a broken file (for example
`tests/validation/V7_broken.xml`). A red notice appears: "V7_broken.xml: the
file is incomplete or damaged and cannot be read." On `767b3c4` the notice
**disappears after about 2 s**, so point at it straight away. Previously
imported cards stay and the app keeps working.

**CLI:** `python -m netcheck analyze <folder>` writes `ERROR` for that file in
`scores.csv` and still analyses the other files (exit 0). This was checked with
a truncated file, an empty file and a non-XML file.

**API:** `curl -s -X POST --data-binary @tests/validation/V7_broken.xml "http://127.0.0.1:8000/api/import?filename=V7_broken.xml"`
returns HTTP 200 with `"status":"error"` and "The file cannot be read." On
`767b3c4` this also saves an error row in history. That behaviour is being
changed in the UI work.

## 6. History before/after with a rising score

**Primary path (live, not verified end to end):**
1. `python -m netcheck network`: confirm you are on the hotspot.
2. BEFORE: scan **one IP** so the scan finishes within the 300 s limit. The
   Home button "Scan the network" → "Confirm and scan" scans the whole default
   subnet, and earlier `/28` scans did not finish. Run this instead:
   `curl -s -X POST http://127.0.0.1:8000/api/scan -H 'Content-Type: application/json' -d '{"target":"<IP>","confirm":true}'`
   (**not run**; from reading the code, the result is saved as a live scan).
3. Fix the service on the target, then repeat step 2 for AFTER.
4. History: the chart line rises. Under "Compare two scans", pick Before and
   After to see "Score: X → Y", "Problems fixed" and "Ports closed now".
   "Export report" opens a printable report.

**Verified UI:** with two scans stored as live in a temporary DB (V6a, V6b),
History showed the chart going from 60 to 100, "Score: 60 → 100" and "Problems
fixed: HTTP_ADMIN_CLEARTEXT, UPNP_EXPOSED, TELNET_OPEN". "Export report" opened
`/api/report?lang=en&a=…&b=…`.

**Plan B:**
- **nmap hangs:** run `pgrep -l nmap`, then the user runs `sudo kill <pid>`.
  On macOS a timeout leaves the root `nmap` running.
- **Live scan fails:** import the saved BEFORE/AFTER XMLs (none are in Git yet).
  On `767b3c4` History shows live scans only, so imports appear there only with
  the "All, including imports" filter **(needs PR #16)**. Without that PR:
  - `curl -s http://127.0.0.1:8000/api/scans` gives the ids;
  - `curl -s "http://127.0.0.1:8000/api/compare?a=<before>&b=<after>"` gives the
    comparison;
  - opening `http://127.0.0.1:8000/api/report?a=<before>&b=<after>&lang=en` in
    the browser shows the report.

  This was verified on imported V6a/V6b: 60 → 100, three findings resolved.
- **Last resort:** import V6a/V6b and say clearly that they are the official
  sample, not our lab.

## 7. No secrets

```sh
sh scripts/macos/check-secrets.sh                                   # expect exit 0, "no leaks found"
gitleaks dir --config .gitleaks.toml --no-banner --redact .        # working tree
git check-ignore -v netcheck.db lab/network.json .env              # all three ignored
```

On `767b3c4` the script runs `gitleaks detect --source .` and `gitleaks git`.
Both scan Git history only. The working-tree scan inside the script comes with
**PR #18**, so until then also run the `gitleaks dir` line.

Verified on `767b3c4` (gitleaks 8.30.1):
- `gitleaks dir`: no leaks found;
- `gitleaks detect --source . --log-opts=--all`: 52 commits, no leaks;
- `git ls-files`: no `.db`, `.env` or `network.json` is tracked.

Not run in this session: the script itself and `gitleaks git`. An earlier
session reported exit 0. The Windows script `.\scripts\windows\check-secrets.ps1`
has not been run.

CI runs gitleaks on pull requests and on manual `workflow_dispatch`, not on push.
