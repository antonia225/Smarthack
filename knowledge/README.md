# NetCheck knowledge corpus

`sources.json` is the fixed allowlist of sources. Run
`python3 scripts/build_knowledge.py` when internet access is available to
retrieve short, attributed passages. The generated Markdown files are
intentionally not committed by the build script unless the command is run.

The Learning Mode fallback works without this directory being populated by
using the local finding catalog. No source has a `verified` state: retrieval
means only that a passage was downloaded from an allowlisted URL.
