#!/bin/sh
set -eu

BEFORE="${1:-lab/before}"
AFTER="${2:-lab/after}"
python lab/services/check_xml.py "$BEFORE"/*.xml
python lab/services/check_xml.py "$AFTER"/*.xml
python lab/compare.py "$BEFORE" "$AFTER"
echo "Next / Următorii pași: păstrați XML-urile și folosiți analizorul oficial când este implementat."
