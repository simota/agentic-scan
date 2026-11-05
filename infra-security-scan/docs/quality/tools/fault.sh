#!/bin/bash
# Usage: fault.sh REPO — copies the scripts, makes iac_scan.py fail on import, runs each tool that does not need it.
R=$1; W=$(mktemp -d); cp -r "$R/skills/infra-scan" "$W/skill"; S=$W/skill/scripts
sed -i '1a raise RuntimeError("injected fault in iac_scan")' "$S/iac_scan.py"
O=$W/out; python3 "$R/skills/infra-scan/scripts/render.py" "$R/examples/findings.sample.json" --out "$O" --no-pdf >/dev/null
run(){ if "$@" >/dev/null 2>"$W/err"; then echo "OK    $*" | sed "s#$W#W#g;s#$R#R#g"; else echo "FAIL  $* :: $(tail -1 $W/err)" | sed "s#$W#W#g;s#$R#R#g"; fi; }
run python3 $S/findings.py status $R/examples/findings.sample.json
run python3 $S/render.py $R/examples/findings.sample.json --out $W/o2 --no-pdf
run python3 $S/contract_check.py $O --no-pdf
run python3 $S/render.py $R/examples/findings.sample.json --out $W/o3 --no-pdf --repo $R/tests/fixtures
run python3 $S/iac_scan.py $R/tests/fixtures --out $W/iac.json
rm -rf "$W"
