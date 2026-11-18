#!/bin/bash
# Usage: fault.sh REPO — copies the scripts, makes iac_scan.py fail on import, runs each tool that does not need it.
R=$1; W=$(mktemp -d); cp -r "$R/skills/infra-security-scan" "$W/skill"; S=$W/skill/scripts
sed -i '1a raise RuntimeError("injected fault in iac_scan")' "$S/iac_scan.py"
O=$W/out; mkdir -p "$O"; cp "$R/examples/findings.sample.json" "$O/findings.json"
python3 "$R/skills/infra-security-scan/scripts/render.py" "$O/findings.json" --out "$O" --no-pdf >/dev/null
# REACHED: the injected fault stopped the tool. ISOLATED: the tool ran to its own result (exit code shown).
run(){ "$@" >/dev/null 2>"$W/err"; rc=$?; if grep -q "injected fault" "$W/err"; then v=REACHED; else v="ISOLATED rc=$rc"; fi
  echo "$v  $* :: $(tail -1 "$W/err")" | sed "s#$W#W#g;s#$R#R#g"; }
run python3 $S/findings.py status $R/examples/findings.sample.json
run python3 $S/render.py $R/examples/findings.sample.json --out $W/o2 --no-pdf
run python3 $S/contract_check.py $O --no-pdf
run python3 $S/render.py $R/examples/findings.sample.json --out $W/o3 --no-pdf --repo $R/tests/fixtures
run python3 $S/iac_scan.py $R/tests/fixtures --out $W/iac.json
rm -rf "$W"
