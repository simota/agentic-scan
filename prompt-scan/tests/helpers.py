import contextlib
import copy
import io
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "skills" / "prompt-scan" / "scripts"
EXAMPLES = REPO / "examples"
SAMPLE_APP = EXAMPLES / "sample-app"
sys.path.insert(0, str(SCRIPTS))

import compare  # noqa: E402,F401
import contract_check  # noqa: E402,F401
import excerpt  # noqa: E402,F401
import export  # noqa: E402,F401
import findings  # noqa: E402,F401
import inventory  # noqa: E402,F401
import record  # noqa: E402,F401
import render  # noqa: E402,F401


def sample(lang="en"):
    name = "findings.sample.ja.json" if lang == "ja" else "findings.sample.json"
    return json.loads((EXAMPLES / name).read_text(encoding="utf-8"))


def write_json(path, value):
    Path(path).write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def run(main, *args):
    """Call a script's main() and return (exit code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main([str(a) for a in args])
    return code, out.getvalue(), err.getvalue()


def clone(value):
    return copy.deepcopy(value)
