"""Shared fixtures and helpers for the offline test suite.

Not collected by unittest discovery (the name does not start with ``test``);
test modules import it as a sibling module, which works both from
``python -m unittest discover -s tests`` and from ``cd tests && python -m unittest test_x``.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from html.parser import HTMLParser
from types import ModuleType
from unittest.mock import patch
from xml.etree.ElementTree import Element, SubElement

REPO = Path(__file__).resolve().parents[1]
SKILL = REPO / "skills" / "performance-scan"
OUTPUTS = ("report.md", "dashboard.html")


def import_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", [str(path.parent)] + sys.path):
        spec.loader.exec_module(module)
    return module


findings = import_module(SKILL / "scripts" / "findings.py", "perf_findings")
render = import_module(SKILL / "scripts" / "render.py", "perf_render")


def finding(fid="P-001", severity="High", **extra) -> dict:
    record = {
        "id": fid, "title": "Order list loads items per order", "severity": severity,
        "confidence": "Confirmed", "category": "Database access", "step": "DB1",
        "location": ["app/orders/serializers.py:42"],
        "workload": "Order list, hot", "scale_driver": "Items per order, uncapped",
        "cost_model": "1 + N queries", "request": "1. GET /api/orders?page=<n>",
        "impact": "Expected constant queries; actual 1 + N", "fix": "Prefetch items",
        "regression_test": "Query count equal for 1 and 50 orders",
        "validation": {"verdict": "Valid", "method": "static", "evidence": "views.py:18"},
    }
    record.update(extra)
    return record


def complete_doc() -> dict:
    return {
        "meta": {"project": "demo", "scope": "repo root", "date": "2026-10-09",
                 "assessor": "test", "lang": "en"},
        "budgets": [{"id": "B-01", "statement": "constant queries", "source": "baseline",
                     "status": "violated"}],
        "findings": [finding(), finding("P-002", "Low")],
        "perspectives": [{"name": n, "status": "applied", "note": "applied"}
                         for n in findings.PERSPECTIVES],
        "checked_ok": ["search paginates"],
        "limitations": ["production volume not observed"],
    }


def run_main(main, *args):
    """Call a script's ``main`` in-process; return (exit code, stdout, stderr)."""
    stdout, stderr = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        code = main([str(arg) for arg in args])
    return code, stdout.getvalue(), stderr.getvalue()


def run_cli(script, *args, timeout=15, env_updates=None):
    """Run ``skills/performance-scan/scripts/<script>`` in a fresh interpreter."""
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.update(env_updates or {})
    return subprocess.run(
        [sys.executable, str(SKILL / "scripts" / script), *(str(arg) for arg in args)],
        capture_output=True, text=True, check=False, timeout=timeout, env=env)


def snapshot(root):
    """Map every entry under root to its type, permission bits and content or link target.

    Uses lstat, so symlink loops and FIFOs are recorded without being followed or opened.
    """
    entries = {}
    for path in Path(root).rglob("*"):
        mode = path.lstat().st_mode
        record = (stat.S_IFMT(mode), stat.S_IMODE(mode))
        if stat.S_ISLNK(mode):
            record += (path.readlink(),)
        elif stat.S_ISREG(mode):
            record += (path.read_bytes(),)
        entries[str(path.relative_to(root))] = record
    return entries


def write_run_dir(out, doc):
    """Write doc as findings.json beside placeholder outputs, as a run directory."""
    out = Path(out)
    (out / "findings.json").write_text(json.dumps(doc), encoding="utf-8")
    for name in OUTPUTS:
        (out / name).write_text("x", encoding="utf-8")


def contract_problems(doc):
    """The run-contract problems ``findings.py check`` reports for doc."""
    with tempfile.TemporaryDirectory() as directory:
        write_run_dir(directory, doc)
        return findings.contract_problems(Path(directory))


class HtmlTableReader(HTMLParser):
    """Collect every table row's cell texts and the sequence of opened tags."""

    def __init__(self):
        super().__init__()
        self.rows = []
        self.tags = []
        self.row = []
        self.cell = None

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        if tag == "tr":
            self.row = []
        if tag in ("td", "th"):
            self.cell = ""

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data

    def handle_endtag(self, tag):
        if tag in ("td", "th"):
            self.row.append(self.cell)
            self.cell = None
        if tag == "tr":
            self.rows.append(self.row)


class HtmlTreeReader(HTMLParser):
    """Read rendered elements and decoded text without a browser dependency."""
    VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
            "meta", "param", "source", "track", "wbr"}

    def __init__(self, html):
        super().__init__()
        self.root = Element("document")
        self.stack = [self.root]
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        element = SubElement(self.stack[-1], tag, dict(attrs))
        if tag not in self.VOID:
            self.stack.append(element)

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, 0, -1):
            if self.stack[i].tag == tag:
                del self.stack[i:]
                break

    def handle_data(self, data):
        element = self.stack[-1]
        if len(element):
            element[-1].tail = (element[-1].tail or "") + data
        else:
            element.text = (element.text or "") + data


def element_text(element):
    return "".join(element.itertext())


compare = import_module(SKILL / "scripts" / "compare.py", "perf_compare")
issues = import_module(SKILL / "scripts" / "issues.py", "perf_issues")
summary = import_module(SKILL / "scripts" / "summary.py", "perf_summary")


def write_record(directory, name, doc) -> Path:
    """Write doc as a JSON record named name under directory and return its path."""
    path = Path(directory) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, ensure_ascii=False), encoding="utf-8")
    return path
