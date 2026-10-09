#!/usr/bin/env python3
"""Render findings.json into the dashboard, the assessment and its PDF.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--no-pdf] [--repo REPO]

Writes DIR/dashboard.html (interactive, self-contained), DIR/assessment.html
(the formal, print-oriented report) and DIR/assessment.pdf (headless Chrome;
set CHROME to choose the binary). With --repo, each finding's `path:line` is
embedded as a short source excerpt; state files, variable files and
secret-looking files are never read, and lines that look like they assign a
secret are redacted. JSON/YAML with sensitive metadata, secret environment
values or unsupported syntax has no excerpt. Other redaction is heuristic:
inspect before sharing.

`validate()` is the executable form of reference/findings-schema.md and is
imported by findings.py and contract_check.py.

Exit codes: 0 rendered (a missing PDF engine is a warning), 2 unreadable input
or schema error (every problem on stderr).
"""
import argparse
import datetime
import html
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlparse

from redaction import (has_escaped_secret_keys, has_structured_secrets, is_secret_name, redact,
                       redact_json_values, redact_lines, split_lines)

SKILL = Path(__file__).resolve().parents[1]

TOP = {"schema_version", "meta", "inventory", "attack_paths", "findings", "perspectives",
       "checked_ok", "decisions", "limitations", "next_steps"}
STRING_LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
SEVERITIES = ("High", "Medium", "Low", "Info")
CONFIDENCES = ("Confirmed", "Environment-dependent", "Suspected")
PROVIDERS = ("aws", "gcp", "azure", "kubernetes", "multi")
VERDICTS = ("Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable")
NEEDS_EVIDENCE = {"Valid", "FalsePositive", "NotApplicable"}
EXCLUDED = {"FalsePositive", "NotApplicable"}
AP_STATUSES = ("open", "blocked", "unknown")
P_STATUSES = ("Applied", "N/A", "Not checked")
INPUT_KINDS = ("iac", "plan", "snapshot", "manifest")
# ASCII digits and \Z: "$" would accept a trailing newline and \d other scripts' digits.
F_ID = re.compile(r"^F-([0-9]{3,})\Z")
I_ID = re.compile(r"^I-([0-9]{3,})\Z")
AP_ID = re.compile(r"^AP-([0-9]{2,})\Z")
LOCATION = re.compile(r"^([^\s:]+):([0-9]+)(?:-([0-9]+))?\Z")
CITED = re.compile(r"[\w./-]+\.[A-Za-z]\w*:[0-9]+")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
F_FIELDS = ("actor", "path", "contrast", "impact", "fix", "regression")
BASE_FIELDS = ("title", "location")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

CHROME_CANDIDATES = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome",
]


class SchemaError(Exception):
    def __init__(self, problems):
        self.problems = [problems] if isinstance(problems, str) else list(problems)
        super().__init__("; ".join(self.problems))


def perspective_names():
    """Canonical names, read from the first table in reference/perspectives.md."""
    names = []
    for line in (SKILL / "reference" / "perspectives.md").read_text(encoding="utf-8").splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) == 2 and cells[0] not in ("Perspective", "") and not set(cells[0]) <= set("-: "):
            names.append(cells[0])
    return names


def blank(value):
    return not isinstance(value, str) or not value.strip()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            # Object keys can themselves be credentials. Keep errors safe to log.
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    except (OSError, UnicodeError, ValueError, RecursionError) as e:
        raise SchemaError(f"{path}: {e}") from None


CWE = re.compile(r"^CWE-[0-9]+\Z")


def valid_date(value):
    if not DATE.match(value):
        return False
    try:
        datetime.date.fromisoformat(value)
    except ValueError:
        return False
    return True


def location_problem(location):
    """path:line or path:line-line, with lines counted from 1."""
    m = LOCATION.match(location)
    if not m:
        return "location must be path:line or path:line-line"
    start, end = int(m.group(2)), int(m.group(3) or m.group(2))
    if start < 1 or end < start:
        return "location lines start at 1 and a range must not run backwards"
    return None


def empty_record():
    return {"schema_version": 1, "meta": {}, "attack_paths": [], "findings": [], "perspectives": [],
            "checked_ok": [], "decisions": [], "limitations": [], "next_steps": []}


def validate(data, partial=False):
    """Raise SchemaError listing every problem. partial=True skips the meta fields
    a record only needs once complete (used while fragments are still merging)."""
    if not isinstance(data, dict):
        raise SchemaError("record: must be a JSON object")
    p = []
    add = p.append
    unknown = set(data) - TOP
    if unknown:
        add(f"record: unknown top-level keys {sorted(unknown)}")
    if type(data.get("schema_version")) is not int or data["schema_version"] != 1:
        add("record: schema_version must be 1")

    meta = data.get("meta", {})
    if not isinstance(meta, dict):
        add("meta: must be an object")
        meta = {}
    if not partial:
        for key in ("project", "scope", "date", "assessor"):
            if blank(meta.get(key)):
                add(f"meta.{key}: required")
    if not blank(meta.get("date")) and not valid_date(meta["date"]):
        add("meta.date: must be a calendar date, YYYY-MM-DD")
    for key in ("project", "scope", "date", "assessor", "method", "commit"):
        if key in meta and not isinstance(meta[key], str):
            add(f"meta.{key}: must be a string")
    if "providers" in meta:
        prov = meta["providers"]
        if not isinstance(prov, list) or any(x not in PROVIDERS[:4] for x in prov):
            add("meta.providers: must be a list of aws, gcp, azure, kubernetes")
    if "inputs" in meta:
        if not isinstance(meta["inputs"], list):
            add("meta.inputs: must be a list")
        else:
            for i, item in enumerate(meta["inputs"]):
                if not isinstance(item, dict) or item.get("kind") not in INPUT_KINDS or blank(item.get("path")):
                    add(f"meta.inputs[{i}]: needs kind ({'|'.join(INPUT_KINDS)}) and path")

    if "inventory" in data and not isinstance(data["inventory"], dict):
        add("inventory: must be an object")

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        add("findings: must be a list")
        findings = []
    paths = data.get("attack_paths", [])
    if not isinstance(paths, list):
        add("attack_paths: must be a list")
        paths = []
    # Only string IDs can be referenced; other types are reported below
    # instead of crashing set membership.
    finding_ids = {f.get("id") for f in findings if isinstance(f, dict) and isinstance(f.get("id"), str)}
    ap_ids = {a.get("id") for a in paths if isinstance(a, dict) and isinstance(a.get("id"), str)}
    names = perspective_names()

    seen = set()
    for n, f in enumerate(findings):
        if not isinstance(f, dict):
            add(f"findings[{n}]: must be an object")
            continue
        fid = f.get("id")
        where = fid if isinstance(fid, str) else f"findings[{n}]"
        is_f = isinstance(fid, str) and bool(F_ID.match(fid))
        is_i = isinstance(fid, str) and bool(I_ID.match(fid))
        if not (is_f or is_i):
            add(f"{where}: id must be F-NNN or I-NNN (at least three digits)")
        else:
            # F-001 and F-0001 are the same number; IDs are compared numerically.
            if id_key(fid) in seen:
                add(f"{where}: duplicate id")
            seen.add(id_key(fid))
        for key in BASE_FIELDS:
            if blank(f.get(key)):
                add(f"{where}: {key} required")
        if isinstance(f.get("title"), str) and "\n" in f["title"].strip():
            add(f"{where}: title must be one line")
        if f.get("severity") not in SEVERITIES:
            add(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
        if f.get("confidence") not in CONFIDENCES:
            add(f"{where}: confidence must be one of {', '.join(CONFIDENCES)}")
        if f.get("category") not in names:
            add(f"{where}: category must be a perspective name from reference/perspectives.md")
        if f.get("provider") not in PROVIDERS:
            add(f"{where}: provider must be one of {', '.join(PROVIDERS)}")
        res = f.get("resources")
        if not isinstance(res, list) or not res or any(blank(r) for r in res):
            add(f"{where}: resources must be a nonempty list of resource addresses")
        if not blank(f.get("location")):
            problem = location_problem(f["location"])
            if problem:
                add(f"{where}: {problem}")
        if is_f:
            for key in F_FIELDS:
                if blank(f.get(key)):
                    add(f"{where}: {key} required for F-* findings")
        if is_i and blank(f.get("rule")):
            add(f"{where}: rule required for I-* findings")
        if f.get("confidence") == "Environment-dependent" and blank(f.get("condition")):
            add(f"{where}: condition required when confidence is Environment-dependent")
        for key in ("actor", "path", "contrast", "impact", "fix", "regression", "condition", "cwe", "rule",
                    "detail"):
            if key in f and not isinstance(f[key], str):
                add(f"{where}: {key} must be a string")
        if "controls" in f and (not isinstance(f["controls"], list) or any(blank(c) for c in f["controls"])):
            add(f"{where}: controls must be a list of strings")
        if isinstance(f.get("cwe"), str) and not CWE.match(f["cwe"]):
            add(f"{where}: cwe must look like CWE-284")
        if "attack_paths" in f:
            if not isinstance(f["attack_paths"], list):
                add(f"{where}: attack_paths must be a list")
            else:
                for ap in f["attack_paths"]:
                    if not isinstance(ap, str) or ap not in ap_ids:
                        add(f"{where}: attack path {ap} does not exist")
        for i, ref in enumerate(f.get("references", []) if isinstance(f.get("references", []), list) else [None]):
            if not isinstance(ref, dict) or blank(ref.get("url")) or blank(ref.get("title")):
                add(f"{where}: references[{i}] needs title and url")
                continue
            u = urlparse(ref["url"])
            if u.scheme != "https" or not u.hostname or "@" in u.netloc:
                add(f"{where}: references[{i}] must be an https URL without credentials")
        val = f.get("validation")
        if not isinstance(val, dict) or val.get("verdict") not in VERDICTS:
            add(f"{where}: validation.verdict must be one of {', '.join(VERDICTS)}")
        else:
            if "evidence" in val and not isinstance(val["evidence"], str):
                add(f"{where}: validation.evidence must be a string")
            elif val["verdict"] in NEEDS_EVIDENCE and blank(val.get("evidence")):
                add(f"{where}: validation.evidence required for {val['verdict']}")
            if is_f and val["verdict"] == "Valid" and f.get("confidence") == "Confirmed" \
                    and isinstance(f.get("path"), str):
                for line in (x for x in f["path"].splitlines() if x.strip()):
                    if not CITED.search(line):
                        add(f"{where}: Valid + Confirmed needs path:line on every edge; missing in {line.strip()!r}")

    seen = set()
    for n, a in enumerate(paths):
        if not isinstance(a, dict):
            add(f"attack_paths[{n}]: must be an object")
            continue
        aid = a.get("id")
        where = aid if isinstance(aid, str) else f"attack_paths[{n}]"
        if not isinstance(aid, str) or not AP_ID.match(aid):
            add(f"{where}: id must be AP-NN (at least two digits)")
        else:
            if id_key(aid) in seen:
                add(f"{where}: duplicate id")
            seen.add(id_key(aid))
        for key in ("entry", "target"):
            if blank(a.get(key)):
                add(f"{where}: {key} required")
        if a.get("status") not in AP_STATUSES:
            add(f"{where}: status must be one of {', '.join(AP_STATUSES)}")
        elif a["status"] != "open" and blank(a.get("note")):
            add(f"{where}: note must name the blocking or unknown edge when status is {a['status']}")
        edges = a.get("edges")
        if not isinstance(edges, list) or not edges or any(blank(e) for e in edges):
            add(f"{where}: edges must be a nonempty list of strings")
        if "note" in a and not isinstance(a["note"], str):
            add(f"{where}: note must be a string")
        refs = a.get("findings", [])
        if not isinstance(refs, list):
            add(f"{where}: findings must be a list")
        else:
            for fid in refs:
                if not isinstance(fid, str) or fid not in finding_ids:
                    add(f"{where}: finding {fid} does not exist")

    persp = data.get("perspectives", [])
    if not isinstance(persp, list):
        add("perspectives: must be a list")
        persp = []
    seen = set()
    for n, item in enumerate(persp):
        if not isinstance(item, dict):
            add(f"perspectives[{n}]: must be an object")
            continue
        name = item.get("name")
        if not isinstance(name, str) or name not in names:
            add(f"perspectives[{n}]: unknown perspective {name!r}")
        elif name in seen:
            add(f"perspectives: {name} listed twice")
        else:
            seen.add(name)
        if item.get("status") not in P_STATUSES:
            add(f"perspectives[{n}]: status must be one of {', '.join(P_STATUSES)}")
        if "note" in item and not isinstance(item["note"], str):
            add(f"perspectives[{n}]: note must be a string")
        if item.get("status") in ("N/A", "Not checked") and blank(item.get("note")):
            add(f"perspectives[{n}]: {item.get('status')} needs a reason in note")
    for key in STRING_LISTS:
        value = data.get(key, [])
        if not isinstance(value, list) or any(not isinstance(x, str) for x in value):
            add(f"{key}: must be a list of strings")
    if p:
        raise SchemaError(p)


# ---------------------------------------------------------------- model

LABELS = {
    "en": {
        "doc_title": "Infrastructure security assessment", "brand": "INFRA-SCAN",
        "dashboard": "Dashboard", "assessment": "Assessment report", "theme": "Theme",
        "summary": "Summary", "findings": "Findings", "attack_paths": "Attack paths",
        "perspectives": "Perspective coverage", "checked_ok": "Checked and sound",
        "decisions": "Decisions for a human", "limitations": "Limitations", "next_steps": "Next steps",
        "excluded": "Excluded findings", "none": "None recorded.",
        "severity": "Severity", "confidence": "Confidence", "verdict": "Verdict", "provider": "Provider",
        "category": "Perspective", "resources": "Resources", "location": "Location", "actor": "Actor",
        "path": "Attack path", "contrast": "Contrast (sound sibling)", "impact": "Impact",
        "fix": "Fix direction", "regression": "Regression check",
        "controls": "Controls", "cwe": "CWE", "condition": "Assumed condition", "references": "References",
        "rule": "Baseline rule", "evidence": "Evidence", "detail": "Detail", "source": "Source excerpt",
        "entry": "Entry", "target": "Target", "status": "Status", "edges": "Edges", "note": "Note",
        "linked": "Findings", "id": "ID", "title": "Title",
        "project": "Project", "scope": "Scope", "date": "Date", "assessor": "Assessor",
        "method": "Method", "commit": "Commit", "inputs": "Inputs", "inventory": "Inventory",
        "resources_n": "resources", "files_n": "files", "not_run": "Not run",
        "all": "All", "search": "Search", "shown": "shown", "copy": "Copy for LLM", "copied": "Copied",
        "expand": "Details", "active": "active", "excluded_n": "excluded", "unverified_n": "unverified",
        "static_note": "Static review of configuration. No cloud API was called and no deployed resource was contacted.",
        "pdf_missing": "PDF not generated: no headless Chrome or WeasyPrint found.",
        "pdf_failed": "PDF not generated: the PDF engine was found but failed.",
        "cover_note": "Confidential — for the owner of the assessed estate.",
        "scope_method": "Scope and method", "counts": "Counts by severity (excluded findings not counted)",
        "md_intro": "Infrastructure security finding from a static configuration review. Propose a minimal IaC change that restores the boundary, and a policy-as-code test for it.",
    },
    "ja": {
        "doc_title": "インフラ セキュリティ診断", "brand": "INFRA-SCAN",
        "dashboard": "ダッシュボード", "assessment": "診断報告書", "theme": "テーマ",
        "summary": "概要", "findings": "検出事項", "attack_paths": "攻撃経路",
        "perspectives": "観点ごとの実施状況", "checked_ok": "確認して問題なし",
        "decisions": "判断が必要な事項", "limitations": "制約事項", "next_steps": "次の対応",
        "excluded": "除外した検出事項", "none": "記録なし。",
        "severity": "深刻度", "confidence": "確度", "verdict": "判定", "provider": "プロバイダ",
        "category": "観点", "resources": "リソース", "location": "場所", "actor": "攻撃主体",
        "path": "攻撃経路", "contrast": "対照（健全な同種設定）", "impact": "影響",
        "fix": "修正の方向", "regression": "回帰チェック",
        "controls": "対応コントロール", "cwe": "CWE", "condition": "前提条件", "references": "参考",
        "rule": "ベースラインルール", "evidence": "根拠", "detail": "詳細", "source": "ソース抜粋",
        "entry": "侵入点", "target": "標的", "status": "状態", "edges": "経路", "note": "備考",
        "linked": "関連する検出事項", "id": "ID", "title": "タイトル",
        "project": "対象", "scope": "範囲", "date": "診断日", "assessor": "診断者",
        "method": "方法", "commit": "コミット", "inputs": "入力", "inventory": "インベントリ",
        "resources_n": "リソース", "files_n": "ファイル", "not_run": "未実施",
        "all": "すべて", "search": "検索", "shown": "件表示", "copy": "LLM用にコピー", "copied": "コピーしました",
        "expand": "詳細", "active": "有効", "excluded_n": "除外", "unverified_n": "未検証",
        "static_note": "設定の静的レビューです。クラウド API の呼び出しや稼働中リソースへの通信は行っていません。",
        "pdf_missing": "PDF は生成されませんでした（ヘッドレス Chrome / WeasyPrint が見つかりません）。",
        "pdf_failed": "PDF は生成されませんでした（PDF エンジンは見つかりましたが失敗しました）。",
        "cover_note": "機密 — 診断対象の所有者向け。",
        "scope_method": "範囲と方法", "counts": "深刻度別の件数（除外分を除く）",
        "md_intro": "設定の静的レビューで見つかったインフラのセキュリティ検出事項です。境界を回復する最小限の IaC 変更と、それを守る policy-as-code テストを提案してください。",
    },
}

DISPLAY = {
    "en": {},
    "ja": {
        "High": "高", "Medium": "中", "Low": "低", "Info": "情報",
        "Confirmed": "確認済み", "Environment-dependent": "環境依存", "Suspected": "疑い",
        "Valid": "妥当", "Likely": "可能性高", "Unverified": "未検証", "Unlikely": "可能性低",
        "FalsePositive": "誤検知", "NotApplicable": "対象外",
        "open": "成立", "blocked": "遮断", "unknown": "不明",
        "Applied": "実施", "N/A": "該当なし", "Not checked": "未確認",
    },
}


def esc(value):
    return html.escape("" if value is None else str(value), quote=True)


def shown(value, lang):
    return DISPLAY[lang].get(value, value)


def is_excluded(f):
    return f.get("validation", {}).get("verdict") in EXCLUDED


def id_key(identifier):
    """Sort a validated ID by prefix and number, including IDs beyond 999."""
    prefix, number = identifier.rsplit("-", 1)
    return prefix, int(number)


def ordered(findings):
    return sorted(findings, key=lambda f: (SEV_RANK.get(f.get("severity"), 9), id_key(f["id"])))


def counts(data):
    active = [f for f in data.get("findings", []) if not is_excluded(f)]
    c = {s: sum(1 for f in active if f.get("severity") == s) for s in SEVERITIES}
    c["excluded"] = len(data.get("findings", [])) - len(active)
    c["unverified"] = sum(1 for f in active if f.get("validation", {}).get("verdict") == "Unverified")
    return c


# ---------------------------------------------------------------- source excerpts

# Terraform names state backups terraform.tfstate.<timestamp>.backup; dotenv
# files carry an environment suffix (.env.production).
SENSITIVE_NAME = re.compile(r"(\.tfvars(\.json)?|\.pem|\.key|\.p12|\.pfx|\.ppk|\.jks|\.keystore|\.env)$|"
                            r"\.tfstate(\.[^/]*)?$|(^|/)\.env\.[^/]*$|secret|credential|"
                            r"id_(rsa|dsa|ecdsa|ed25519)|\.netrc|\.npmrc|\.pypirc|\.pgpass|kubeconfig|"
                            r"\.dockercfg|(^|/)\.docker/config\.json$", re.IGNORECASE)


def hcl_declares_sensitive(text):
    """Only a known false variable/output declaration permits its source."""
    # Local imports avoid a cycle: the scanner also uses redaction helpers.
    from iac_scan import literal, parse_hcl
    for block in parse_hcl(text):
        if block.type in ("variable", "output") and "sensitive" in block.attrs:
            raw, _ = block.attrs["sensitive"]
            if literal(raw) is not False:
                return True
    return False


HCL_NAME = re.compile(r'(?i)(?<![\w.-])"?(?:name|key)"?\s*[=:]\s*"([^"\n]*)"')
HCL_VALUE = re.compile(r'(?i)(?<![\w.-])"?value"?\s*[=:]')


def hcl_has_paired_secret(text):
    """Name/value pairs (env blocks, jsonencode lists) and secret-named variables.

    Line redaction sees `value = "..."`, not that its sibling `name` is
    DB_PASSWORD. Treat a secret-shaped name with a value nearby as a secret.
    """
    from iac_scan import parse_hcl
    lines = text.split("\n")
    for n, line in enumerate(lines):
        for match in HCL_NAME.finditer(line):
            if is_secret_name(match.group(1)) and any(
                    HCL_VALUE.search(near) for near in lines[max(0, n - 5):n + 6]):
                return True
    for block in parse_hcl(text):
        if block.type == "variable" and block.labels and "default" in block.attrs and \
                is_secret_name(block.labels[0]):
            return True
    return False


def hcl_module_sensitive(directory):
    """Conservatively include declarations inherited through override files.

    Do not evaluate override order or read symlink targets. Unknown sibling
    context makes the module's excerpts unsafe, even when this file looks public.
    """
    try:
        for sibling in directory.iterdir():
            if sibling.name.lower().endswith((".tf.json", ".tofu.json")):
                return True  # Unsupported Terraform JSON can also override sensitivity.
            if sibling.suffix.lower() not in (".tf", ".tofu"):
                continue
            if sibling.is_symlink():
                return True
            if sibling.is_file() and hcl_declares_sensitive(sibling.read_text(encoding="utf-8-sig")):
                return True
    except (OSError, ValueError, TypeError, RecursionError):
        return True
    return False


def source_lines(path):
    """Preserve source line numbers, or return None if an excerpt is unsafe.

    Reuse the scanner's conservative YAML subset. A tag, alias or other
    unsupported construct must not fall back to raw text near another finding.
    JSON sensitivity and env name/value relationships require the whole document;
    line-oriented redaction alone cannot enforce them.
    """
    # Match the scanner's BOM handling before checking sensitivity or line numbers.
    text = path.read_text(encoding="utf-8-sig")
    lines = split_lines(text)
    suffix = path.suffix.lower()
    syntax = "text"
    try:
        if suffix == ".json":
            syntax = "json"
            docs = [json.loads(text, object_pairs_hook=unique_object)]
        elif suffix in (".yaml", ".yml"):
            syntax = "yaml"
            # Local import avoids a cycle: iac_scan also uses redaction helpers.
            from iac_scan import _YamlSubset
            docs, rows = [], []
            for n, line in enumerate(lines, 1):
                if re.fullmatch(r"(?:---|\.\.\.)(?:\s+#.*)?\s*", line):
                    docs.append(_YamlSubset(rows).parse())
                    rows = []
                else:
                    rows.append((n, line))
            docs.append(_YamlSubset(rows).parse())
        else:
            docs = []
            if suffix in (".tf", ".tofu"):
                syntax = "hcl"
                # Sensitivity belongs to the block, not to the default/value
                # line. Only a known false declaration permits an excerpt.
                if hcl_declares_sensitive(text) or hcl_has_paired_secret(text):
                    return None
        if has_escaped_secret_keys(text, docs) or any(has_structured_secrets(doc) for doc in docs):
            return None
        lines = redact_lines(lines, syntax=syntax)
        if syntax == "json":
            lines = redact_json_values(text, lines)
    except (ValueError, TypeError, RecursionError):
        return None
    return lines


def attach_sources(data, repo, context=3):
    """Return {finding id: [(lineno, text, hit)]} for readable, non-sensitive locations."""
    root = Path(repo).resolve()
    out = {}
    hcl_modules = {}
    # Kubernetes Secret values can have arbitrary keys and remain secret even
    # when base64-encoded. Do not expose them through a neighboring finding.
    secret_manifests = set()
    for f in data.get("findings", []):
        if f.get("rule") == "K8S-003":
            match = LOCATION.match(f.get("location", ""))
            if match:
                secret_manifests.add(match.group(1))
    for f in data.get("findings", []):
        if f.get("rule") in ("SEC-001", "K8S-003"):
            continue
        m = LOCATION.match(f.get("location", ""))
        if not m:
            continue
        rel, start = m.group(1), int(m.group(2))
        end = int(m.group(3) or start)
        if rel in secret_manifests or SENSITIVE_NAME.search(rel):
            continue
        cand = root / rel
        try:
            if cand.is_symlink() or not cand.is_file():
                continue
            cand.resolve().relative_to(root)
            if cand.suffix.lower() in (".tf", ".tofu") or cand.name.lower().endswith((".tf.json", ".tofu.json")):
                directory = cand.parent.resolve()
                directory.relative_to(root)
                if directory not in hcl_modules:
                    hcl_modules[directory] = hcl_module_sensitive(directory)
                if hcl_modules[directory]:
                    continue
            lines = source_lines(cand)
        except (OSError, ValueError):
            continue
        if lines is None:
            continue
        end = min(end, start + 40)
        lo, hi = max(1, start - context), min(len(lines), end + context)
        out[f["id"]] = [(i, lines[i - 1], start <= i <= end) for i in range(lo, hi + 1)]
    return out


def snippet_html(rows):
    if not rows:
        return ""
    body = "".join(f'<span class="{"hit" if hit else ""}"><b>{n:>4}</b>  {esc(t)}</span>' for n, t, hit in rows)
    return f'<pre class="snippet">{body}</pre>'


# ---------------------------------------------------------------- shared pieces

FIELD_ORDER = ("actor", "path", "contrast", "impact", "condition", "fix", "regression", "detail",
               "rule", "controls", "cwe")


def field_text(f, key):
    value = f.get(key)
    if isinstance(value, list):
        return ", ".join(value)
    return value


def finding_markdown(f, L, lang):
    lines = [L["md_intro"], "", f"## {f['id']} {f.get('title', '')}", ""]
    lines.append(f"- {L['severity']}: {f.get('severity')} / {L['confidence']}: {f.get('confidence')}")
    lines.append(f"- {L['category']}: {f.get('category')} / {L['provider']}: {f.get('provider')}")
    lines.append(f"- {L['location']}: `{f.get('location')}`")
    lines.append(f"- {L['resources']}: " + ", ".join(f"`{r}`" for r in f.get("resources", [])))
    for key in FIELD_ORDER:
        value = field_text(f, key)
        if value:
            if "\n" in str(value):
                lines += ["", f"### {L[key]}", "", str(value)]
            else:
                lines.append(f"- {L[key]}: {value}")
    val = f.get("validation", {})
    lines += ["", f"### {L['verdict']}", "", f"{val.get('verdict')}: {val.get('evidence', '')}".rstrip(": ")]
    for ref in f.get("references", []):
        lines.append(f"- [{ref.get('title') or ref['url']}]({ref['url']})")
    return "\n".join(lines).strip() + "\n"


def detail_dl(f, L, lang, sources):
    rows = [(L["resources"], "<br>".join(f"<code>{esc(r)}</code>" for r in f.get("resources", []))),
            (L["location"], f"<code>{esc(f.get('location'))}</code>")]
    for key in FIELD_ORDER:
        value = field_text(f, key)
        if value:
            rows.append((L[key], esc(value)))
    if f.get("attack_paths"):
        rows.append((L["attack_paths"], ", ".join(f'<a href="#{esc(a)}">{esc(a)}</a>' for a in f["attack_paths"])))
    val = f.get("validation", {})
    rows.append((L["verdict"], esc(shown(val.get("verdict"), lang))))
    if val.get("evidence"):
        rows.append((L["evidence"], esc(val["evidence"])))
    if f.get("references"):
        rows.append((L["references"], "<br>".join(
            f'<a href="{esc(r["url"])}" rel="noopener noreferrer">{esc(r.get("title") or r["url"])}</a>'
            for r in f["references"])))
    if f.get("id") in sources:
        rows.append((L["source"], snippet_html(sources[f["id"]])))
    return "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"


def ap_html(a, L, lang):
    edges = "".join(f"<li>{esc(e)}</li>" for e in a.get("edges", []))
    links = ", ".join(f'<a href="#{esc(x)}">{esc(x)}</a>' for x in a.get("findings", [])) or "—"
    note = f'<p class="note">{esc(a["note"])}</p>' if a.get("note") else ""
    return (f'<article class="ap st-{esc(a.get("status"))}" id="{esc(a.get("id"))}">'
            f'<div class="ap-head"><strong>{esc(a.get("id"))}</strong>'
            f'<span class="pill st-{esc(a.get("status"))}">{esc(shown(a.get("status"), lang))}</span></div>'
            f'<p class="ap-route"><span>{esc(a.get("entry"))}</span> <span aria-hidden="true">→</span> '
            f'<span>{esc(a.get("target"))}</span></p><ol class="edges">{edges}</ol>{note}'
            f'<p class="muted">{L["linked"]}: {links}</p></article>')


def list_block(items, L):
    if not items:
        return f'<p class="muted">{L["none"]}</p>'
    return "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>"


def meta_rows(data, L):
    meta = data.get("meta", {})
    rows = [(L[k], esc(meta.get(k))) for k in ("project", "scope", "date", "assessor", "method", "commit")
            if meta.get(k)]
    if meta.get("inputs"):
        rows.append((L["inputs"], "<br>".join(
            f'{esc(i.get("kind"))}: <code>{esc(i.get("path"))}</code>' + (f' — {esc(i["note"])}' if i.get("note") else "")
            for i in meta["inputs"])))
    inv = data.get("inventory")
    if inv:
        parts = []
        if "resources" in inv:
            parts.append(f'{esc(inv["resources"])} {L["resources_n"]}')
        if "files" in inv:
            parts.append(f'{esc(inv["files"])} {L["files_n"]}')
        if isinstance(inv.get("by_provider"), dict):
            parts.append(", ".join(f"{esc(k)} {esc(v)}" for k, v in inv["by_provider"].items()))
        rows.append((L["inventory"], " · ".join(parts)))
        if inv.get("not_run"):
            rows.append((L["not_run"], "<br>".join(esc(x if isinstance(x, str) else json.dumps(x, ensure_ascii=False))
                                                   for x in inv["not_run"])))
    return "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows)


TOKENS = """
:root{color-scheme:light;--bg:#f6f5f1;--panel:#fff;--text:#1b1b1b;--muted:#5b5b5b;--line:#dcd9d2;--soft:#ecebe5;--high:#9b1c1c;--medium:#8a5300;--low:#24476e;--info:#5b5b5b;--accent:#1f4f7a;--ok:#2d6a3e}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;--bg:#16171a;--panel:#1f2024;--text:#ece9e2;--muted:#b0aba2;--line:#38383c;--soft:#2a2b30;--high:#f2a19a;--medium:#e8bf7a;--low:#a9c3e6;--info:#b0aba2;--accent:#9cc3ec;--ok:#9fd3ad}}
:root[data-theme="dark"]{color-scheme:dark;--bg:#16171a;--panel:#1f2024;--text:#ece9e2;--muted:#b0aba2;--line:#38383c;--soft:#2a2b30;--high:#f2a19a;--medium:#e8bf7a;--low:#a9c3e6;--info:#b0aba2;--accent:#9cc3ec;--ok:#9fd3ad}
"""

BASE_CSS = """
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.65 system-ui,-apple-system,"Hiragino Sans","Noto Sans JP",sans-serif;overflow-wrap:anywhere}
a{color:var(--accent)}code,.snippet{font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}
.muted,.note{color:var(--muted)}
.High{color:var(--high)}.Medium{color:var(--medium)}.Low{color:var(--low)}.Info{color:var(--info)}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.06em;white-space:nowrap}
.pill{font-size:11px;font-weight:700;border:1px solid currentColor;border-radius:999px;padding:0 8px}
.st-open .pill,.pill.st-open{color:var(--high)}.pill.st-blocked{color:var(--ok)}.pill.st-unknown{color:var(--medium)}
.snippet{margin:0;padding:8px 10px;border-left:2px solid var(--line);overflow-x:auto;white-space:pre}
.snippet span{display:block}.snippet .hit{background:var(--soft)}.snippet b{color:var(--muted);font-weight:400}
dl{display:grid;grid-template-columns:150px minmax(0,1fr);gap:6px 16px;margin:10px 0}
dt{color:var(--muted);font-size:12px}dd{margin:0;white-space:pre-wrap;min-width:0}
.ap{border-top:2px solid var(--line);padding:12px 0}.ap.st-open{border-top-color:var(--high)}.ap.st-blocked{border-top-color:var(--ok)}.ap.st-unknown{border-top-color:var(--medium)}
.ap-head{display:flex;gap:10px;align-items:center}.ap-route{font-weight:650;margin:6px 0}
.edges{margin:6px 0;padding-left:22px}.edges li{margin:2px 0}
"""

DASH_CSS = """
main{max-width:1240px;margin:auto;padding:28px 16px 48px}
.masthead{display:flex;justify-content:space-between;align-items:center;gap:12px;border-bottom:1.5px solid var(--text);padding-bottom:14px}
.brand{font-size:11px;letter-spacing:.2em;color:var(--muted);font-weight:700}
.tools{display:flex;gap:8px;flex-wrap:wrap}
button,.button,select,input{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:4px;padding:7px 11px;text-decoration:none}
button{cursor:pointer}button:hover,.button:hover{background:var(--soft)}:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
h1{font-size:clamp(24px,3.4vw,34px);margin:20px 0 4px;line-height:1.25}h2{font-size:18px;margin:32px 0 10px}
.meta{color:var(--muted);margin:0}
.banner{border-top:1px solid var(--text);border-bottom:1px solid var(--text);padding:12px 2px;margin:18px 0;font-weight:650}
.cards{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:20px}
.card{border-top:2px solid currentColor;padding:8px 2px}.card .n{font-size:32px;line-height:1.2}.card .l{font-size:11px;letter-spacing:.08em;color:var(--muted);display:block}
.aps{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,360px),1fr));gap:18px}
.filters{display:grid;grid-template-columns:repeat(4,minmax(0,1fr)) 2fr;gap:10px}
.filters label{display:flex;flex-direction:column;gap:3px;font-size:12px;color:var(--muted)}.filters select,.filters input{width:100%;min-width:0}
.count{font-size:12px;color:var(--muted);margin:8px 0}
.tablewrap{border-top:1.5px solid var(--text);border-bottom:1.5px solid var(--text)}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:11px;letter-spacing:.05em;color:var(--muted)}
tr.excluded td{opacity:.6}
.toggle{border:0;background:none;padding:0;text-align:left;font-weight:650;width:100%}.toggle:hover{background:none;color:var(--accent)}
.loc{display:block;font-size:11px;color:var(--muted)}
tr.detail>td{background:var(--soft);padding:14px 18px}
.detail-actions{display:flex;justify-content:flex-end}
.coverage{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,280px),1fr));gap:4px 24px}
.persp{border-bottom:1px solid var(--line);padding:8px 0}.persp p{margin:2px 0;font-size:13px;color:var(--muted)}
.persp .st{font-size:11px;font-weight:700;margin-left:6px}
.lists{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,260px),1fr));gap:20px}
.lists ul{padding-left:18px;margin:6px 0}
.footer{border-top:1.5px solid var(--text);margin-top:36px;padding-top:12px;font-size:12px;color:var(--muted)}
@media(max-width:760px){.cards{grid-template-columns:repeat(2,minmax(0,1fr))}.filters{grid-template-columns:1fr 1fr}.filters .search{grid-column:1/-1}
thead{display:none}table,tbody,tr,td{display:block}tr.row{display:grid;grid-template-columns:1fr 1fr;gap:4px 10px;padding:10px 0;border-bottom:1px solid var(--line)}
tr.row td{border:0;padding:0}tr.row td.t{grid-column:1/-1}td[data-l]:before{content:attr(data-l);display:block;font-size:10px;color:var(--muted)}
dl{grid-template-columns:1fr}dd{margin-bottom:6px}}
@media screen{tr[hidden]{display:none!important}}
@media print{.tools,.filters,.detail-actions{display:none}tr.detail{display:table-row!important}}
"""

DASH_JS = r"""
(function(){
var root=document.documentElement;
try{var t=localStorage.getItem('infra-scan-theme');if(t)root.setAttribute('data-theme',t);}catch(e){}
document.getElementById('theme').addEventListener('click',function(){
  var dark=root.getAttribute('data-theme')==='dark'||(!root.getAttribute('data-theme')&&matchMedia('(prefers-color-scheme: dark)').matches);
  var next=dark?'light':'dark';root.setAttribute('data-theme',next);
  try{localStorage.setItem('infra-scan-theme',next);}catch(e){}
});
var md=JSON.parse(document.getElementById('md').textContent);
var rows=[].slice.call(document.querySelectorAll('tr.row'));
var f={sev:document.getElementById('f-sev'),prov:document.getElementById('f-prov'),cat:document.getElementById('f-cat'),ver:document.getElementById('f-ver'),q:document.getElementById('f-q')};
var count=document.getElementById('count');
function apply(){
  var q=f.q.value.trim().toLowerCase(),n=0;
  rows.forEach(function(r){
    var ok=(!f.sev.value||r.dataset.sev===f.sev.value)&&(!f.prov.value||r.dataset.prov===f.prov.value)&&
      (!f.cat.value||r.dataset.cat===f.cat.value)&&(!f.ver.value||r.dataset.ver===f.ver.value)&&
      (!q||r.dataset.text.indexOf(q)>=0);
    r.hidden=!ok;var d=r.nextElementSibling;if(!ok)d.hidden=true;else if(r.querySelector('.toggle').getAttribute('aria-expanded')==='true')d.hidden=false;
    if(ok)n++;
  });
  count.textContent=n+' / '+rows.length+' '+count.dataset.l;
}
Object.keys(f).forEach(function(k){f[k].addEventListener('input',apply);});
document.querySelectorAll('.toggle').forEach(function(b){b.addEventListener('click',function(){
  var open=b.getAttribute('aria-expanded')==='true';b.setAttribute('aria-expanded',String(!open));
  b.closest('tr').nextElementSibling.hidden=open;
});});
document.querySelectorAll('.copy').forEach(function(b){b.addEventListener('click',function(){
  var text=md[b.dataset.id],done=function(){var o=b.textContent;b.textContent=b.dataset.done;setTimeout(function(){b.textContent=o;},1500);};
  if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).then(done,fallback);}else fallback();
  function fallback(){var ta=document.createElement('textarea');ta.value=text;document.body.appendChild(ta);ta.select();try{document.execCommand('copy');done();}catch(e){}ta.remove();}
});});
if(location.hash){var el=document.getElementById(location.hash.slice(1));if(el&&el.classList.contains('row')){el.querySelector('.toggle').click();}}
apply();
})();
"""


def options(values, L, lang):
    return f'<option value="">{L["all"]}</option>' + "".join(
        f'<option value="{esc(v)}">{esc(shown(v, lang))}</option>' for v in values)


def render_dashboard(data, L, lang, sources):
    meta = data.get("meta", {})
    c = counts(data)
    fs = ordered(data.get("findings", []))
    md = {f["id"]: finding_markdown(f, L, lang) for f in fs}
    # Escape every markup character: "<!--<script>" in a finding would
    # otherwise keep the real </script> from closing this block.
    md_json = (json.dumps(md, ensure_ascii=False).replace("<", "\\u003c")
               .replace(">", "\\u003e").replace("&", "\\u0026"))
    banner = " · ".join(f"{shown(s, lang)} {c[s]}" for s in SEVERITIES) + \
        f" — {L['excluded_n']} {c['excluded']}, {L['unverified_n']} {c['unverified']}"
    cards = "".join(f'<div class="card {s}"><span class="l">{esc(shown(s, lang))}</span><span class="n">{c[s]}</span></div>'
                    for s in SEVERITIES)
    aps = "".join(ap_html(a, L, lang) for a in data.get("attack_paths", [])) or f'<p class="muted">{L["none"]}</p>'
    rows = []
    for f in fs:
        val = f.get("validation", {}).get("verdict", "")
        text = " ".join(str(x) for x in (f.get("id"), f.get("title"), f.get("location"), " ".join(f.get("resources", [])),
                                         f.get("rule", ""), f.get("category"))).lower()
        cls = "row excluded" if is_excluded(f) else "row"
        rows.append(
            f'<tr class="{cls}" id="{esc(f["id"])}" data-sev="{esc(f.get("severity"))}" data-prov="{esc(f.get("provider"))}" '
            f'data-cat="{esc(f.get("category"))}" data-ver="{esc(val)}" data-text="{esc(text)}">'
            f'<td data-l="{L["severity"]}"><span class="badge {esc(f.get("severity"))}">{esc(shown(f.get("severity"), lang))}</span></td>'
            f'<td data-l="{L["id"]}">{esc(f["id"])}</td>'
            f'<td class="t"><button class="toggle" type="button" aria-expanded="false">{esc(f.get("title"))}</button>'
            f'<span class="loc">{esc(f.get("location"))}</span></td>'
            f'<td data-l="{L["provider"]}">{esc(f.get("provider"))}</td>'
            f'<td data-l="{L["category"]}">{esc(f.get("category"))}</td>'
            f'<td data-l="{L["confidence"]}">{esc(shown(f.get("confidence"), lang))}</td>'
            f'<td data-l="{L["verdict"]}">{esc(shown(val, lang))}</td></tr>'
            f'<tr class="detail" hidden><td colspan="7">{detail_dl(f, L, lang, sources)}'
            f'<div class="detail-actions"><button class="copy" type="button" data-id="{esc(f["id"])}" '
            f'data-done="{esc(L["copied"])}">{L["copy"]}</button></div></td></tr>')
    table = "".join(rows) or f'<tr><td colspan="7" class="muted">{L["none"]}</td></tr>'
    names = perspective_names()
    present = {p.get("name"): p for p in data.get("perspectives", [])}
    persp = "".join(
        f'<div class="persp"><strong>{esc(n)}</strong><span class="st">{esc(shown(present[n].get("status"), lang)) if n in present else "—"}</span>'
        f'<p>{esc(present.get(n, {}).get("note", ""))}</p></div>' for n in names)
    used = lambda key: sorted({f.get(key) for f in fs if f.get(key)})
    lists = "".join(f'<section><h2>{L[k]}</h2>{list_block(data.get(k, []), L)}</section>' for k in STRING_LISTS)
    title = f'{L["doc_title"]} — {meta.get("project", "")}'
    return f"""<!doctype html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(title)}</title><style>{TOKENS}{BASE_CSS}{DASH_CSS}</style></head>
<body><main>
<header class="masthead"><span class="brand">{L["brand"]}</span><div class="tools">
<a class="button" href="assessment.html">{L["assessment"]}</a><button id="theme" type="button">{L["theme"]}</button></div></header>
<h1>{esc(meta.get("project", ""))}</h1>
<p class="meta">{esc(meta.get("scope", ""))} · {esc(meta.get("date", ""))} · {esc(meta.get("assessor", ""))}{(" · " + esc(meta["commit"][:12])) if meta.get("commit") else ""}</p>
<p class="banner">{esc(banner)}</p>
<div class="cards">{cards}</div>
<h2>{L["attack_paths"]}</h2><div class="aps">{aps}</div>
<h2 id="findings-h">{L["findings"]}</h2>
<div class="filters">
<label>{L["severity"]}<select id="f-sev">{options(SEVERITIES, L, lang)}</select></label>
<label>{L["provider"]}<select id="f-prov">{options(used("provider"), L, lang)}</select></label>
<label>{L["category"]}<select id="f-cat">{options(used("category"), L, lang)}</select></label>
<label>{L["verdict"]}<select id="f-ver">{options(VERDICTS, L, lang)}</select></label>
<label class="search">{L["search"]}<input id="f-q" type="search"></label>
</div>
<p class="count" id="count" data-l="{L["shown"]}"></p>
<div class="tablewrap"><table aria-labelledby="findings-h"><thead><tr><th>{L["severity"]}</th><th>{L["id"]}</th><th>{L["title"]}</th>
<th>{L["provider"]}</th><th>{L["category"]}</th><th>{L["confidence"]}</th><th>{L["verdict"]}</th></tr></thead>
<tbody>{table}</tbody></table></div>
<h2>{L["perspectives"]}</h2><div class="coverage">{persp}</div>
<div class="lists">{lists}</div>
<footer class="footer">{L["static_note"]}</footer>
</main>
<script type="application/json" id="md">{md_json}</script>
<script>{DASH_JS}</script>
</body></html>
"""


REPORT_CSS = """
@page{size:A4;margin:18mm 16mm}
body{font-family:"Hiragino Mincho ProN","Noto Serif CJK JP","Yu Mincho",Georgia,serif;font-size:11pt;line-height:1.7;max-width:900px;margin:auto;padding:24px 16px}
h1,h2,h3{line-height:1.3}h2{border-bottom:1.5px solid var(--text);padding-bottom:4px;margin-top:28px;break-after:avoid}
h3{margin:18px 0 4px;break-after:avoid}
.cover{min-height:60vh;display:flex;flex-direction:column;justify-content:center;border-bottom:2px solid var(--text);margin-bottom:24px;break-after:page}
.cover h1{font-size:28pt;margin:0 0 8px}.cover .sub{font-size:15pt}
table{border-collapse:collapse;width:100%;margin:8px 0}th,td{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{font-family:system-ui,sans-serif;font-size:9pt;color:var(--muted)}
.finding{break-inside:avoid-page;border-top:1px solid var(--line);padding-top:6px}
.finding.excluded{opacity:.75}
dt{font-family:system-ui,sans-serif}
@media print{body{max-width:none;padding:0;background:#fff;color:#000}a{color:inherit}}
"""


def render_assessment(data, L, lang, sources, pdf_note=""):
    meta = data.get("meta", {})
    c = counts(data)
    fs = ordered(data.get("findings", []))
    active = [f for f in fs if not is_excluded(f)]
    excluded = [f for f in fs if is_excluded(f)]

    def article(f, cls="finding"):
        return (f'<article class="{cls}" id="{esc(f["id"])}"><h3><span class="badge {esc(f.get("severity"))}">'
                f'{esc(shown(f.get("severity"), lang))}</span> {esc(f["id"])} {esc(f.get("title"))}</h3>'
                f'<p class="muted">{esc(f.get("category"))} · {esc(f.get("provider"))} · {esc(shown(f.get("confidence"), lang))}</p>'
                f'{detail_dl(f, L, lang, sources)}</article>')

    by_sev = "".join(
        f'<h3>{esc(shown(s, lang))}</h3>' + "".join(article(f) for f in active if f.get("severity") == s)
        for s in SEVERITIES if any(f.get("severity") == s for f in active)) or f'<p class="muted">{L["none"]}</p>'
    excl = "".join(article(f, "finding excluded") for f in excluded) or f'<p class="muted">{L["none"]}</p>'
    present = {p.get("name"): p for p in data.get("perspectives", [])}
    persp = "".join(f'<tr><td>{esc(n)}</td><td>{esc(shown(present[n].get("status"), lang)) if n in present else "—"}</td>'
                    f'<td>{esc(present.get(n, {}).get("note", ""))}</td></tr>' for n in perspective_names())
    count_rows = "".join(f'<tr><td class="{s}">{esc(shown(s, lang))}</td><td>{c[s]}</td></tr>' for s in SEVERITIES)
    aps = "".join(ap_html(a, L, lang) for a in data.get("attack_paths", [])) or f'<p class="muted">{L["none"]}</p>'
    sections = [
        (L["summary"], f'<p><strong>{" · ".join(f"{shown(s, lang)} {c[s]}" for s in SEVERITIES)}</strong> — '
                       f'{L["excluded_n"]} {c["excluded"]}, {L["unverified_n"]} {c["unverified"]}</p>'
                       f'<table><caption class="muted">{L["counts"]}</caption>{count_rows}</table><p>{L["static_note"]}</p>'
                       + (f'<p class="muted">{esc(pdf_note)}</p>' if pdf_note else "")),
        (L["scope_method"], f"<dl>{meta_rows(data, L)}</dl>"),
        (L["attack_paths"], aps),
        (L["findings"], by_sev),
        (L["excluded"], excl),
        (L["perspectives"], f'<table><thead><tr><th>{L["category"]}</th><th>{L["status"]}</th><th>{L["note"]}</th></tr></thead>'
                            f'<tbody>{persp}</tbody></table>'),
    ] + [(L[k], list_block(data.get(k, []), L)) for k in STRING_LISTS]
    body = "".join(f"<section><h2>{i}. {t}</h2>{b}</section>" for i, (t, b) in enumerate(sections, 1))
    return f"""<!doctype html>
<html lang="{lang}">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{esc(L["assessment"])} — {esc(meta.get("project", ""))}</title><style>{TOKENS}{BASE_CSS}{REPORT_CSS}</style></head>
<body>
<section class="cover"><p class="muted">{L["brand"]}</p><h1>{L["doc_title"]}</h1>
<p class="sub">{esc(meta.get("project", ""))}</p>
<dl>{"".join(f"<dt>{L[k]}</dt><dd>{esc(meta.get(k))}</dd>" for k in ("scope", "date", "assessor", "commit") if meta.get(k))}</dl>
<p class="muted">{L["cover_note"]}</p></section>
{body}
</body></html>
"""


def to_pdf(html_path, pdf_path, failed=None):
    """Print with Chrome or WeasyPrint; leave no PDF when neither succeeds.

    Engines that were found but did not produce a PDF are appended to `failed`.
    """
    failed = [] if failed is None else failed
    pdf = Path(pdf_path)
    pdf.unlink(missing_ok=True)
    chrome = os.environ.get("CHROME")
    # Chrome refuses to start its sandbox as root (containers, CI runners).
    # The page is a local file this script just wrote, not a remote site.
    sandbox = ["--no-sandbox"] if hasattr(os, "geteuid") and os.geteuid() == 0 else []
    for c in ([chrome] if chrome else CHROME_CANDIDATES):
        exe = c if os.path.isabs(c) and os.path.exists(c) else shutil.which(c)
        if not exe:
            continue
        with tempfile.TemporaryDirectory() as profile:
            try:
                proc = subprocess.Popen(
                    [exe, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", *sandbox,
                     f"--user-data-dir={profile}", f"--print-to-pdf={pdf}", Path(html_path).resolve().as_uri()],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError:
                continue
            # Chrome may keep running after writing: wait until the file stops growing.
            complete = False
            last, deadline = -1, time.monotonic() + 120
            while time.monotonic() < deadline:
                status = proc.poll()
                size = pdf.stat().st_size if pdf.exists() else -1
                if status is not None:
                    complete = status == 0 and size > 0
                    break
                if size > 0 and size == last:
                    complete = True
                    break
                last = size
                time.sleep(0.5)
            status = proc.poll()
            if status is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            elif status != 0:
                complete = False
        if complete and pdf.exists() and pdf.stat().st_size > 0:
            return "chrome"
        failed.append(f"{exe} (exit {status})" if status is not None else f"{exe} (timed out)")
        pdf.unlink(missing_ok=True)
    wp = shutil.which("weasyprint")
    if wp:
        try:
            r = subprocess.run([wp, str(html_path), str(pdf)], capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired):
            pass
        else:
            if r.returncode == 0 and pdf.exists() and pdf.stat().st_size > 0:
                return "weasyprint"
        failed.append(f"{wp}")
    pdf.unlink(missing_ok=True)
    return None


def output_problem(out, repo):
    """Refuse outputs inside the assessed repository or through symlinks."""
    if repo:
        root, target = Path(repo).resolve(), out.resolve()
        if target == root or root in target.parents:
            return f"{out} is inside the assessed repository {repo}; write outputs elsewhere"
    for name in ("dashboard.html", "assessment.html", "assessment.pdf"):
        if (out / name).is_symlink():
            return f"{out / name} is a symlink; refusing to write through it"
    return None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--no-pdf", action="store_true", help="skip PDF generation and remove any previous PDF")
    p.add_argument("--repo", help="assessed repository root: embeds redacted source excerpts for path:line locations")
    a = p.parse_args(argv)
    try:
        data = load(a.findings)
        validate(data)
    except SchemaError as e:
        for problem in e.problems:
            print(f"schema: {problem}", file=sys.stderr)
        return 2
    L = LABELS[a.lang]
    out = Path(a.out)
    problem = output_problem(out, a.repo)
    if problem:
        print(f"render: {problem}", file=sys.stderr)
        return 2
    sources = attach_sources(data, a.repo) if a.repo else {}
    out.mkdir(parents=True, exist_ok=True)
    pdf = out / "assessment.pdf"
    pdf.unlink(missing_ok=True)  # Previous findings must not survive an HTML-only render.
    (out / "dashboard.html").write_text(render_dashboard(data, L, a.lang, sources), encoding="utf-8")
    assessment = out / "assessment.html"
    assessment.write_text(render_assessment(data, L, a.lang, sources), encoding="utf-8")
    print(f"wrote {out / 'dashboard.html'}\nwrote {assessment}")
    if not a.no_pdf:
        failed = []
        engine = to_pdf(assessment, pdf, failed)
        if engine:
            print(f"wrote {pdf} ({engine})")
        else:
            note = L["pdf_failed"] if failed else L["pdf_missing"]
            assessment.write_text(render_assessment(data, L, a.lang, sources, note), encoding="utf-8")
            print(f"warning: {note}" + (f" Tried: {', '.join(failed)}" if failed else ""), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
