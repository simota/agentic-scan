#!/usr/bin/env python3
"""Render findings.json into dashboard.html, report.html and report.pdf.

    python3 render.py FINDINGS --out DIR [--lang ja|en] [--repo REPO] [--no-pdf]

With --repo, each finding's `location` excerpt is embedded: read from the blob
at `meta.commit` when the record names one and the tree was known clean at scan time
(never from later working-tree edits), otherwise from the working tree. A file with a
`filter` attribute (git-crypt, Git LFS) is always read from the working tree: its blob
holds what the clean command stored, and no repository command is run to undo that.
Credential-shaped values in excerpts are masked, private-key blocks whole, and so
are single-token values (quoted ones without spaces) assigned to credential-named
keys (`password=`, `SECRET_KEY:`, `"api_key" =>`, `const DB_PASSWORD =`, `API_KEY: str =`,
`password :=`, `ENV API_TOKEN=`) and URL passwords; `.env*`, `*.env`, key files (.pem, .key, .p12, .pfx,
.jks, .keystore) and login files (.npmrc, .pypirc, .netrc, id_rsa...) get no excerpt.
--lang defaults to `meta.lang`, else ja. Styles, PDF printing and safe writes come from the vendored
scan-report-kit (scan_report_kit/): the PDF is printed by headless
Chrome/Chromium (CHROME overrides the path), else WeasyPrint, each within
PROMPT_SCAN_PDF_TIMEOUT seconds (default: 120 plus 0.05 per finding, at most 900).

Exit codes: 0 written, 2 unreadable input or schema error, 3 HTML written but
no PDF (no engine, or the engine failed; the message says which).
"""
import argparse
from collections import Counter
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys

# The kit sits next to this script; -I and PYTHONSAFEPATH leave the script's directory off sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from scan_report_kit import pdf as kit_pdf, style as kit_style  # noqa: E402
from scan_report_kit.output import unsafe_target, write_output  # noqa: E402

SEVERITIES = ["High", "Medium", "Low", "Info"]
CONFIDENCES = ["Confirmed", "Model-dependent", "Suspected"]
KINDS = ["defect", "improvement"]
STATUSES = ["Open", "Fixed", "Accepted"]
VERDICTS = ["Valid", "Likely", "Unverified", "Unlikely", "FalsePositive", "NotApplicable"]
EXCLUDED = {"FalsePositive", "NotApplicable"}
PROMPT_KINDS = ["system", "template", "few-shot", "tool", "agent", "skill", "other"]
RESULTS = ["applied", "N/A", "not checked"]
TOP_KEYS = {"schema_version", "meta", "prompts", "findings", "eval_runs", "perspectives",
            "checked_ok", "decisions", "limitations", "next_steps"}
STRING_LISTS = ("checked_ok", "decisions", "limitations", "next_steps")
FINDING_ID = re.compile(r"[FL]-[0-9]{3,}")
PROMPT_ID = re.compile(r"P-[0-9]{2,3}")
EVAL_ID = re.compile(r"E-[0-9]{3}")
LOC_RE = re.compile(r"^(?P<path>[^:\s][^:]*):(?P<start>[0-9]+)(?:-(?P<end>[0-9]+))?$")
SECRET_RE = re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}|\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|"
                       r"\bgh[pousr]_[A-Za-z0-9]{36,}|\bgithub_pat_[A-Za-z0-9_]{22,}|\bglpat-[A-Za-z0-9_-]{20,}|"
                       r"\bhf_[A-Za-z0-9]{30,}|\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}|"
                       r"\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAIza[0-9A-Za-z_-]{35}|"
                       r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")
# Values with no recognisable format sit next to ones that have one (an AWS secret key under its key id):
# an excerpt masks the value assigned to a credential-named key, and the password in a URL. A key starts a
# line (after indent, `- ` or declaration keywords such as `export const`, `private static final String`,
# `ENV`) or follows { ( [ , ; & ?, so prose ("asks for the password: no") is left alone. It is assigned
# with =, :, =>, := or a type annotation (`API_KEY: str =`). The value is one token or a quoted string
# without spaces; a number, None/null/true/false, a template variable or an unquoted call is not a secret.
# Every run is bounded, so long lines stay linear.
DECLARATION = r"(?:export|const|let|var|val|final|static|readonly|private|public|protected|internal|ENV|String|string|str)"
ASSIGNED_SECRET_RE = re.compile(
    r"""(?im)((?:^[ \t]{0,64}(?P<decl>(?:-[ \t]+|(?-i:""" + DECLARATION + r""")[ \t]+){0,4})|[{(\[,;&?][ \t]{0,8})["']?"""
    r"""[\w.-]{0,64}?"""
    r"""(?:secret|passw(?:or)?d|passwd|pwd|token|api[_-]?key|access[_-]?key|private[_-]?key|credentials?)"""
    r"""(?:[_-][A-Za-z0-9]{1,16}){0,2}["']?\]?[ \t]{0,8}"""
    r"""(?P<op>=>|:=|[:=]|:[ \t]{0,8}[A-Za-z_][\w.\[\]]{0,40}[ \t]{0,8}=)[ \t]{0,8})"""
    r"""(?!(?:-?[0-9]+(?:\.[0-9]+)?|None|null|nil|true|false|undefined)[ \t]*(?:[,;#&)\]}]|$)|["']?[{$<%])"""
    r"""(?P<value>"[^"\s]{1,256}"|'[^'\s]{1,256}'|[^\s"',;#&)\]}]{1,256})(?=[ \t]*(?:[,;#&)\]}]|$))""")
# The password runs to the last @ before the host, so one that holds an @ or a / is masked whole.
URL_PASSWORD_RE = re.compile(r"((?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{0,31}://[^\s:/@]{0,256}:)(\S{1,256})"
                             r"(?=@[^\s@/]{0,256}(?:[/?#\s]|$))")
# Files that hold credentials by convention: inventory.py never reads them, and no excerpt quotes them.
SENSITIVE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore"}
SENSITIVE_NAMES = {".npmrc", ".pypirc", ".netrc", "_netrc", ".pgpass", ".htpasswd", ".git-credentials",
                   "credentials", "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"}
# A whole private-key block, so masking it also hides the key body lines (an unterminated block runs to the end).
KEY_BLOCK_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
                          re.S)
MAX_JSON_DEPTH = 100
STAMP = '<meta name="prompt-scan-source" content="sha256:{}">'

LABELS = {
    "en": {
        "title": "Prompt review report", "dashboard": "Prompt review dashboard",
        "target": "Target", "commit": "Revision", "dirty": "uncommitted changes present",
        "dirty_unknown": "uncommitted changes not determined", "date": "Date",
        "assessor": "Assessor", "scope": "Scope", "abstract": "Summary",
        "summary_line": "{total} findings ({defects} defects, {improvements} improvements); "
                        "{high} High, {medium} Medium. {excluded} excluded with evidence.",
        "table_counts": "Findings by severity and kind",
        "running_footer": "PROMPT REVIEW", "cap_inventory": "Prompts in scope",
        "cap_perspectives": "Coverage by perspective", "cap_evals": "Eval runs against findings",
        "severity": "Severity", "kind": "Kind", "total": "Total",
        "defect": "Defect", "improvement": "Improvement",
        "s_inventory": "Prompt inventory", "s_perspectives": "Perspectives", "s_findings": "Findings",
        "s_sound": "Checked and sound", "s_evals": "Eval runs", "s_decisions": "Decisions for a human",
        "s_limitations": "Limitations", "s_next": "Next steps",
        "id": "ID", "name": "Name", "location": "Location", "consumer": "Consumer", "model": "Model",
        "inputs": "Inputs", "output": "Output", "result": "Result", "note": "Note", "perspective": "Perspective",
        "prompt": "Prompt", "confidence": "Confidence", "verdict": "Verdict", "status": "Status",
        "symptom": "Symptom", "cause": "Cause", "impact": "Impact", "fix": "Fix direction",
        "proposal": "Proposal", "before": "Before", "after": "After", "test": "Eval / test assertion",
        "evidence": "Verdict evidence", "references": "References", "excerpt": "Excerpt",
        "previous": "Earlier review (before rescan)", "source": "Source",
        "cases": "Cases", "passed": "Passed", "failed": "Failed", "finding": "Finding",
        "none": "None recorded.", "all": "All", "search": "Search", "excluded": "Excluded",
        "no_match": "No finding matches the filters.",
        "kinds": {"defect": "Defect", "improvement": "Improvement"},
        "results": {"applied": "applied", "N/A": "N/A", "not checked": "not checked"},
    },
    "ja": {
        "title": "プロンプト診断レポート", "dashboard": "プロンプト診断ダッシュボード",
        "target": "対象", "commit": "リビジョン", "dirty": "未コミットの変更あり",
        "dirty_unknown": "未コミットの変更は未確認", "date": "診断日",
        "assessor": "診断者", "scope": "範囲", "abstract": "要旨",
        "summary_line": "指摘 {total} 件（不具合 {defects} 件、改善提案 {improvements} 件）。"
                        "High {high} 件、Medium {medium} 件。根拠付きで除外 {excluded} 件。",
        "table_counts": "深刻度と種別ごとの指摘数",
        "running_footer": "プロンプト診断", "cap_inventory": "対象プロンプト",
        "cap_perspectives": "観点ごとの確認結果", "cap_evals": "指摘ごとの評価実行",
        "severity": "深刻度", "kind": "種別", "total": "合計",
        "defect": "不具合", "improvement": "改善提案",
        "s_inventory": "プロンプト一覧", "s_perspectives": "観点", "s_findings": "指摘",
        "s_sound": "確認して問題がなかった項目", "s_evals": "評価の実行記録", "s_decisions": "判断が必要な事項",
        "s_limitations": "制約事項", "s_next": "次のステップ",
        "id": "ID", "name": "名前", "location": "場所", "consumer": "利用箇所", "model": "モデル",
        "inputs": "入力", "output": "出力先", "result": "結果", "note": "備考", "perspective": "観点",
        "prompt": "プロンプト", "confidence": "確度", "verdict": "検証判定", "status": "状態",
        "symptom": "症状", "cause": "原因", "impact": "影響", "fix": "修正方針",
        "proposal": "改善案", "before": "現在", "after": "提案", "test": "評価・テストの確認内容",
        "evidence": "判定の根拠", "references": "参考資料", "excerpt": "抜粋",
        "previous": "再スキャン前のレビュー", "source": "出所",
        "cases": "ケース数", "passed": "成功", "failed": "失敗", "finding": "指摘",
        "none": "記録なし。", "all": "すべて", "search": "検索", "excluded": "除外",
        "no_match": "条件に合う指摘はありません。",
        "kinds": {"defect": "不具合", "improvement": "改善提案"},
        "results": {"applied": "実施", "N/A": "対象外", "not checked": "未確認"},
    },
}


class SchemaError(Exception):
    pass


def json_depth(value):
    depth, pending = 0, [(value, 1)]
    while pending:
        item, level = pending.pop()
        if isinstance(item, (dict, list)):
            depth = max(depth, level)
            if level > MAX_JSON_DEPTH:
                return level
            pending.extend((child, level + 1) for child in (item.values() if isinstance(item, dict) else item))
    return depth


def _str(obj, key, where, required=False):
    value = obj.get(key)
    if value is None and not required:
        return
    if not isinstance(value, str) or (required and not value.strip()):
        raise SchemaError(f"{where}.{key} must be a {'nonblank ' if required else ''}string")


def _enum(obj, key, allowed, where, required=True):
    if key not in obj and not required:
        return
    if obj.get(key) not in allowed:
        raise SchemaError(f"{where}.{key} must be one of {', '.join(allowed)}")


def validate_data(data):
    """Structural check of a findings.json object. Raises SchemaError."""
    if not isinstance(data, dict):
        raise SchemaError("report must be a JSON object")
    unknown = data.keys() - TOP_KEYS
    if unknown:
        raise SchemaError(f"unknown top-level keys {sorted(unknown)}")
    if data.get("schema_version", 1) != 1:
        raise SchemaError("schema_version must be 1")
    meta = data.get("meta", {})
    if not isinstance(meta, dict):
        raise SchemaError("meta must be an object")
    for key in ("target", "date", "assessor", "scope", "lang"):
        _str(meta, key, "meta")
    # Any other value would silently fall back to a Japanese report.
    if meta.get("lang") is not None and meta["lang"] not in LABELS:
        raise SchemaError(f"meta.lang must be one of {', '.join(sorted(LABELS))} "
                          '(findings.py merge a fragment {"meta": {"lang": ...}} to set it)')
    if meta.get("commit") is not None and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(meta["commit"])):
        raise SchemaError("meta.commit must be a full Git object id or null")
    if meta.get("dirty") is not None and not isinstance(meta["dirty"], bool):
        raise SchemaError("meta.dirty must be true, false or null")
    for key in ("prompts", "findings", "eval_runs", "perspectives", *STRING_LISTS):
        if not isinstance(data.get(key, []), list):
            raise SchemaError(f"{key} must be a list")
    for key in STRING_LISTS:
        if not all(isinstance(x, str) and x.strip() for x in data.get(key, [])):
            raise SchemaError(f"{key} entries must be nonblank strings")
    seen = set()
    for i, p in enumerate(data.get("prompts", [])):
        where = f"prompts[{i}]"
        if not isinstance(p, dict) or not PROMPT_ID.fullmatch(str(p.get("id", ""))):
            raise SchemaError(f"{where}.id must be P-NN")
        if p["id"] in seen:
            raise SchemaError(f"duplicate prompt id {p['id']}")
        seen.add(p["id"])
        _str(p, "name", where, True)
        _str(p, "location", where, True)
        _enum(p, "kind", PROMPT_KINDS, where)
        for key in ("consumer", "model", "inputs", "output"):
            _str(p, key, where)
    prompts = seen
    seen = set()
    for i, f in enumerate(data.get("findings", [])):
        if not isinstance(f, dict) or not FINDING_ID.fullmatch(str(f.get("id", ""))):
            raise SchemaError(f"findings[{i}].id must be F-NNN or L-NNN")
        where = f"findings[{f['id']}]"
        if f["id"] in seen:
            raise SchemaError(f"duplicate finding id {f['id']}")
        seen.add(f["id"])
        _enum(f, "kind", KINDS, where)
        _enum(f, "severity", SEVERITIES, where)
        _enum(f, "confidence", CONFIDENCES, where)
        _enum(f, "status", STATUSES, where, required=False)
        for key in ("title", "location", "category"):
            _str(f, key, where, True)
        if "\x00" in f["location"]:
            raise SchemaError(f"{where}.location must not contain a NUL character")
        for key in ("symptom", "cause", "impact", "fix", "source", "rule"):
            _str(f, key, where)
        test = f.get("test")
        if test is not None and not (isinstance(test, str) or (
                isinstance(test, list) and all(isinstance(t, str) for t in test))):
            raise SchemaError(f"{where}.test must be a string or a list of strings")
        refs = f.get("prompt")
        refs = [refs] if isinstance(refs, str) else refs
        if refs is not None and (not isinstance(refs, list) or any(not isinstance(r, str) or r not in prompts for r in refs)):
            raise SchemaError(f"{where}.prompt must name recorded prompt ids")
        proposal = f.get("proposal")
        if proposal is not None:
            if not isinstance(proposal, dict) or proposal.keys() - {"before", "after"}:
                raise SchemaError(f"{where}.proposal must be an object with before and after")
            for key in ("before", "after"):
                _str(proposal, key, f"{where}.proposal")
        for key in ("validation", "previous_validation"):
            v = f.get(key)
            if v is None and key == "previous_validation":
                continue
            if not isinstance(v, dict):
                raise SchemaError(f"{where}.{key} must be an object")
            _enum(v, "verdict", VERDICTS, f"{where}.{key}")
            _str(v, "evidence", f"{where}.{key}")
            _str(v, "method", f"{where}.{key}")
        if f["validation"]["verdict"] in {"Valid", *EXCLUDED} and not (f["validation"].get("evidence") or "").strip():
            raise SchemaError(f"{where}: verdict {f['validation']['verdict']} needs validation.evidence")
        if not isinstance(f.get("references", []), list):
            raise SchemaError(f"{where}.references must be a list")
        for j, ref in enumerate(f.get("references", [])):
            if not isinstance(ref, dict) or not re.match(r"https?://", str(ref.get("url", ""))):
                raise SchemaError(f"{where}.references[{j}] needs an http(s) url")
            _str(ref, "title", f"{where}.references[{j}]")
    findings = seen
    seen = set()
    for i, run in enumerate(data.get("eval_runs", [])):
        where = f"eval_runs[{i}]"
        if not isinstance(run, dict) or not EVAL_ID.fullmatch(str(run.get("id", ""))):
            raise SchemaError(f"{where}.id must be E-NNN")
        if run["id"] in seen:
            raise SchemaError(f"duplicate eval run id {run['id']}")
        seen.add(run["id"])
        if not isinstance(run.get("finding"), str) or run["finding"] not in findings:
            raise SchemaError(f"{where}.finding must name a recorded finding")
        if not run["finding"].startswith("F-"):
            raise SchemaError(f"{where}.finding must be an F-* id; L-* ids are reassigned on every rescan")
        for key in ("model", "date"):
            _str(run, key, where, True)
        _str(run, "note", where)
        for key in ("cases", "passed", "failed"):
            if not isinstance(run.get(key), int) or isinstance(run.get(key), bool) or run[key] < 0:
                raise SchemaError(f"{where}.{key} must be a nonnegative integer")
        if run["passed"] + run["failed"] > run["cases"]:
            raise SchemaError(f"{where}: passed + failed exceeds cases")
    for i, p in enumerate(data.get("perspectives", [])):
        where = f"perspectives[{i}]"
        if not isinstance(p, dict):
            raise SchemaError(f"{where} must be an object")
        _str(p, "name", where, True)
        _enum(p, "result", RESULTS, where)
        _str(p, "note", where)
    return data


def parse_json(raw, path):
    """Strict JSON: a duplicate key would silently drop a value, and NaN or Infinity (or a number that overflows to
    it) is not JSON a browser parses."""
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key {key!r}")
            result[key] = value
        return result

    def constant(name):
        raise ValueError(f"{name} is not a JSON value")

    def number(text):
        # 1e400 is valid JSON but overflows to inf, which json.dumps would write back as Infinity.
        value = float(text)
        if math.isinf(value):
            raise ValueError(f"{text} does not fit a double")
        return value
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=constant,
                           parse_float=number)
    except (UnicodeError, ValueError, RecursionError) as e:
        raise SchemaError(f"{path}: {e}") from None
    if json_depth(value) > MAX_JSON_DEPTH:
        raise SchemaError(f"{path}: JSON nesting deeper than {MAX_JSON_DEPTH} levels")
    try:
        # A \ud83d escape with no pair parses, but no output can encode it.
        json.dumps(value, ensure_ascii=False).encode("utf-8")
    except UnicodeEncodeError:
        raise SchemaError(f"{path}: a string holds a lone UTF-16 surrogate escape (\\ud800-\\udfff)") from None
    return value


def load(path, raw=None):
    try:
        raw = Path(path).read_bytes() if raw is None else raw
    except OSError as e:
        raise SchemaError(f"{path}: {e}") from None
    return validate_data(parse_json(raw, path))


def id_key(ident):
    """F-/L-/E- ids in numeric order, so F-1000 follows F-999."""
    prefix, _, number = ident.partition("-")
    return prefix, int(number) if number.isdigit() else 0


def ordered(findings):
    """Active findings by severity, then kind and id; excluded ones last."""
    return sorted(findings, key=lambda f: (f["validation"]["verdict"] in EXCLUDED, SEVERITIES.index(f["severity"]),
                                           KINDS.index(f["kind"]), id_key(f["id"])))


def counts(data):
    active = [f for f in data.get("findings", []) if f["validation"]["verdict"] not in EXCLUDED]
    by = Counter((f["severity"], f["kind"]) for f in active)
    return active, by


# ---------------------------------------------------------------- excerpts

def mask(text):
    return SECRET_RE.sub("[REDACTED]", text)


def mask_excerpt(line):
    """mask(), plus the values an excerpt's context lines carry without a recognisable format."""
    # Before mask(): its [REDACTED] would otherwise read as a value assigned to the key.
    def assigned(m):
        value = m["value"]
        # An unquoted value holding "(" is a call, a quoted one a literal whatever it holds; after a
        # declaration keyword a bare ":" starts a type (`let password: string`), not a value.
        if "(" in value and value[0] not in "\"'" or m["op"] == ":" and m["decl"] and m["decl"].strip("- \t"):
            return m.group(0)
        return m.group(1) + "[REDACTED]"
    line = ASSIGNED_SECRET_RE.sub(assigned, line)
    return mask(URL_PASSWORD_RE.sub(lambda m: m.group(1) + "[REDACTED]", line))


def mask_key_blocks(text):
    """Replace each private-key block line by line, so line numbers stay put."""
    return KEY_BLOCK_RE.sub(lambda m: "\n".join("[REDACTED]" for _ in m.group(0).split("\n")), text)


def source_lines(text):
    """Lines as editors and `path:line` count them: split on newline only.

    str.splitlines() also breaks at form feeds, U+2028 and other separators, which
    would shift every later line number.
    """
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [line[:-1] if line.endswith("\r") else line for line in lines]


def sensitive(name):
    """Whether a file name is one that holds credentials by convention (.env*, *.env, key and login files)."""
    lower = name.lower()
    return (lower.startswith(".env") or lower.endswith(".env") or lower in SENSITIVE_NAMES
            or Path(lower).suffix in SENSITIVE_SUFFIXES)


def git_in(repo):
    """git in the reviewed repository, never running its fsmonitor command (check-attr reads the index) and
    never writing its index, as inventory.py runs it."""
    return ["git", "--no-optional-locks", "-C", str(repo), "-c", "core.fsmonitor=false"]


def _source(repo, commit, rel):
    if Path(rel).is_absolute() or ".." in Path(rel).parts or sensitive(Path(rel).name):
        return None
    if commit:
        try:
            # A blob under a filter driver (git-crypt, LFS) is what the clean command stored, not the text the
            # scan read; the tree was clean, so the working-tree file is that text. check-attr runs no driver.
            attr = subprocess.run([*git_in(repo), "check-attr", "-z", "filter", "--", f"./{rel}"],
                                  capture_output=True, timeout=20)
            if attr.returncode != 0:
                return None
            if attr.stdout.split(b"\0")[2:3] in ([b"unspecified"], [b"unset"]):
                # "./" resolves the path against --repo, which may be a subdirectory of the Git work tree.
                r = subprocess.run([*git_in(repo), "show", f"{commit}:./{rel}"], capture_output=True,
                                   timeout=20)
                return r.stdout.decode("utf-8", errors="replace") if r.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired):
            return None
    root = Path(repo).resolve()
    path = (root / rel).resolve()
    if root not in path.parents or sensitive(path.name) or not path.is_file() or path.stat().st_size > 4 * 1024 * 1024:
        return None
    return path.read_text(encoding="utf-8", errors="replace")


def attach_sources(data, repo, context=3, limit=40):
    """Excerpts keyed by finding id: (first line number, lines, highlighted range)."""
    excerpts = {}
    if repo is None:
        return excerpts
    meta = data.get("meta", {})
    # Only a scan known to be clean reviewed the commit's blob; a dirty or undetermined one read the working tree.
    commit = meta.get("commit") if meta.get("dirty") is False else None
    cache = {}
    for f in data.get("findings", []):
        m = LOC_RE.match(f["location"])
        if not m:
            continue
        rel = m["path"]
        if rel not in cache:
            cache[rel] = _source(repo, commit, rel)
        text = cache[rel]
        if text is None:
            continue
        lines = source_lines(mask_key_blocks(text))
        start = int(m["start"])
        end = max(start, int(m["end"] or start))
        if start < 1 or start > len(lines):
            continue
        first = max(1, start - context)
        last = min(len(lines), end + context, first + limit - 1)
        excerpts[f["id"]] = (first, [mask_excerpt(line) for line in lines[first - 1:last]], (start, end))
    return excerpts


# ---------------------------------------------------------------- HTML helpers

def esc(value):
    return html.escape(str(value), quote=True)


def para(value):
    if isinstance(value, list):
        return "<ul>" + "".join(f"<li>{esc(v)}</li>" for v in value) + "</ul>"
    return f'<p class="prose">{esc(value)}</p>'


def snippet_html(excerpt):
    """A source excerpt as the kit's captioned listing: numbered lines, the cited range highlighted."""
    first, lines, (start, end) = excerpt
    rows = "".join(f'<span class="{"hit" if start <= first + i <= end else ""}"><b>{first + i:>4}</b>  {esc(line)}</span>'
                   for i, line in enumerate(lines))
    return f'<pre class="snippet">{rows}</pre>'


def revision(meta, L):
    """The short commit with the tree state at scan time, or None outside Git."""
    commit = meta.get("commit")
    if not commit:
        return None
    state = {True: L["dirty"], None: L["dirty_unknown"]}.get(meta.get("dirty"))
    return commit[:12] + (f" ({state})" if state else "")


def meta_lines(data, L):
    meta = data.get("meta", {})
    revision_text = revision(meta, L) or "—"
    rows = [(L["commit"], revision_text), (L["date"], meta.get("date") or "—"),
            (L["assessor"], meta.get("assessor") or "—"), (L["scope"], meta.get("scope") or "—")]
    return "".join(f'<p class="meta-line"><strong>{esc(k)}</strong><span>{esc(v)}</span></p>' for k, v in rows)


def counts_table(data, L):
    active, by = counts(data)
    head = "".join(f'<th scope="col" class="num">{esc(L[k])}</th>' for k in KINDS) + \
        f'<th scope="col" class="num">{esc(L["total"])}</th>'
    rows = []
    for s in SEVERITIES:
        cells = "".join(f'<td class="num">{by[(s, k)]}</td>' for k in KINDS)
        rows.append(f'<tr><th scope="row"><span class="badge {s}">{s}</span></th>{cells}'
                    f'<td class="num">{sum(by[(s, k)] for k in KINDS)}</td></tr>')
    totals = "".join(f'<td class="num">{sum(by[(s, k)] for s in SEVERITIES)}</td>' for k in KINDS)
    rows.append(f'<tr class="total"><th scope="row">{esc(L["total"])}</th>{totals}<td class="num">{len(active)}</td></tr>')
    return (f'<table class="counts"><caption>{esc(L["table_counts"])}</caption>'
            f'<thead><tr><th scope="col">{esc(L["severity"])}</th>{head}</tr></thead><tbody>{"".join(rows)}</tbody></table>')


def summary_line(data, L):
    active, by = counts(data)
    return L["summary_line"].format(
        total=len(active), defects=sum(1 for f in active if f["kind"] == "defect"),
        improvements=sum(1 for f in active if f["kind"] == "improvement"),
        high=sum(1 for f in active if f["severity"] == "High"),
        medium=sum(1 for f in active if f["severity"] == "Medium"),
        excluded=len(data.get("findings", [])) - len(active))


def finding_html(f, L, excerpts):
    """One finding entry in the kit's document vocabulary; its section number comes from CSS counters."""
    prompt = f.get("prompt")
    prompt = ", ".join(prompt) if isinstance(prompt, list) else prompt
    v = f["validation"]
    rows = [(L["severity"], f'<span class="badge {f["severity"]}">{f["severity"]}</span>'),
            (L["kind"], f'<span class="kind kind-{f["kind"]}">{esc(L["kinds"][f["kind"]])}</span>'),
            (L["location"], f'<code>{esc(f["location"])}</code>'),
            (L["prompt"], esc(prompt) if prompt else None),
            (L["perspective"], esc(f["category"])),
            (L["confidence"], esc(f["confidence"])),
            (L["verdict"], esc(v["verdict"]) + (f' <span class="muted">({esc(v["method"])})</span>'
                                                 if v.get("method") else "")),
            (L["status"], esc(f.get("status", "Open"))),
            (L["source"], esc(f["source"]) if f.get("source") else None)]
    state = "".join(f'<tr><th scope="row">{esc(k)}</th><td>{val}</td></tr>' for k, val in rows if val)
    fields = []
    for key in ("symptom", "cause", "impact", "fix"):
        if f.get(key):
            fields.append((L[key], para(f[key])))
    proposal = f.get("proposal")
    if proposal:
        fields.append((L["proposal"], '<div class="proposal">'
                       f'<figure><figcaption>{esc(L["before"])}</figcaption><pre>{esc(proposal.get("before", ""))}</pre></figure>'
                       f'<figure><figcaption>{esc(L["after"])}</figcaption><pre>{esc(proposal.get("after", ""))}</pre></figure>'
                       "</div>"))
    if f.get("test"):
        fields.append((L["test"], para(f["test"])))
    if v.get("evidence"):
        fields.append((L["evidence"], para(v["evidence"])))
    if f.get("previous_validation"):
        pv = f["previous_validation"]
        fields.append((L["previous"], para(pv["verdict"] + ": " + (pv.get("evidence") or ""))))
    if f["id"] in excerpts:
        fields.append((L["excerpt"], snippet_html(excerpts[f["id"]])))
    if f.get("references"):
        items = "".join(f'<li><a href="{esc(r["url"])}" rel="noopener noreferrer">{esc(r.get("title") or r["url"])}</a></li>'
                        for r in f["references"])
        fields.append((L["references"], f'<ul class="refs">{items}</ul>'))
    body = "".join(f'<div class="finding-field"><h4>{esc(k)}</h4>{content}</div>' for k, content in fields)
    cls = "finding excluded" if v["verdict"] in EXCLUDED else f'finding sev-{f["severity"]}'
    return (f'<article class="{cls}" id="{esc(f["id"])}"><div class="finding-header">'
            f'<span class="finding-id">{esc(f["id"])}</span><h3>{esc(f["title"])}</h3>'
            f'<table class="finding-state"><tbody>{state}</tbody></table></div>{body}</article>')


def list_section(items, L):
    return "<ul>" + "".join(f"<li>{esc(x)}</li>" for x in items) + "</ul>" if items else f'<p class="small">{esc(L["none"])}</p>'


# The shared stylesheet (scan_report_kit/assets/document.css, design: scan-report-kit)
# comes first; these add only the rules for prompt-scan record types: the
# severity-by-kind counts table, the prompt inventory and eval-run tables, the
# kind label and before/after proposals.
REPORT_CSS = """
.num{text-align:right}
.counts .badge{margin:0}
.counts tbody th{border-bottom:0;font-weight:400}
.counts tbody tr+tr th{border-top:.3pt solid var(--hair)}
.counts tr.total th,.counts tr.total td{font-weight:700;border-top:.6pt solid var(--rule)}
.inv .id-col{width:8%}.evals .id-col{width:9%}
.inv .name-col{width:20%}.inv .kind-col{width:11%}.inv .loc-col{width:20%}.inv .consumer-col{width:17%}.inv .model-col{width:24%}
.evals .finding-col{width:10%}.evals .model-col{width:18%}.evals .date-col{width:13%}.evals .num-col{width:8%}.evals .note-col{width:26%}
.fid{font:7.8pt/1.5 var(--mono);white-space:nowrap}
.inv code{font-size:7.6pt}
.kind{font:7.2pt/1.5 var(--sans);letter-spacing:.06em;color:var(--muted);border:.5pt solid var(--hair);padding:0 1.5mm;border-radius:.6mm;white-space:nowrap}
.muted{color:var(--muted)}
.finding.excluded h3{color:var(--muted);text-decoration:line-through}
.proposal{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:4mm}
.proposal figure{margin:0;min-width:0}
.proposal figcaption{font:700 7.4pt/1.4 var(--sans);letter-spacing:.06em;color:var(--muted);margin-bottom:1mm}
.proposal pre{margin:0;padding:1.5mm 0 1.5mm 3mm;border-left:.6pt solid var(--rule);font:7.6pt/1.55 var(--mono);white-space:pre-wrap;overflow-wrap:anywhere;word-wrap:break-word;word-break:break-all}
@media screen and (max-width:600px){.proposal{grid-template-columns:minmax(0,1fr)}.inv,.evals{table-layout:auto}}
"""


def table_or_none(rows, html_table, L):
    return html_table if rows else f'<p class="small">{esc(L["none"])}</p>'


def render_report_html(data, L, lang, excerpts):
    findings = ordered(data.get("findings", []))
    prompts = data.get("prompts", [])
    prompt_rows = "".join(
        f'<tr><td class="fid">{esc(p["id"])}</td><td>{esc(p["name"])}</td><td>{esc(p.get("kind", ""))}</td>'
        f'<td><code>{esc(p["location"])}</code></td><td><code>{esc(p.get("consumer", ""))}</code></td>'
        f'<td>{esc(p.get("model", ""))}</td></tr>' for p in prompts)
    prompt_table = table_or_none(prompts, (
        f'<table class="inv"><caption>{esc(L["cap_inventory"])}</caption><colgroup><col class="id-col"><col class="name-col">'
        '<col class="kind-col"><col class="loc-col"><col class="consumer-col"><col class="model-col"></colgroup>'
        f'<thead><tr><th scope="col">{L["id"]}</th><th scope="col">{L["name"]}</th><th scope="col">{L["kind"]}</th>'
        f'<th scope="col">{L["location"]}</th><th scope="col">{L["consumer"]}</th><th scope="col">{L["model"]}</th></tr></thead>'
        f'<tbody>{prompt_rows}</tbody></table>'), L)
    persp_rows = "".join(
        f'<tr><td>{esc(p["name"])}</td><td>{esc(L["results"][p["result"]])}</td><td>{esc(p.get("note", ""))}</td></tr>'
        for p in data.get("perspectives", []))
    persp_table = (f'<table class="coverage"><caption>{esc(L["cap_perspectives"])}</caption>'
                   '<colgroup><col class="perspective-col"><col class="result-col"><col class="note-col"></colgroup>'
                   f'<thead><tr><th scope="col">{L["perspective"]}</th><th scope="col">{L["result"]}</th>'
                   f'<th scope="col">{L["note"]}</th></tr></thead><tbody>{persp_rows}</tbody></table>')
    finding_parts = "".join(finding_html(f, L, excerpts) for f in findings) \
        or f'<p class="small">{esc(L["none"])}</p>'
    runs = data.get("eval_runs", [])
    eval_rows = "".join(
        f'<tr><td class="fid">{esc(r["id"])}</td><td class="fid">{esc(r["finding"])}</td><td>{esc(r["model"])}</td>'
        f'<td>{esc(r["date"])}</td><td class="num">{r["cases"]}</td><td class="num">{r["passed"]}</td>'
        f'<td class="num">{r["failed"]}</td><td>{esc(r.get("note", ""))}</td></tr>' for r in runs)
    eval_part = table_or_none(runs, (
        f'<table class="evals"><caption>{esc(L["cap_evals"])}</caption><colgroup><col class="id-col"><col class="finding-col">'
        '<col class="model-col"><col class="date-col"><col class="num-col"><col class="num-col"><col class="num-col">'
        '<col class="note-col"></colgroup>'
        f'<thead><tr><th scope="col">{L["id"]}</th><th scope="col">{L["finding"]}</th><th scope="col">{L["model"]}</th>'
        f'<th scope="col">{L["date"]}</th><th scope="col" class="num">{L["cases"]}</th>'
        f'<th scope="col" class="num">{L["passed"]}</th><th scope="col" class="num">{L["failed"]}</th>'
        f'<th scope="col">{L["note"]}</th></tr></thead><tbody>{eval_rows}</tbody></table>'), L)
    sections = [
        ("summary", L["abstract"], f'<p class="lead">{esc(summary_line(data, L))}</p>{counts_table(data, L)}'),
        ("inventory", L["s_inventory"], prompt_table), ("perspectives", L["s_perspectives"], persp_table),
        ("checked-ok", L["s_sound"], list_section(data.get("checked_ok", []), L)),
        ("finding-details", L["s_findings"], finding_parts), ("eval-runs", L["s_evals"], eval_part),
        ("decisions", L["s_decisions"], list_section(data.get("decisions", []), L)),
        ("limitations", L["s_limitations"], list_section(data.get("limitations", []), L)),
        ("next-steps", L["s_next"], list_section(data.get("next_steps", []), L)),
    ]
    body = "".join(f'<section id="{sid}"' + (' class="summary-section"' if sid == "summary" else "") +
                   f'><h2>{esc(title)}</h2>{content}</section>' for sid, title, content in sections)
    target = data.get("meta", {}).get("target", "")
    title = f'{L["title"]} — {target}'.rstrip(" —")
    return (f'<!doctype html><html lang="{lang}"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1"><title>{esc(title)}</title>'
            f'<style>{kit_style.document_css(L["running_footer"])}{REPORT_CSS}</style></head><body>'
            f'<header class="report-header"><p class="kicker">{esc(L["running_footer"])}</p><h1>{esc(L["title"])}</h1>'
            f'<p class="project">{esc(target or "—")}</p>{meta_lines(data, L)}</header>'
            f'<main>{body}</main></body></html>')


# The shared stylesheet (scan_report_kit/assets/dashboard.css, design: scan-report-kit)
# comes first; these add only the rules for prompt-scan's dashboard pieces: the
# decisions panel, the verify-first legend, paired counts on the closed card,
# the earlier-validation history box and proposal text, which wraps as in the
# report where the kit's code listing scrolls sideways.
DASH_CSS = """
#decisions-section h2{margin-bottom:8px}#decisions-section ul{margin:0;padding-left:20px}
.verify-legend{margin:0 0 14px;color:var(--muted)}
.verify-legend .action-label{font-family:var(--sans);font-size:12px;font-weight:700;color:var(--accent)}
.card .n .pair{display:inline-block;white-space:nowrap;margin-right:18px}
.card .n .u{font-family:var(--sans);font-size:11px;letter-spacing:.06em;color:var(--muted);margin-left:6px}
.history{border:1px dashed var(--line);padding:12px;margin-top:16px}
.history p{margin:5px 0;white-space:pre-wrap}
.snippet.proposal-text{white-space:pre-wrap;overflow-wrap:anywhere}
"""

DASHBOARD = r"""<!doctype html>
<html lang="__LANG__">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
__CSS__
</style>
</head>
<body>
<a class="skip" href="#findings" data-l="jump_findings"></a>
<main>
<header class="masthead"><span class="brand" data-l="eyebrow"></span><div class="tools"><a class="button" href="report.html" data-l="report_link"></a><button id="theme" type="button" data-l="theme"></button></div></header>
<div class="hero"><div><div class="eyebrow" data-l="dash_title"></div><h1 id="h"></h1><div class="meta" id="meta"></div></div><div class="hero-aside" data-l="report_note"></div></div>
<div class="summary-banner" id="summary"></div>
<div class="cards" id="cards"></div><p class="report-note" data-l="counts_note"></p>
<div class="cards part-cards" id="part-cards"></div><p class="report-note" data-l="part_note"></p>
<section aria-labelledby="priority-heading"><div class="section-head"><div><h2 id="priority-heading" data-l="priority"></h2><p data-l="priority_note"></p></div><a href="#findings" data-l="view_all"></a></div><p class="verify-legend" id="verify-legend" hidden></p><div id="priority"></div><p class="section-note" id="queue-note"></p></section>
<section class="panel" id="decisions-section" aria-labelledby="decisions-heading"><h2 id="decisions-heading" data-l="decisions"></h2><div id="decisions"></div></section>
<details class="panel coverage" id="coverage" open><summary><span data-l="coverage_heading"></span><span class="small" id="coverage-count"></span></summary><p data-l="coverage_note"></p><dl class="scope-meta" id="scope-meta"></dl><div class="coverage-columns"><section><h3 data-l="limitations"></h3><div id="limitations"></div></section><section><h3 data-l="perspectives"></h3><div id="perspectives"></div></section></div></details>
<details class="chart-section"><summary data-l="overview"></summary><p class="section-note" data-l="count_basis"></p><div class="grid"><div class="panel"><h3 data-l="by_sev"></h3><div id="c-sev"></div></div><div class="panel"><h3 data-l="by_kind"></h3><div id="c-kind"></div></div><div class="panel"><h3 data-l="by_conf"></h3><div id="c-conf"></div></div><div class="panel"><h3 data-l="by_cat"></h3><div id="c-cat"></div></div><div class="panel"><h3 data-l="by_status"></h3><div id="c-status"></div></div><div class="panel"><h3 data-l="by_verdict"></h3><div id="c-verdict"></div><p class="section-note" data-l="excluded_note"></p></div></div></details>
<section id="findings" aria-labelledby="findings-heading"><div class="section-head"><div><h2 id="findings-heading" data-l="findings_register"></h2><p data-l="findings_note"></p></div></div>
<div class="panel filters-panel"><div class="filters">
<label><span data-l="record_set"></span><select id="f-scope"></select></label><label><span data-l="part"></span><select id="f-part"></select></label><label><span data-l="severity"></span><select id="f-sev"></select></label><label><span data-l="confidence"></span><select id="f-conf"></select></label><label><span data-l="category"></span><select id="f-cat"></select></label><label><span data-l="prompt"></span><select id="f-prompt"></select></label><label><span data-l="status"></span><select id="f-status"></select></label><label><span data-l="verdict"></span><select id="f-verdict"></select></label><label><span data-l="sort"></span><select id="f-sort"></select></label><label class="search"><span data-l="search"></span><input id="f-q" type="search"></label></div><div class="filter-bottom"><p class="result-count" id="result-count" role="status" aria-live="polite"></p><button type="button" id="reset" data-l="reset"></button></div></div>
<div class="tablewrap"><table class="register"><thead><tr><th scope="col">ID</th><th scope="col" data-l="severity"></th><th scope="col" data-l="part"></th><th scope="col" data-l="confidence"></th><th scope="col" data-l="verdict"></th><th scope="col" data-l="title_col"></th><th scope="col" data-l="category"></th></tr></thead><tbody id="rows"></tbody></table></div></section>
<div class="lists" id="lists"></div><footer class="footer" data-l="source_note"></footer>
<noscript><p>__NOSCRIPT__ <a href="report.html">__REPORT__</a></p></noscript>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
'use strict';
var D=JSON.parse(document.getElementById('data').textContent),L=D.labels,ALL=D.findings,R=D.report;
var F=ALL.filter(function(f){return D.excluded_verdicts.indexOf(f.verdict)<0;}),SEV=D.order.severity,CONF=D.order.confidence,ST=D.order.status;
var expanded=new Set();
function el(t,a,txt){var e=document.createElement(t);if(a)Object.keys(a).forEach(function(k){e.setAttribute(k,a[k]);});if(txt!=null)e.textContent=txt;return e;}
function byId(id){return document.getElementById(id);}
function fmt(text,values){return text.replace(/\{(\w+)\}/g,function(_,key){return values[key];});}
function pl(key,n,values){return fmt(n===1&&L[key+'_one']?L[key+'_one']:L[key],values||{n:n});}
function excluded(f){return D.excluded_verdicts.indexOf(f.verdict)>=0;}
function statusText(f){return excluded(f)?L.excluded_short:f.status;}
function badge(f){return el('span',{'class':'badge '+f.severity},f.severity);}
function kindText(f){return L['part_short_'+f.kind];}
function action(f){return f.status==='Open'&&f.verdict==='Valid'&&f.confidence==='Confirmed'?'fix_now':'verify_first';}
function count(fs,key,label){var c=Object.create(null);fs.forEach(function(f){var k=label?label(f):f[key];c[k]=(c[k]||0)+1;});return c;}
function listInto(box,items,empty){if(!items.length){box.appendChild(el('p',{'class':'muted'},empty));return;}var ul=el('ul');items.forEach(function(x){ul.appendChild(el('li',null,x));});box.appendChild(ul);}
document.title=L.dash_title+' - '+D.meta.target;byId('h').textContent=D.meta.target;
byId('meta').textContent=[D.meta.date,D.meta.assessor].filter(Boolean).join(' · ');
document.querySelectorAll('[data-l]').forEach(function(e){e.textContent=L[e.getAttribute('data-l')];});
byId('theme').onclick=function(){var root=document.documentElement,dark=root.dataset.theme?root.dataset.theme==='dark':window.matchMedia('(prefers-color-scheme: dark)').matches;root.dataset.theme=dark?'light':'dark';};
var summary=byId('summary');
summary.appendChild(el('strong',null,D.headline));
summary.appendChild(el('p',null,F.length?(R.open_hm?pl('risk_summary',R.open_hm):(R.open_count?pl('open_summary',R.open_count):L.no_open)):L.no_findings));
[[L.open_hm,R.open_hm,'urgent',L.open_count+': '+R.open_count],[L.needs_validation,R.verify_first,'review',L.fix_now+': '+R.fix_now],[L.closed_count,[[R.fixed,'Fixed'],[R.accepted,'Accepted']],'',L.included+': '+F.length],[L.excluded_short,R.excluded,'',L.all_records+': '+ALL.length]].forEach(function(c){var d=el('div',{'class':'card '+c[2]});d.appendChild(el('span',{'class':'l'},c[0]));var n=el('div',{'class':'n'});if(Array.isArray(c[1]))c[1].forEach(function(x){var pair=el('span',{'class':'pair'},x[0]);pair.appendChild(el('span',{'class':'u'},x[1]));n.appendChild(pair);});else n.textContent=c[1];d.appendChild(n);d.appendChild(el('div',{'class':'sub'},c[3]));byId('cards').appendChild(d);});
D.parts.forEach(function(part){var c=R.parts[part],d=el('div',{'class':'card','data-part':part});d.appendChild(el('span',{'class':'l'},L['part_'+part]+' · '+L.open_count));d.appendChild(el('div',{'class':'n'},c.open_count));d.appendChild(el('div',{'class':'sub'},fmt(L.part_card_sub,c)));byId('part-cards').appendChild(d);});
var shownTop=0;D.parts.forEach(function(part){var items=R.queue.filter(function(item){return item.kind===part;}).map(function(item){return {finding:ALL.find(function(f){return f.id===item.id;}),action:item.action,anchor:D.anchors[item.id]};}),high=items.filter(function(item){return item.finding.severity==='High';}).length,top=items.slice(0,Math.max(4,Math.min(high,12))),hiddenHigh=high-top.filter(function(item){return item.finding.severity==='High';}).length;shownTop+=top.length;if(!R.queue.length)return;byId('priority').appendChild(el('h3',{'class':'part-heading',id:'priority-'+part},L['part_'+part]));var list=el('div',{'class':'priority-list'});byId('priority').appendChild(list);if(!top.length)list.appendChild(el('div',{'class':'panel muted'},L.part_none_open));top.forEach(function(item){var f=item.finding,p=el('article',{'class':'panel priority-item sev-'+f.severity}),head=el('div',{'class':'priority-top'});head.appendChild(badge(f));head.appendChild(el('span',{'class':'action-label'},L[item.action]));p.appendChild(head);var h=el('h3');h.appendChild(el('a',{href:'#'+item.anchor},f.id+' · '+f.title));p.appendChild(h);p.appendChild(el('div',{'class':'verdict'},f.confidence+' · '+f.verdict));p.appendChild(el('code',{'class':'location'},f.location));if(f.impact)p.appendChild(el('p',{'class':'impact'},f.impact));if(item.action==='fix_now')p.appendChild(el('p',{'class':'action'},f.fix||L.missing_fix));list.appendChild(p);});if(hiddenHigh>0)byId('priority').appendChild(el('p',{'class':'section-note more-high','data-part':part},pl('more_high',hiddenHigh)));});
if(R.queue.some(function(item){return item.action==='verify_first';})){var legend=byId('verify-legend');legend.appendChild(el('span',{'class':'action-label'},L.verify_first));legend.appendChild(document.createTextNode(' '+L.verify_first_note));legend.hidden=false;}
if(!R.queue.length)byId('priority').appendChild(el('div',{'class':'panel muted'},L.no_open));byId('queue-note').textContent=shownTop<R.open_count?fmt(L.queue_more,{shown:shownTop,total:R.open_count}):'';
[['scope','scope_l'],['commit','commit'],['prompts','prompts_l']].forEach(function(k){byId('scope-meta').appendChild(el('dt',null,L[k[1]]));byId('scope-meta').appendChild(el('dd',null,D.meta[k[0]]||L.not_recorded));});
byId('coverage-count').textContent=L.limitations_count+': '+D.limitations.length;listInto(byId('limitations'),D.limitations,L.limitations_empty);
if(!D.perspectives.length)byId('perspectives').appendChild(el('p',{'class':'muted'},L.coverage_missing));
D.perspectives.forEach(function(p){var box=el('div',{'class':'perspective'});box.appendChild(el('strong',null,p.name));box.appendChild(el('p',null,L.results[p.result]||p.result||L.not_recorded));if(p.note)box.appendChild(el('p',{'class':'muted'},p.note));byId('perspectives').appendChild(box);});
function bars(id,key,order,colored,fs,label){var c=count(fs||F,key,label),keys=order||Object.keys(c).sort(function(a,b){return c[b]-c[a]||a.localeCompare(b);});var max=Math.max.apply(null,keys.map(function(k){return c[k]||0;}).concat([1]));keys.forEach(function(k){var r=el('div',{'class':'bar'});r.appendChild(el('span',{'class':'t'},k));var t=el('div',{'class':'track'}),fill=el('div',{'class':'fill'});fill.style.width=((c[k]||0)/max*100)+'%';if(colored)fill.style.background='var(--'+k.toLowerCase()+')';t.appendChild(fill);r.appendChild(t);r.appendChild(el('span',{'class':'v'},c[k]||0));byId(id).appendChild(r);});}
bars('c-sev','severity',SEV,true);bars('c-kind','kind',D.parts.map(function(p){return L['part_short_'+p];}),false,F,kindText);bars('c-conf','confidence',CONF);bars('c-cat','category');bars('c-status','status',ST);bars('c-verdict','verdict',D.order.verdict,false,ALL);
function opts(id,vals,first){var s=byId(id);if(first)s.appendChild(el('option',{value:''},first));vals.forEach(function(v){var pair=Array.isArray(v)?v:[v,v];s.appendChild(el('option',{value:pair[0]},pair[1]));});s.onchange=function(){if(id==='f-verdict'&&D.excluded_verdicts.indexOf(s.value)>=0)byId('f-scope').value='all';draw();};}
opts('f-scope',[['included',L.included_set],['excluded',L.excluded_set],['all',L.all_records]]);opts('f-part',D.parts.map(function(part){return [part,L['part_short_'+part]];}),L.part_all);opts('f-sort',[['priority',L.priority_sort],['severity',L.severity_sort]]);
opts('f-sev',SEV,L.all);opts('f-conf',CONF,L.all);opts('f-cat',Object.keys(count(ALL,'category')).sort(),L.all);opts('f-prompt',D.prompt_ids,L.all);opts('f-status',ST,L.all);opts('f-verdict',D.order.verdict,L.all_verdicts);
// Large registers redraw once typing pauses instead of on every keystroke.
var q=byId('f-q'),searchTimer=null;q.placeholder=L.search;q.oninput=function(){clearTimeout(searchTimer);if(ALL.length>300)searchTimer=setTimeout(draw,150);else draw();};
function v(id){return byId(id).value;}
function reset(){['f-part','f-sev','f-conf','f-cat','f-prompt','f-status','f-verdict'].forEach(function(id){byId(id).value='';});byId('f-scope').value='included';byId('f-sort').value='priority';q.value='';}
byId('reset').onclick=function(){reset();draw();};
function fence(text){var runs=String(text).match(/`+/g)||[],n=Math.max.apply(null,runs.map(function(r){return r.length;}).concat([2]))+1;return Array(n+1).join('`');}
function oneLine(v){return String(v).replace(/\s*[\r\n]+\s*/g,' ');}
function fenced(v){var fc=fence(v);return fc+'text\n'+v+'\n'+fc;}
function asText(v){return Array.isArray(v)?v.map(function(x){return '- '+x;}).join('\n'):v;}
function findingMarkdown(f){var out=['## '+oneLine(f.id)+' · '+oneLine(f.title),''],p=function(label,value){if(value)out.push('- '+label+': '+oneLine(value));},block=function(label,value,raw){if(value)out.push('','### '+label,'',raw?value:fenced(value));};
p(L.severity,f.severity);p(L.part,kindText(f));p(L.confidence,f.confidence);p(L.status,statusText(f));p(L.verdict,f.verdict);p(L.category,f.category);p(L.prompt,f.prompts.join(', '));p(L.location,f.location);
if(f.status==='Open'&&!excluded(f)){var a=action(f);block(L[a],L[a+'_note'],true);}['symptom','cause','impact','fix'].forEach(function(k){block(L[k],f[k]);});
if(f.proposal){block(L.proposal_before,f.proposal.before);block(L.proposal_after,f.proposal.after);}block(L.test,asText(f.test));block(L.evidence,f.validation.evidence);block(L.validation_method,f.validation.method);
if(f.snippet){var lines=f.snippet.lines.map(function(text,i){var n=f.snippet.start+i;return (n>=f.snippet.hit[0]&&n<=f.snippet.hit[1]?'>':' ')+String(n).padStart(5,' ')+' '+text;}).join('\n'),fc=fence(lines);block(L.snippet,fc+'\n'+lines+'\n'+fc,true);}
var refs=f.references||[];if(refs.length)block(L.references,refs.map(function(r){return '- '+(r.title&&r.title!==r.url?oneLine(r.title)+' — ':'')+oneLine(r.url);}).join('\n'),true);
return out.join('\n')+'\n';}
// A denied or unavailable Clipboard API falls back to the selection copy.
function copyText(text){if(navigator.clipboard&&window.isSecureContext)return navigator.clipboard.writeText(text).catch(function(){return copyFallback(text);});return copyFallback(text);}
function copyFallback(text){return new Promise(function(resolve,reject){var prev=document.activeElement,t=el('textarea',{readonly:'','aria-hidden':'true',style:'position:fixed;top:0;left:-9999px'});t.value=text;document.body.appendChild(t);t.select();var ok=false;try{ok=document.execCommand('copy');}catch(e){}t.remove();if(prev&&prev.focus)prev.focus({preventScroll:true});if(ok)resolve();else reject(new Error('copy'));});}
function copyButton(f){var b=el('button',{type:'button','class':'copy-finding','aria-live':'polite'},L.copy_llm),timer;b.onclick=function(e){e.stopPropagation();var done=function(label){b.textContent=label;clearTimeout(timer);timer=setTimeout(function(){b.textContent=L.copy_llm;},2000);};copyText(findingMarkdown(f)).then(function(){done(L.copied);},function(){done(L.copy_failed);});};return b;}
// Detail content is built on first expansion: a large register would
// otherwise build every record's full detail tree on each redraw.
function details(f,anchor){var dt=el('tr',{'class':'detail',id:anchor+'-detail'});dt.hidden=!expanded.has(anchor);if(!dt.hidden)fillDetails(dt,f,anchor);return dt;}
function snippetNode(start,lines,hit){var pre=el('pre',{'class':'snippet'});lines.forEach(function(text,i){var n=start+i,ln=el('span',{'class':hit&&n>=hit[0]&&n<=hit[1]?'hit':''});ln.appendChild(el('b',null,String(n).padStart(5,' ')+' '));ln.appendChild(document.createTextNode(text));pre.appendChild(ln);});return pre;}
function textNode(text){var pre=el('pre',{'class':'snippet proposal-text'});pre.textContent=text;return pre;}
function fillDetails(dt,f,anchor){if(dt.firstChild)return;var td=el('td',{colspan:7}),dl=el('dl');
var head=el('div',{'class':'detail-actions'});head.appendChild(el('strong',null,f.id+' · '+f.title));var links=el('span',{'class':'detail-links'});links.appendChild(copyButton(f));links.appendChild(el('a',{href:'#'+anchor},L.permalink));head.appendChild(links);td.appendChild(head);
if(f.status==='Open'&&!excluded(f)){var a=action(f),guidance=el('div',{'class':'action-guidance'});guidance.appendChild(el('strong',null,L[a]));guidance.appendChild(el('p',null,L[a+'_note']));td.appendChild(guidance);}else if(excluded(f)){td.appendChild(el('p',{'class':'muted'},L.excluded_note));}
function field(label,value){dl.appendChild(el('dt',null,label));var dd=el('dd');if(value instanceof Node)dd.appendChild(value);else dd.textContent=value;dl.appendChild(dd);}
field(L.location,f.location);if(f.prompts.length)field(L.prompt,f.prompts.join(', '));field(L.status,statusText(f));['symptom','cause','impact'].forEach(function(k){if(f[k])field(L[k],f[k]);});field(L.fix,f.fix||(f.status==='Open'&&!excluded(f)?L.missing_fix:L.not_recorded));
if(f.proposal){if(f.proposal.before)field(L.proposal_before,textNode(f.proposal.before));if(f.proposal.after)field(L.proposal_after,textNode(f.proposal.after));}
if(f.test)field(L.test,asText(f.test));field(L.evidence,f.validation.evidence||L.missing_evidence);if(f.validation.method)field(L.validation_method,f.validation.method);
if(f.snippet)field(L.snippet,snippetNode(f.snippet.start,f.snippet.lines,f.snippet.hit));
var refs=f.references||[];if(refs.length){var ul=el('ul',{'class':'refs'});refs.forEach(function(r){var li=el('li');li.appendChild(el('a',{href:r.url,target:'_blank',rel:'noopener noreferrer'},r.title||r.url));ul.appendChild(li);});field(L.references,ul);}td.appendChild(dl);
if(f.previous_validation&&typeof f.previous_validation==='object'){var history=el('aside',{'class':'history'});history.appendChild(el('strong',null,L.previous_validation));history.appendChild(el('p',null,L.history_note));['verdict','evidence','method'].forEach(function(k){if(typeof f.previous_validation[k]==='string')history.appendChild(el('p',null,f.previous_validation[k]));});td.appendChild(history);}dt.appendChild(td);}
var searchCache=new Map();
function searchText(f){if(searchCache.has(f))return searchCache.get(f);var val=f.validation||{},pr=f.proposal||{},text=[f.id,f.title,f.location,f.category,f.prompts.join(' '),f.symptom,f.cause,f.impact,f.fix,pr.before,pr.after,asText(f.test),f.status,f.severity,f.kind,kindText(f),f.confidence,f.verdict,val.evidence,val.method].filter(Boolean).join('\n').toLowerCase();searchCache.set(f,text);return text;}
function draw(){clearTimeout(searchTimer);var tb=byId('rows');tb.textContent='';var term=q.value.trim().toLowerCase(),scope=v('f-scope');var pool=scope==='all'?ALL:ALL.filter(function(f){return scope==='excluded'?excluded(f):!excluded(f);});var shown=pool.filter(function(f){return (!v('f-part')||f.kind===v('f-part'))&&(!v('f-sev')||f.severity===v('f-sev'))&&(!v('f-conf')||f.confidence===v('f-conf'))&&(!v('f-cat')||f.category===v('f-cat'))&&(!v('f-prompt')||f.prompts.indexOf(v('f-prompt'))>=0)&&(!v('f-status')||f.status===v('f-status'))&&(!v('f-verdict')||f.verdict===v('f-verdict'))&&(!term||searchText(f).indexOf(term)>=0);});
shown.sort(function(a,b){var status=v('f-sort')==='priority'?Number(a.status!=='Open')-Number(b.status!=='Open'):0;return status||SEV.indexOf(a.severity)-SEV.indexOf(b.severity)||(v('f-sort')==='priority'?Number(action(a)!=='fix_now')-Number(action(b)!=='fix_now'):0)||D.parts.indexOf(a.kind)-D.parts.indexOf(b.kind)||String(a.id).localeCompare(String(b.id),'en',{numeric:true});});
byId('result-count').textContent=fmt(L.showing,{shown:shown.length,total:pool.length});
if(!shown.length){var empty=el('tr'),td=el('td',{colspan:7,'class':'empty'},pool.length?L.no_matches:L.no_records);empty.appendChild(td);tb.appendChild(empty);return;}
shown.forEach(function(f){var anchor=D.anchors[f.id],tr=el('tr',{'class':'row',id:anchor}),dt=details(f,anchor);var labels=['ID',L.severity,L.part,L.confidence,L.verdict,L.title_col,L.category];var values=[f.id,null,kindText(f),f.confidence,f.verdict,null,f.category],button;
values.forEach(function(value,i){var cell=el('td',{'data-label':labels[i]},value);if(i===1)cell.appendChild(badge(f));if(i===5){button=el('button',{type:'button','class':'finding-toggle','aria-expanded':String(!dt.hidden),'aria-controls':dt.id},f.title);button.appendChild(el('span',{'class':'toggle-label'},dt.hidden?L.expand:L.collapse));cell.appendChild(button);cell.appendChild(el('code',{'class':'location'},f.location));}tr.appendChild(cell);});
function toggle(){if(dt.hidden)fillDetails(dt,f,anchor);dt.hidden=!dt.hidden;if(dt.hidden)expanded.delete(anchor);else expanded.add(anchor);button.setAttribute('aria-expanded',String(!dt.hidden));button.querySelector('.toggle-label').textContent=dt.hidden?L.expand:L.collapse;}
button.onclick=function(e){e.stopPropagation();toggle();};tr.onclick=function(e){if(!e.target.closest('a,button'))toggle();};tb.appendChild(tr);tb.appendChild(dt);});}
function openHash(){var anchor=window.location.hash.slice(1),f=ALL.find(function(x){return D.anchors[x.id]===anchor;});if(!f)return;expanded.add(anchor);draw();if(!byId(anchor)){reset();if(excluded(f))byId('f-scope').value='all';expanded.add(anchor);draw();}var row=byId(anchor);row.scrollIntoView({block:'start'});row.querySelector('button').focus({preventScroll:true});}
document.addEventListener('click',function(e){var a=e.target.closest('a[href^="#finding-"]');if(a&&a.getAttribute('href')===window.location.hash){e.preventDefault();openHash();}});
window.addEventListener('hashchange',openHash);draw();if(window.location.hash)openHash();
listInto(byId('decisions'),D.decisions,L.not_recorded);
['next_steps','checked_ok'].forEach(function(k){var p=el('section',{'class':'panel'});p.appendChild(el('h2',null,L[k]));listInto(p,D[k],L.not_recorded);byId('lists').appendChild(p);});
})();
</script>
</body>
</html>
"""

# Dashboard wording follows security-scan's dashboard; the record's kinds stand where its parts were.
DASH_LABELS = {
    "en": {
        "eyebrow": "PROMPT REVIEW", "dash_title": "Prompt Findings",
        "report_note": "Static review · read-only · offline report",
        "report_link": "Print / report", "theme": "Toggle color theme",
        "priority": "Start here",
        "priority_note": "Open findings, ordered by severity, then readiness to fix. Check the cited prompt "
                         "and call site before changing the text.",
        "fix_now": "Plan the fix", "verify_first": "Verify first",
        "fix_now_note": "Valid, Confirmed finding. Apply the recorded fix direction or proposal and check it "
                        "with the recorded eval or test.",
        "verify_first_note": "Re-read the prompt as sent and the code around it, or run the recorded eval "
                             "case, before deciding on a change.",
        "more_high": "{n} more open High findings of this kind are listed in the findings register.",
        "more_high_one": "1 more open High finding of this kind is listed in the findings register.",
        "missing_fix": "Fix direction not recorded. Define the change after reviewing the evidence.",
        "no_open": "No open findings are recorded. This does not establish that the prompts behave as intended.",
        "no_findings": "No included findings are recorded. Review the scope and limitations before drawing "
                       "conclusions.",
        "included": "Included findings", "excluded_short": "Excluded", "open_count": "Open findings",
        "open_hm": "Open High/Medium", "needs_validation": "Open, needs validation",
        "closed_count": "Fix recorded / accepted", "all_records": "All records",
        "open_summary": "{n} open findings are recorded; none are High or Medium.",
        "open_summary_one": "1 open finding is recorded; it is not High or Medium.",
        "risk_summary": "{n} open High / Medium findings need attention.",
        "risk_summary_one": "1 open High / Medium finding needs attention.",
        "counts_note": "Report-wide totals include Open, Fixed and Accepted. Excluded findings do not "
                       "contribute to these totals.",
        "part": "Kind", "part_all": "All kinds",
        "part_defect": "Defects", "part_improvement": "Improvements",
        "part_short_defect": "Defect", "part_short_improvement": "Improvement",
        "part_note": "Defects are prompts or prompt assembly that is broken: unfilled variables, contradictions, "
                     "output-contract mismatches, injection boundaries, truncation. Improvements are prompts that "
                     "work but would work better; each carries a before/after proposal. L-* findings come from "
                     "inventory.py lint.",
        "part_card_sub": "Open High/Medium: {open_hm} · Total: {total}",
        "part_none_open": "No open findings of this kind.",
        "view_all": "View all findings", "queue_more": "Showing {shown} of {total} open findings.",
        "decisions": "Decisions required",
        "coverage_heading": "Scope, coverage and limitations",
        "coverage_note": "Coverage is recorded per perspective below. Missing perspectives or empty notes do "
                         "not mean they were checked. Zero findings does not mean the prompts behave as intended.",
        "scope_l": "Scope", "commit": "Revision", "prompts_l": "Prompts reviewed",
        "limitations": "Limitations", "limitations_count": "Recorded limitations",
        "limitations_empty": "No limitations were recorded. This is not evidence of complete coverage.",
        "perspectives": "Coverage by perspective", "coverage_missing": "No perspective coverage was recorded.",
        "not_recorded": "Not recorded",
        "overview": "Results overview",
        "count_basis": "Severity is potential impact; confidence is certainty. The verdict records whether the "
                       "finding applies.",
        "by_sev": "By severity", "by_kind": "By kind", "by_conf": "By confidence", "by_cat": "By perspective",
        "by_status": "By status", "by_verdict": "By verdict",
        "excluded_note": "Excluded findings are retained with their justification. They are not counted in "
                         "included totals.",
        "findings_register": "Findings register",
        "findings_note": "Open a finding for its cause, proposal and how to check the fix. Totals above remain "
                         "report-wide while filtering.",
        "record_set": "Records", "included_set": "Included (excludes ruled-out findings)",
        "excluded_set": "Excluded only", "severity": "Severity", "confidence": "Confidence",
        "category": "Perspective", "prompt": "Prompt", "status": "Status", "verdict": "Verdict",
        "all_verdicts": "All verdicts", "sort": "Order", "priority_sort": "Open first, then severity",
        "severity_sort": "Severity", "search": "Search", "all": "All", "reset": "Clear filters",
        "showing": "Showing {shown} of {total} records in this view",
        "no_matches": "No findings match these filters. Clear filters to see more.",
        "no_records": "No records in this view.", "title_col": "Title",
        "expand": "Show details", "collapse": "Hide details", "permalink": "Link to finding",
        "copy_llm": "Copy for LLM", "copied": "Copied", "copy_failed": "Copy failed",
        "location": "Location", "symptom": "Symptom", "cause": "Cause", "impact": "Impact",
        "fix": "Fix direction", "proposal_before": "Current text", "proposal_after": "Proposed text",
        "test": "How to check", "evidence": "Verdict evidence", "validation_method": "Validation method",
        "snippet": "Source", "references": "References",
        "previous_validation": "Previous validation (historical; not the current verdict)",
        "history_note": "Revalidate this evidence against the current prompts and code.",
        "missing_evidence": "No validation evidence recorded.",
        "next_steps": "Recommended next steps", "checked_ok": "Checked and sound",
        "source_note": "Source excerpts are best-effort redacted. Inspect this report before sharing.",
        "no_script": "Enable JavaScript to use the interactive dashboard, or open the report for the complete "
                     "record.",
        "jump_findings": "Jump to findings",
    },
    "ja": {
        "eyebrow": "PROMPT REVIEW", "dash_title": "プロンプト診断結果",
        "report_note": "静的レビュー · 読み取り専用 · オフラインレポート",
        "report_link": "印刷用のレポート", "theme": "配色を切り替え",
        "priority": "まず取り組むこと",
        "priority_note": "未対応の指摘を深刻度順、同じ深刻度では修正判断の準備ができた順に表示します。"
                         "文面を変える前に、該当プロンプトと呼び出し箇所を確認してください。",
        "fix_now": "修正を計画", "verify_first": "先に検証する",
        "fix_now_note": "Valid・Confirmed の指摘です。記録された修正方針または改善案を適用し、記録された評価・テストで確認してください。",
        "verify_first_note": "送信されるプロンプト全体と周辺コードを読み直すか、記録された評価ケースを実行してから変更要否を判断してください。",
        "more_high": "この種別には未対応の High がほかに {n} 件あります（指摘一覧に記載）。",
        "missing_fix": "修正方針が未記録です。根拠を確認し、変更内容を具体化してください。",
        "no_open": "未対応の指摘は記録されていません。プロンプトが意図どおりに動くことを保証するものではありません。",
        "no_findings": "集計対象の指摘はありません。診断範囲と制約を確認してから判断してください。",
        "included": "集計対象の指摘", "excluded_short": "除外", "open_count": "未対応の指摘",
        "open_hm": "未対応の高・中", "needs_validation": "未対応・要検証",
        "closed_count": "修正の申告 / 受容", "all_records": "すべての記録",
        "open_summary": "未対応の指摘は {n} 件です。High / Medium は含まれていません。",
        "risk_summary": "未対応の High / Medium が {n} 件あります。",
        "counts_note": "全体集計には Open・Fixed・Accepted を含みます。除外した指摘は含みません。",
        "part": "種別", "part_all": "すべての種別",
        "part_defect": "不具合", "part_improvement": "改善提案",
        "part_short_defect": "不具合", "part_short_improvement": "改善提案",
        "part_note": "不具合は、プロンプトやその組み立てが壊れているものです（埋まらない変数、指示の矛盾、出力形式とパーサーの不一致、"
                     "インジェクション境界、切り詰め）。改善提案は、動作はするがより良くできるもので、現在の文面と提案文を併記しています。"
                     "L-* は inventory.py の機械チェックによる指摘です。",
        "part_card_sub": "未対応の高・中: {open_hm} 件 · 計 {total} 件",
        "part_none_open": "この種別に未対応の指摘はありません。",
        "view_all": "指摘一覧を見る", "queue_more": "未対応 {total} 件のうち {shown} 件を表示しています。",
        "decisions": "判断が必要な事項",
        "coverage_heading": "診断範囲・確認状況・制約",
        "coverage_note": "観点ごとの確認状況を下に示します。観点や備考の記載がない場合、確認済みとは見なしません。"
                         "指摘がゼロでも、プロンプトが意図どおりに動く保証にはなりません。",
        "scope_l": "範囲", "commit": "リビジョン", "prompts_l": "対象プロンプト",
        "limitations": "制約事項", "limitations_count": "記録された制約",
        "limitations_empty": "制約事項が記録されていません。すべて確認済みであることを示すものではありません。",
        "perspectives": "観点別の診断結果", "coverage_missing": "観点ごとの確認状況が記録されていません。",
        "not_recorded": "未記録",
        "overview": "結果概要",
        "count_basis": "深刻度は想定される影響、確度は確かさ、検証判定はこの対象に指摘が成立するかを表します。",
        "by_sev": "深刻度別", "by_kind": "種別別", "by_conf": "確度別", "by_cat": "観点別",
        "by_status": "状態別", "by_verdict": "検証判定別",
        "excluded_note": "除外した指摘も、その根拠とともに保持します。集計対象の件数には含めません。",
        "findings_register": "指摘一覧",
        "findings_note": "指摘を開くと原因・改善案・修正の確認方法を確認できます。絞り込んでも上部の全体集計は変わりません。",
        "record_set": "表示対象", "included_set": "集計対象（誤検知・対象外を除く）",
        "excluded_set": "除外した指摘のみ", "severity": "深刻度", "confidence": "確度",
        "category": "観点", "prompt": "プロンプト", "status": "状態", "verdict": "検証判定",
        "all_verdicts": "すべての検証判定", "sort": "表示順", "priority_sort": "未対応を先に、深刻度順",
        "severity_sort": "深刻度順", "search": "検索", "all": "すべて", "reset": "絞り込みを解除",
        "showing": "この表示対象 {total} 件中 {shown} 件を表示",
        "no_matches": "条件に一致する指摘はありません。絞り込みを解除すると、ほかの指摘を確認できます。",
        "no_records": "この表示対象に該当する記録はありません。", "title_col": "件名",
        "expand": "詳細を開く", "collapse": "詳細を閉じる", "permalink": "この指摘へのリンク",
        "copy_llm": "LLM用にコピー", "copied": "コピーしました", "copy_failed": "コピーできませんでした",
        "location": "場所", "symptom": "症状", "cause": "原因", "impact": "影響",
        "fix": "修正方針", "proposal_before": "現在の文面", "proposal_after": "提案する文面",
        "test": "確認方法", "evidence": "判定の根拠", "validation_method": "検証方法",
        "snippet": "該当ソース", "references": "参照",
        "previous_validation": "以前の判定（履歴。現在の判定ではありません）",
        "history_note": "現在のプロンプト・コードに照らして再検証してください。",
        "missing_evidence": "判定の根拠が記録されていません。",
        "next_steps": "推奨する対応順", "checked_ok": "問題がなかった確認項目",
        "source_note": "ソース抜粋の伏せ字は完全ではありません。共有前に内容を確認してください。",
        "no_script": "対話型ダッシュボードには JavaScript が必要です。レポートではすべての記録を確認できます。",
        "jump_findings": "指摘一覧へ移動",
    },
}


def dashboard_model(data):
    """Counts and the open queue, as security-scan's dashboard shows them."""
    findings = data.get("findings", [])
    included = [f for f in findings if f["validation"]["verdict"] not in EXCLUDED]
    open_ = [f for f in included if f.get("status", "Open") == "Open"]

    def action(f):
        return "fix_now" if f["validation"]["verdict"] == "Valid" and f["confidence"] == "Confirmed" else "verify_first"

    queue = sorted(open_, key=lambda f: (SEVERITIES.index(f["severity"]), action(f) != "fix_now",
                                         KINDS.index(f["kind"]), id_key(f["id"])))
    return {
        "queue": [{"id": f["id"], "kind": f["kind"], "action": action(f)} for f in queue],
        "open_count": len(open_), "open_hm": sum(f["severity"] in ("High", "Medium") for f in open_),
        "fix_now": sum(action(f) == "fix_now" for f in open_),
        "verify_first": sum(action(f) == "verify_first" for f in open_),
        "fixed": sum(f.get("status") == "Fixed" for f in included),
        "accepted": sum(f.get("status") == "Accepted" for f in included),
        "excluded": len(findings) - len(included),
        "parts": {kind: {"open_count": sum(f["kind"] == kind for f in open_),
                         "open_hm": sum(f["kind"] == kind and f["severity"] in ("High", "Medium") for f in open_),
                         "total": sum(f["kind"] == kind for f in included)} for kind in KINDS},
    }


def render_dashboard(data, L, lang, excerpts):
    meta = data.get("meta", {})
    labels = {**L, **DASH_LABELS[lang]}
    items = []
    for f in data.get("findings", []):
        prompt = f.get("prompt")
        x = excerpts.get(f["id"])
        item = {k: f[k] for k in ("id", "kind", "severity", "confidence", "category", "title", "location",
                                  "symptom", "cause", "impact", "fix", "proposal", "test", "references",
                                  "previous_validation") if k in f}
        item.update(status=f.get("status", "Open"), verdict=f["validation"]["verdict"], validation=f["validation"],
                    prompts=[prompt] if isinstance(prompt, str) else (prompt or []),
                    snippet={"start": x[0], "lines": x[1], "hit": list(x[2])} if x else None)
        items.append(item)
    prompts = data.get("prompts", [])
    payload = {
        "meta": {"target": meta.get("target", ""), "date": meta.get("date"), "assessor": meta.get("assessor"),
                 "scope": meta.get("scope"),
                 "commit": revision(meta, L),
                 "prompts": ", ".join(f'{p["id"]} {p["name"]}' for p in prompts) or None},
        "labels": labels, "headline": summary_line(data, L), "report": dashboard_model(data), "findings": items,
        "anchors": {f["id"]: "finding-" + f["id"].lower() for f in data.get("findings", [])},
        "parts": KINDS, "prompt_ids": [p["id"] for p in prompts],
        "order": {"severity": SEVERITIES, "confidence": CONFIDENCES, "status": STATUSES, "verdict": VERDICTS},
        "excluded_verdicts": sorted(EXCLUDED),
        **{k: data.get(k, []) for k in STRING_LISTS},
        "perspectives": [{k: p[k] for k in ("name", "result", "note") if k in p} for p in data.get("perspectives", [])],
    }
    # Escape every less-than sign: <!-- and <script also change HTML parsing.
    blob = json.dumps(payload, ensure_ascii=False).replace("<", "\\u003c") \
        .replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")
    replacements = {"__CSS__": kit_style.dashboard_css() + DASH_CSS,
                    "__LANG__": lang, "__TITLE__": esc(f'{labels["dash_title"]} - {meta.get("target", "")}'),
                    "__NOSCRIPT__": esc(labels["no_script"]), "__REPORT__": esc(labels["report_link"]),
                    "__DATA__": blob}
    # Substitute only template tokens, not token-like strings inside report data.
    return re.sub(r"__(?:CSS|LANG|TITLE|NOSCRIPT|REPORT|DATA)__", lambda m: replacements[m.group(0)], DASHBOARD)


# ---------------------------------------------------------------- PDF

TIMEOUT_ENV = "PROMPT_SCAN_PDF_TIMEOUT"
OUTPUTS = ("dashboard.html", "report.html", "report.pdf")


def to_pdf(html_path, pdf_path, failures, timeout=None):
    """Print html_path with scan_report_kit.pdf (Chrome, else WeasyPrint). Returns the engine name or None.

    Each engine that was found but did not produce a PDF is appended to failures
    as one readable string; engine stderr is masked (mask) before it is recorded.
    """
    found = []
    timeout = kit_pdf.pdf_timeout(env=TIMEOUT_ENV) if timeout is None else timeout
    engine = kit_pdf.to_pdf(html_path, pdf_path, found, timeout, redact=mask)
    failures.extend(f"{name} {reason}" + (f": {detail}" if detail else "") for name, reason, detail in found)
    return engine


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True)
    p.add_argument("--lang", choices=sorted(LABELS), help="report language (default: meta.lang, else ja)")
    p.add_argument("--repo", help="reviewed repository, for embedded excerpts")
    p.add_argument("--no-pdf", action="store_true")
    a = p.parse_args(argv)
    try:
        source = Path(a.findings).read_bytes()
        data = load(a.findings, source)
        excerpts = attach_sources(data, a.repo)
        lang = a.lang or data.get("meta", {}).get("lang") or "ja"
        L = LABELS[lang]
        stamp = STAMP.format(hashlib.sha256(source).hexdigest())
        pages = {"dashboard.html": render_dashboard(data, L, lang, excerpts),
                 "report.html": render_report_html(data, L, lang, excerpts)}
    except (SchemaError, OSError) as e:
        print(f"render.py: {e}", file=sys.stderr)
        return 2
    out = Path(a.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        unsafe = unsafe_target(out, OUTPUTS)
        if unsafe:
            raise OSError(f"refusing to write {unsafe}: it exists as a symlink or non-regular file")
        # A previous run's PDF must never survive next to newer HTML.
        (out / "report.pdf").unlink(missing_ok=True)
        for name, page in pages.items():
            write_output(out / name, page.replace("<head>", "<head>" + stamp, 1))
            print(f"wrote {out / name}")
        if a.no_pdf:
            return 0
    except OSError as e:
        print(f"render.py: cannot write outputs to {out}: {e}", file=sys.stderr)
        return 2
    failures = []
    timeout = kit_pdf.pdf_timeout(len(data.get("findings", [])), env=TIMEOUT_ENV)
    engine = to_pdf(out / "report.html", out / "report.pdf", failures, timeout)
    if not engine:
        reason = "; ".join(failures) if failures else "no PDF engine found (Chrome/Chromium or weasyprint)"
        print(f"render.py: {reason}. report.html is ready to print. Without an engine anywhere: merge the "
              "limitation 'report.pdf not produced: no PDF engine', re-run with --no-pdf, then "
              "contract_check.py <out> --no-pdf", file=sys.stderr)
        return 3
    print(f"wrote {out / 'report.pdf'} ({engine})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
