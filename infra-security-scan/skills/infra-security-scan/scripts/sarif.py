#!/usr/bin/env python3
"""Export findings.json as SARIF 2.1.0 for code scanning, CI and editors.

    python3 sarif.py FINDINGS --out FILE [--lang en|ja] [--min-severity High|Medium|Low|Info]
                     [--mask] [--counted-only]

Writes one SARIF log: GitHub code scanning (`github/codeql-action/upload-sarif`),
GitLab, Azure DevOps and SARIF viewers in editors read it, so each finding shows
as an alert on its `path:line` with its severity, fix and attack path. FILE is
scratch, never inside the output directory (its file set is fixed); nothing is
uploaded by this script.

- Rules: an I-* finding uses its baseline rule (`AWS-NET-001`…) with the rule's
  title, CWE and controls; an F-* finding uses one rule per perspective
  (`review/network-exposure`…), since review titles differ per finding
- Severity: `level` is error (High), warning (Medium) or note (Low, Info);
  `security-severity` (High 8.0, Medium 5.5, Low 3.0, Info 0.5) is set on each
  result and, as the worst of its results, on each rule, which is where GitHub
  reads it
- Fingerprints: `partialFingerprints["infraSecurityScan/v1"]` hashes the kind, rule or
  perspective, provider, sorted resources and file — not the ID, which
  `renumber` changes, nor the line — so an alert keeps its identity across runs
- Attack paths: each linked `AP-*` becomes a code flow whose steps are its
  edges, located at the `path:line` each edge cites
- Excluded findings (FalsePositive / NotApplicable) and I-* covered by a review
  finding are written with a SARIF suppression carrying the evidence, so a code
  scanning alert raised by an earlier upload is closed rather than left open;
  `--counted-only` leaves them out
- `@snapshots/<dir>/...` locations use the `SNAPSHOTS` base instead of
  `%SRCROOT%`: they are not files of the repository

`--mask` replaces 12-digit account IDs and IPv4 addresses (0.0.0.0 kept) in
every message, as `issues.py --mask` does. An upload to a public repository's
code scanning is visible to its readers: an unfixed High or Medium belongs only
in a private repository's code scanning, as with issue drafts.

Exit codes: 0 written, 1 refused (FILE in the output directory, a symlink or
not a regular file), 2 unreadable input, schema error or unwritable FILE.
"""
import argparse
import hashlib
import html
import json
from pathlib import Path
import re
import sys
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))  # also under python -I
import render  # noqa: E402
from common import LOCATION, SEV_RANK, SEVERITIES, has_symlink_parent  # noqa: E402
from issues import mask  # noqa: E402
from redaction import CREDENTIAL  # noqa: E402
from report_output import write_output  # noqa: E402

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFORMATION_URI = "https://github.com/simota/infra-security-scan"
LEVEL = {"High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
SECURITY_SEVERITY = {"High": "8.0", "Medium": "5.5", "Low": "3.0", "Info": "0.5"}
SNAPSHOT_PREFIX = "@snapshots/"
MESSAGE_FIELDS = ("actor", "impact", "condition", "fix", "regression", "detail")
LABELS = {
    "en": {"covered": "Covered by review finding {0}: its root cause is fixed there.",
           "excluded": "Excluded after triage ({0}).", "review_rule": "Review finding: {0}",
           "review_help": "Findings from the attack-path review under the perspective “{0}”. Each result carries "
                          "its own title, attack path, fix and regression check."},
    "ja": {"covered": "検出事項 {0} に統合されています。根本原因はそちらで修正します。",
           "excluded": "精査の結果除外しました（{0}）。", "review_rule": "レビューの検出事項: {0}",
           "review_help": "観点「{0}」の攻撃経路レビューで見つかった検出事項です。各結果にタイトル・攻撃経路・修正・回帰チェックがあります。"},
}


def slug(text):
    return re.sub(r"[^a-z0-9]+", "-", str(text).casefold()).strip("-") or "uncategorized"


def rule_id(f):
    if str(f.get("id", "")).startswith("I-") and f.get("rule"):
        return str(f["rule"])
    return f"review/{slug(f.get('category'))}"


def fingerprint(f):
    """Stable across renumbering and line moves: the root cause, not its ID."""
    m = LOCATION.match(str(f.get("location", "")))
    file = m.group(1) if m else str(f.get("location", ""))
    key = json.dumps([str(f.get("id", ""))[:2], rule_id(f), f.get("provider"),
                      sorted(str(r) for r in f.get("resources", [])), file], ensure_ascii=False)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def artifact(path):
    if path.startswith(SNAPSHOT_PREFIX):
        return {"uri": quote(path[len(SNAPSHOT_PREFIX):], safe="/"), "uriBaseId": "SNAPSHOTS"}
    return {"uri": quote(path.lstrip("/"), safe="/"), "uriBaseId": "%SRCROOT%"}


def physical(location):
    m = LOCATION.match(str(location or ""))
    if not m:
        return None
    start = int(m.group(2))
    region = {"startLine": start}
    if m.group(3):
        region["endLine"] = int(m.group(3))
    return {"artifactLocation": artifact(m.group(1)), "region": region}


def md_text(value):
    """Markdown-safe text: no raw HTML, no bidirectional controls."""
    return render.BIDI.sub(lambda m: f"[U+{ord(m.group()):04X}]", html.escape(str(value), quote=False))


class Text:
    """Every string that leaves the record goes through here: redacted, maybe masked."""

    def __init__(self, masked):
        self.masked = masked

    def __call__(self, value):
        text = CREDENTIAL.sub("[redacted]", str(value))
        return mask(text) if self.masked else text


def message(f, lang, clean):
    L = render.LABELS[lang]
    title = render.shown(f.get("title", ""), lang)
    lines, md = [title], [f"**{md_text(title)}**"]
    head = (f"{L['severity']}: {render.shown(f.get('severity'), lang)} · "
            f"{L['confidence']}: {render.shown(f.get('confidence'), lang)} · "
            f"{L['verdict']}: {render.shown(f.get('validation', {}).get('verdict'), lang)}")
    lines.append(head)
    md.append(head)
    if f.get("resources"):
        lines.append(f"{L['resources']}: {', '.join(map(str, f['resources']))}")
        md.append(f"{L['resources']}: " + ", ".join(f"`{r}`" for r in f["resources"]))
    for key in MESSAGE_FIELDS:
        value = f.get(key)
        if value:
            lines.append(f"{L[key]}: {value}")
            md.append(f"**{L[key]}:** {md_text(value)}")
    if f.get("path"):
        lines.append(f"{L['path']}:\n{f['path']}")
        md.append(f"**{L['path']}:**  \n" + "  \n".join(md_text(e) for e in str(f["path"]).split("\n") if e))
    evidence = f.get("validation", {}).get("evidence")
    if evidence:
        lines.append(f"{L['evidence']}: {evidence}")
        md.append(f"**{L['evidence']}:** {md_text(evidence)}")
    return {"text": clean("\n".join(lines)), "markdown": clean("\n\n".join(md))}


def code_flows(f, paths, clean):
    flows = []
    for ap_id in f.get("attack_paths", []) or []:
        ap = paths.get(ap_id)
        if not ap:
            continue
        steps = []
        for edge in ap.get("edges", []):
            loc = {"message": {"text": clean(edge)}}
            m = render.CITED.search(str(edge))  # the cite validate() requires
            where = physical(m.group()) if m else None
            if where:
                loc["physicalLocation"] = where
            steps.append({"location": loc})
        if steps:
            flows.append({"message": {"text": clean(f"{ap_id} ({ap.get('status')}): {ap.get('entry')} → "
                                                   f"{ap.get('target')}")},
                          "threadFlows": [{"locations": steps}]})
    return flows


def tags(f):
    out = ["security", f"infra-security-scan/{slug(f.get('category'))}", f"provider/{f.get('provider')}"]
    cwe = f.get("cwe")
    if isinstance(cwe, str) and cwe.startswith("CWE-"):
        out.append(f"external/cwe/{cwe.lower()}")
    return out


def baseline_rules():
    try:
        import iac_scan
    except Exception:  # noqa: BLE001 - the export still works without rule metadata
        return {}
    return iac_scan.RULES


def build(data, lang="en", min_severity="Info", masked=False, counted_only=False):
    clean = Text(masked)
    L = LABELS[lang]
    covered = render.covered_by(data)
    paths = {a.get("id"): a for a in data.get("attack_paths", []) if isinstance(a, dict)}
    catalog = baseline_rules()
    limit = SEV_RANK[min_severity]
    rules, results, worst = {}, [], {}
    for f in render.ordered([f for f in data.get("findings", []) if isinstance(f, dict)]):
        sev = f.get("severity")
        if SEV_RANK.get(sev, 9) > limit:
            continue
        excluded = render.is_excluded(f)
        cover = covered.get(f.get("id"))
        if counted_only and (excluded or cover):
            continue
        rid = rule_id(f)
        rule = rules.get(rid)
        if rule is None:
            if rid in catalog:
                title, _, category, _, controls, cwe = catalog[rid]
                rule = {"id": rid, "name": rid,
                        "shortDescription": {"text": clean(render.shown(title, lang))},
                        "fullDescription": {"text": clean(render.shown(title, lang))},
                        "properties": {"tags": tags({"category": category, "provider": f.get("provider"), "cwe": cwe}),
                                       "category": category}}
                if controls:
                    rule["properties"]["controls"] = [clean(c) for c in controls]
            else:
                category = render.shown(f.get("category"), lang)
                rule = {"id": rid, "name": rid,
                        "shortDescription": {"text": clean(L["review_rule"].format(category))},
                        "fullDescription": {"text": clean(L["review_help"].format(category))},
                        "properties": {"tags": ["security", f"infra-security-scan/{slug(f.get('category'))}"],
                                       "category": f.get("category")}}
            rule["helpUri"] = INFORMATION_URI
            rule["defaultConfiguration"] = {"level": LEVEL.get(sev, "note")}
            rule["properties"]["security-severity"] = SECURITY_SEVERITY.get(sev, "0.5")
            rules[rid] = rule
        elif sev in SEV_RANK and SEV_RANK[sev] < worst[rid]:
            # The worst result decides the rule's grade: GitHub reads severity per rule.
            rule["properties"]["security-severity"] = SECURITY_SEVERITY[sev]
            rule["defaultConfiguration"]["level"] = LEVEL[sev]
        worst[rid] = min(worst.get(rid, 9), SEV_RANK.get(sev, 9))
        result = {"ruleId": rid, "level": LEVEL.get(sev, "note"), "message": message(f, lang, clean),
                  "partialFingerprints": {"infraSecurityScan/v1": fingerprint(f)},
                  "properties": {"id": f.get("id"), "severity": sev, "confidence": f.get("confidence"),
                                 "verdict": f.get("validation", {}).get("verdict"),
                                 "category": f.get("category"), "provider": f.get("provider"),
                                 "security-severity": SECURITY_SEVERITY.get(sev, "0.5"), "tags": tags(f)}}
        loc = physical(f.get("location"))
        logical = [{"fullyQualifiedName": clean(r), "kind": "resource"} for r in f.get("resources", [])]
        location = {}
        if loc:
            location["physicalLocation"] = loc
        if logical:
            location["logicalLocations"] = logical
        if location:
            result["locations"] = [location]
        for key in ("controls", "attack_paths"):
            if f.get(key):
                result["properties"][key] = [clean(x) for x in f[key]]
        if f.get("cwe"):
            result["properties"]["cwe"] = f["cwe"]
        if f.get("references"):
            result["properties"]["references"] = [{"title": clean(r.get("title", "")), "url": clean(r.get("url", ""))}
                                                  for r in f["references"] if isinstance(r, dict)]
        flows = code_flows(f, paths, clean)
        if flows:
            result["codeFlows"] = flows
        if excluded:
            verdict = render.shown(f["validation"]["verdict"], lang)
            reason = L["excluded"].format(verdict)
            evidence = f["validation"].get("evidence")
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": clean(f"{reason} {evidence}" if evidence else reason)}]
        elif cover:
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": clean(L["covered"].format(", ".join(cover)))}]
        results.append(result)
    meta = data.get("meta", {})
    run = {
        "tool": {"driver": {"name": "infra-security-scan", "informationUri": INFORMATION_URI,
                            "rules": sorted(rules.values(), key=lambda r: r["id"])}},
        "originalUriBaseIds": {"%SRCROOT%": {"description": {"text": "The assessed repository root"}},
                               "SNAPSHOTS": {"description": {"text": "Read-only exports the requester supplied "
                                                                     "(iac_scan.py --snapshots)"}}},
        "automationDetails": {"id": f"infra-security-scan/{slug(meta.get('project', 'estate'))}/"},
        "columnKind": "unicodeCodePoints",
        "results": results,
        "properties": {k: clean(meta[k]) for k in ("project", "scope", "date", "assessor", "method") if meta.get(k)},
    }
    if meta.get("commit"):
        # versionControlProvenance needs the repository URL, which the record does not hold.
        run["properties"]["commit"] = meta["commit"]
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}


def out_problem(out, findings_path):
    out = Path(out)
    if out.is_symlink() or has_symlink_parent(out):
        return f"{out} is a symlink or has a symlinked parent directory"
    if out.exists() and not out.is_file():
        return f"{out} is not a regular file"
    if out.parent.resolve() == Path(findings_path).resolve().parent:
        return (f"{out.parent} holds findings.json; the output directory's file set is fixed — "
                "write the SARIF log to scratch")
    return None


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("findings")
    p.add_argument("--out", required=True, help="SARIF file to write, in scratch")
    p.add_argument("--lang", choices=sorted(LABELS), default="en")
    p.add_argument("--min-severity", choices=SEVERITIES, default="Info", metavar="SEVERITY")
    p.add_argument("--mask", action="store_true", help="mask 12-digit account IDs and IPv4 addresses")
    p.add_argument("--counted-only", action="store_true",
                   help="leave out excluded findings and I-* covered by a review finding")
    a = p.parse_args(argv)
    try:
        data = render.load_record(a.findings)
        render.validate(data, partial=True)
    except render.SchemaError as e:
        for problem in e.problems:
            print(f"schema: {problem}", file=sys.stderr)
        return 2
    problem = out_problem(a.out, a.findings)
    if problem:
        print(f"refused: {problem}", file=sys.stderr)
        return 1
    log = build(data, a.lang, a.min_severity, a.mask, a.counted_only)
    out = Path(a.out)
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        write_output(out, json.dumps(log, ensure_ascii=False, indent=2) + "\n")
    except OSError as e:
        print(f"cannot write {out}: {e.strerror or e}", file=sys.stderr)
        return 2
    results = log["runs"][0]["results"]
    suppressed = sum(1 for r in results if r.get("suppressions"))
    print(f"wrote {len(results)} result(s) ({suppressed} suppressed) under "
          f"{len(log['runs'][0]['tool']['driver']['rules'])} rule(s) to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
