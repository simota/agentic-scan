#!/usr/bin/env python3
"""Measure what docs/quality/sqi-rubric.md scores. Development only; the skill never runs this.

    python3 docs/quality/audit.py code --out result.json
    python3 docs/quality/audit.py ui --out result.json --shots DIR [--axe axe.min.js] [--root CHECKOUT]

`code` needs only the standard library (ruff is used when present). `ui` needs Python Playwright with Chromium,
and axe-core when --axe is given. Both accept --root, so two checkouts are measured by the same script.
"""
import argparse
import ast
import json
import multiprocessing
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[2]
VIEWPORTS = {"desktop": (1440, 900), "tablet": (768, 1024), "mobile": (390, 844)}

# (name, fragment text). A clean refusal is exit 2 with no traceback, or exit 0 when the record stays faithful.
FRAGMENTS = [
    ("section is a number", '{"gates": 3}'),
    ("section is a string", '{"findings": "x"}'),
    ("meta is a string", '{"meta": "x"}'),
    ("fragment is a list", "[]"),
    ("summary is a number", '{"summary": 3}'),
    ("string list given as a string", '{"next_steps": "do"}'),
    ("remove is a list", '{"remove": []}'),
    ("remove items is a string", '{"remove": {"next_steps": "x"}}'),
    ("perspective is a string", '{"perspectives": ["x"]}'),
    ("perspectives is a string", '{"perspectives": "x"}'),
    ("surface without id", '{"findings":[{"id":"BG-001","title":"t","status":"Open","pattern":"BP01","surfaces":[{"op":"x"}]}]}'),
    ("surfaces is a number", '{"findings":[{"id":"BG-001","title":"t","status":"Open","pattern":"BP01","surfaces":3}]}'),
    ("pattern is a list", '{"findings":[{"id":"BG-001","title":"t","status":"Open","pattern":["x"]}]}'),
    ("status is a list", '{"findings":[{"id":"BG-001","title":"t","status":["Open"]}]}'),
    ("location is a number", '{"findings":[{"id":"BG-001","title":"t","status":"Open","pattern":"BP01","location":3}]}'),
    ("id is a list", '{"findings":[{"id":["x"],"title":"t","status":"Open"}]}'),
    ("relations is a number", '{"findings":[{"id":"BG-001","title":"t","status":"Open","relations":3}]}'),
    ("path is a string", '{"findings":[{"id":"BG-001","title":"t","status":"Open","path":"x"}]}'),
    ("siblings is a number", '{"findings":[{"id":"BG-001","title":"t","status":"Open","sibling_sites":3}]}'),
    ("repro steps is a number", '{"findings":[{"id":"BG-001","title":"t","status":"Open","repro":{"state":"static","steps":3,"expected":"e"}}]}'),
    ("event origin commits is a number", '{"fix_events":[{"id":"E-1","commit":"abcd","type":"omission","pattern":"BP01","detected":"ci","module":"m","origin":{"channel":"none","strength":"Traced","commits":3}}]}'),
    ("issue feeds is a number", '{"issues":[{"id":"I-1","kind":"k","at":"a","feeds":3}]}'),
]


def run(command, **kw):
    return subprocess.run(command, capture_output=True, text=True, **kw)


def corpus(scripts):
    """Run each malformed fragment through the real CLI. A traceback is a failure; so is a record silently corrupted."""
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for index, (name, text) in enumerate(FRAGMENTS):
            out = Path(tmp) / str(index)
            fragment = Path(tmp) / f"{index}.json"
            fragment.write_text(text, encoding="utf-8")
            done = run([sys.executable, "-B", str(scripts / "findings.py"), "merge", str(out / "findings.json"), str(fragment)])
            traceback = "Traceback" in done.stderr
            corrupted = done.returncode == 0 and name == "string list given as a string"
            rows.append(dict(case=name, exit=done.returncode, traceback=traceback, corrupted=corrupted,
                             message=done.stderr.strip().splitlines()[-1][:160] if done.stderr.strip() else ""))
    return rows


def render_refusals(scripts, examples):
    """Records that pass the merge shape check but reference something absent. Render must name the problem."""
    code = r"""
import copy, sys
sys.path.insert(0, sys.argv[1]); sys.dont_write_bytecode = True
import common, render
r, s, h = [common.load_json(sys.argv[2] + "/" + n + ".sample.json") for n in ("findings", "surfaces", "history")]
def attempt(name, record):
    try:
        render.build(record, s, h, "en"); print(name, "rendered")
    except (common.RecordError, render.report.FormatError) as error:
        print(name, "named-error", str(error)[:90].replace("\n", " "))
    except Exception as error:
        print(name, "CRASH", type(error).__name__, str(error)[:60])
a = copy.deepcopy(r); a["findings"][0]["relations"] = [dict(type="blocks", to="BG-099", strength="Traced", evidence="x")]; attempt("relation-to-missing-id", a)
a = copy.deepcopy(r); next(e for e in a["fix_events"] if e.get("gate_missed"))["gate_missed"] = ["G-99"]; attempt("unknown-gate", a)
a = copy.deepcopy(r); a["findings"][0]["surfaces"] = [dict(id="API-99")]; attempt("unknown-surface", a)
"""
    return run([sys.executable, "-c", code, str(scripts), str(examples)]).stdout.strip().splitlines()


def _merge_worker(args):
    scripts, directory, worker = args
    sys.path.insert(0, scripts)
    sys.dont_write_bytecode = True
    import findings
    for i in range(25):
        path = f"{directory}/f{worker}_{i}.json"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump({"next_steps": [f"s{worker}-{i}"]}, handle)
        findings.merge(f"{directory}/findings.json", [path])


def lost_updates(scripts):
    out = []
    for _ in range(3):
        with tempfile.TemporaryDirectory() as tmp:
            with multiprocessing.get_context("spawn").Pool(8) as pool:
                pool.map(_merge_worker, [(str(scripts), tmp, w) for w in range(8)])
            out.append(200 - len(json.loads(Path(tmp, "findings.json").read_text(encoding="utf-8"))["next_steps"]))
    return out


def import_graph(scripts):
    names = {p.stem for p in scripts.glob("*.py")}
    graph = {}
    for path in scripts.glob("*.py"):
        imported = set()
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".")[0])
        graph[path.stem] = sorted(imported & names)
    return graph


def cycles(graph):
    found = []

    def walk(node, trail):
        for target in graph[node]:
            if target in trail:
                found.append(trail[trail.index(target):] + [target])
            else:
                walk(target, trail + [target])

    for start in graph:
        walk(start, [start])
    return sorted({"->".join(c) for c in found})


def code_audit(root):
    scripts = root / "skills" / "bug-scan" / "scripts"
    own = sorted(scripts.glob("*.py"))
    text = {p.name: p.read_text(encoding="utf-8") for p in own}
    all_text = "".join(text.values())
    literal = {
        "closed status literal outside common": sum(t.count('("Fixed", "Verified")') for n, t in text.items() if n != "common.py"),
        "excluded verdict literal outside common": sum(t.count('("FalsePositive", "NotApplicable")') for n, t in text.items() if n != "common.py"),
        "severity order literal outside common": sum(t.count('("High", "Medium", "Low", "Info")') for n, t in text.items() if n != "common.py"),
        "text-cleaning helper copies": len(re.findall(r'EMAIL\.sub\("\[email\]", redact', all_text)),
        "is_excluded copies": len(re.findall(r"\bdef (?:is_excluded|excluded)\(", all_text)),
    }
    corpus_rows = corpus(scripts)
    graph = import_graph(scripts)
    result = dict(
        corpus=corpus_rows,
        corpus_tracebacks=sum(r["traceback"] for r in corpus_rows),
        corpus_corrupted=sum(r["corrupted"] for r in corpus_rows),
        corpus_cases=len(corpus_rows),
        render_refusals=render_refusals(scripts, root / "examples"),
        lost_updates_per_200=lost_updates(scripts),
        import_graph=graph,
        import_cycles=cycles(graph),
        duplicate_rules=literal,
        own_python_lines=sum(t.count("\n") for t in text.values()),
    )
    done = run(["ruff", "check", str(scripts), "--exclude", "scan_report_kit", "--select", "C901,E741,E731,F,B", "--output-format", "concise", "--isolated"])
    if done.returncode in (0, 1):
        result["ruff"] = sorted({m: len(re.findall(rf"\b{m}\b", done.stdout)) for m in ("C901", "E741", "E731", "F401", "F841", "B905")}.items())
    tests = run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"], cwd=root)
    result["tests"] = tests.stderr.strip().splitlines()[-3:]
    manifest = run(["shasum", "-a", "256", "-c", "--quiet", "MANIFEST"], cwd=scripts / "scan_report_kit")
    result["kit_manifest_ok"] = manifest.returncode == 0
    code = ("import sys,time,statistics;sys.path.insert(0,sys.argv[1]);sys.dont_write_bytecode=True;import common,render;"
            "r,s,h=[common.load_json(sys.argv[2]+'/'+n+'.sample.json') for n in('findings','surfaces','history')];"
            "t=[];[(a:=time.perf_counter(),render.build(r,s,h,'ja'),t.append(time.perf_counter()-a)) for _ in range(30)];"
            "print(round(statistics.median(t)*1000,2))")
    result["render_build_ms_median30"] = float(run([sys.executable, "-c", code, str(scripts), str(root / "examples")]).stdout.strip())
    return result


PAGE_PROBE = r"""
() => {
  const bgOf = el => { for (let n = el; n; n = n.parentElement) { const c = getComputedStyle(n).backgroundColor; if (c && !/rgba\(.*, 0\)|transparent/.test(c)) return c; } return 'rgb(255,255,255)'; };
  const rgb = c => { const m = c.match(/[\d.]+/g).map(Number); return m; };
  const lum = c => { const a = c.slice(0,3).map(v => { v/=255; return v<=.03928? v/12.92: Math.pow((v+.055)/1.055,2.4); }); return .2126*a[0]+.7152*a[1]+.0722*a[2]; };
  const ratio = (a,b) => { const x=lum(a), y=lum(b); return (Math.max(x,y)+.05)/(Math.min(x,y)+.05); };
  const blend = (top, alpha, under) => top.slice(0,3).map((v,i)=>v*alpha+under[i]*(1-alpha));
  const out = {overflow: document.documentElement.scrollWidth - innerWidth, svgs: [], low: [], overlaps: 0, escape: 0, overBox: 0, sizes: []};
  document.querySelectorAll('.bsf svg[viewBox]').forEach(svg => {
    const vb = svg.viewBox.baseVal, box = svg.getBoundingClientRect(), scale = box.width / vb.width;
    const page = rgb(bgOf(svg));
    const shapes = [...svg.querySelectorAll('rect')].map(r => ({r, b: r.getBBox(), s: getComputedStyle(r)}));
    const rects = [];
    svg.querySelectorAll('text').forEach(t => {
      const cs = getComputedStyle(t), size = parseFloat(cs.fontSize) * scale, b = t.getBoundingClientRect(), bb = t.getBBox();
      out.sizes.push(size);
      if (t.textContent) rects.push({b, t: t.textContent});
      if (b.right > box.right + 1 || b.left < box.left - 1) out.escape++;
      const cx = bb.x + bb.width/2, cy = bb.y + bb.height/2;
      let under = page, inside = null;
      if (!t.getAttribute('transform')) shapes.forEach(({b:rb, s}) => {
        if (cx>=rb.x && cx<=rb.x+rb.width && cy>=rb.y && cy<=rb.y+rb.height) {
          inside = rb;
          const f = s.fill; if (f && f !== 'none' && !/rgba\(.*, 0\)/.test(f)) under = blend(rgb(f), parseFloat(s.opacity||1), under);
        }
      });
      if (inside && bb.x + bb.width > inside.x + inside.width + 0.5) out.overBox++;
      const r = ratio(rgb(cs.fill), under);
      if (r < 4.5) out.low.push({text: t.textContent.slice(0,24), cls: t.getAttribute('class'), ratio: +r.toFixed(2), fig: svg.closest('[id^=fig-]').id});
    });
    for (let i=0;i<rects.length;i++) for (let j=i+1;j<rects.length;j++) {
      const a=rects[i].b,b=rects[j].b, w=Math.min(a.right,b.right)-Math.max(a.left,b.left), h=Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top);
      if (w>1.5 && h>3) out.overlaps++;
    }
    out.svgs.push({fig: svg.closest('[id^=fig-]').id, width: Math.round(box.width), scale: +scale.toFixed(2)});
  });
  const s = out.sizes.sort((a,b)=>a-b);
  out.minFontPx = s.length ? +s[0].toFixed(1) : null;
  out.medianFontPx = s.length ? +s[Math.floor(s.length/2)].toFixed(1) : null;
  out.textBelow10px = s.filter(v=>v<10).length; out.textCount = s.length; delete out.sizes;
  const focusable = [...document.querySelectorAll('a[href],button,select,input,summary,[tabindex]')].filter(e => {
    const ti = e.getAttribute('tabindex'); if (ti === '-1') return false;
    if (e.closest('details:not([open])') && e.tagName !== 'SUMMARY') return false;
    return e.getClientRects().length > 0;
  });
  const reg = focusable.findIndex(e => e.matches('button.finding-toggle'));
  out.focusable = focusable.length; out.tabStopsBeforeFirstRecord = reg;
  out.figureTabStops = focusable.filter(e => e.closest('.bsf svg')).length;
  const f = document.querySelector('#findings'); const fig = document.querySelector('#figures');
  out.registerTopInScreens = f ? +(f.getBoundingClientRect().top + scrollY) / innerHeight : null;
  out.figuresBeforeRegister = !!(f && fig && (fig.compareDocumentPosition(f) & Node.DOCUMENT_POSITION_FOLLOWING));
  out.pageHeightScreens = +(document.documentElement.scrollHeight / innerHeight).toFixed(1);
  out.registerTopInScreens = out.registerTopInScreens === null ? null : +out.registerTopInScreens.toFixed(1);
  return out;
}
"""


def axe_summary(page, axe):
    if not axe:
        return None
    page.add_script_tag(path=axe)
    report = page.evaluate("""async () => { const r = await axe.run(document, {runOnly: {type: 'tag', values: ['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice']}});
      return r.violations.map(v => ({id: v.id, impact: v.impact, nodes: v.nodes.length, inOverlay: v.nodes.filter(n => n.target.join(' ').match(/fig-d|figures|\\.bsf|bs-tip/)).length, sample: v.nodes[0].target.join(' ').slice(0,90)})); }""")
    return report


def focus_visibility(page):
    """Share of focusable figure parts whose pixels change when focused, tooltip hidden. E2 for focus visibility."""
    page.add_style_tag(content="#bs-tip{visibility:hidden!important}html{scroll-behavior:auto!important}")
    handles = page.query_selector_all(".bsf svg [tabindex], .bsf svg a[href]")
    page.keyboard.press("Tab")
    visible = total = 0
    missing = {}
    for handle in handles:
        handle.evaluate("e => e.setAttribute('tabindex', '0')")
        handle.scroll_into_view_if_needed()
        box = handle.bounding_box()
        if not box or box["width"] < 1 or box["height"] < 1:
            continue
        clip = dict(x=max(box["x"] - 4, 0), y=max(box["y"] - 4, 0), width=box["width"] + 8, height=box["height"] + 8)
        page.evaluate("document.activeElement && document.activeElement.blur()")
        before = page.screenshot(clip=clip)
        handle.evaluate("e => e.focus()")
        total += 1
        if page.screenshot(clip=clip) != before:
            visible += 1
        else:
            kind = handle.evaluate("e => e.closest('[id^=fig-]').id + ':' + e.tagName")
            missing[kind] = missing.get(kind, 0) + 1
    return dict(checked=total, visible=visible, missing=missing)


def tasks(page, url):
    """Scripted tasks, not user testing: they show a path exists and how many interactions it takes."""
    out = {}
    page.goto(url)
    page.locator("#priority article h3 a").first.click()
    page.wait_for_timeout(100)
    out["T1 open first-priority defect: clicks"] = 1 if page.locator("tr.detail:not([hidden])").count() else None
    page.goto(url)
    link = page.locator('#fig-d7 svg a[href^="#finding-"]')
    if link.count():
        link.first.click(force=True)
        page.wait_for_timeout(100)
        out["T2 figure to record: interactions"] = 1 if page.locator("tr.detail:not([hidden])").count() else None
    else:
        out["T2 figure to record: interactions"] = "no link; read the ID, focus search, type it, open the row (3+)"
    page.goto(url)
    start = time.perf_counter()
    page.locator('.nav-links a[href="#findings"]').first.click()
    page.wait_for_timeout(50)
    out["T3 reach register: nav click ms"] = round((time.perf_counter() - start) * 1000)
    page.goto(url)
    page.select_option("#f-sev", "High")
    out["T4 filter to High: rows"] = page.locator("tr.row").count()
    page.goto(url)
    page.locator('#fig-d7 svg [tabindex="0"]').first.focus()
    start_id = page.evaluate("document.activeElement.getAttribute('aria-label') || document.activeElement.getAttribute('data-tip')")
    page.keyboard.press("ArrowRight")
    moved = page.evaluate("document.activeElement.getAttribute('aria-label') || document.activeElement.getAttribute('data-tip')")
    out["T5 arrow moves inside a figure"] = moved != start_id
    out["T5 figure part has an accessible name"] = bool(page.evaluate("document.activeElement.getAttribute('aria-label')"))
    page.keyboard.press("Tab")
    out["T5 tab leaves the figure"] = page.evaluate("!document.activeElement.closest('#fig-d7 svg')")
    page.goto(url)
    page.evaluate("window.scrollTo({top: document.documentElement.scrollHeight, behavior: 'instant'})")
    page.wait_for_timeout(200)
    out["nav current at page end"] = page.evaluate("(document.querySelector('.nav-links a[aria-current]')||{getAttribute(){return null}}).getAttribute('href')")
    return out


def perf(page, url):
    runs = []
    for _ in range(9):
        page.goto(url)
        runs.append(page.evaluate("""() => new Promise(done => { let cls = 0;
          new PerformanceObserver(l => l.getEntries().forEach(e => { if (!e.hadRecentInput) cls += e.value; })).observe({type: 'layout-shift', buffered: true});
          setTimeout(() => { const n = performance.getEntriesByType('navigation')[0];
            done({dcl: n.domContentLoadedEventEnd, load: n.loadEventEnd, cls}); }, 300); })"""))
    toggle = []
    for _ in range(9):
        toggle.append(page.evaluate("""() => { const b = document.querySelector('button.finding-toggle'); const t = performance.now(); b.click(); document.body.offsetHeight; const d = performance.now() - t; b.click(); return d; }"""))
    return dict(dcl_ms=round(statistics.median(r["dcl"] for r in runs), 1), load_ms=round(statistics.median(r["load"] for r in runs), 1),
                cls=round(statistics.median(r["cls"] for r in runs), 4), toggle_ms=round(statistics.median(toggle), 2))


def ui_audit(root, shots, axe, chromium=None):
    from playwright.sync_api import sync_playwright
    result = {}
    with tempfile.TemporaryDirectory() as tmp:
        for lang in ("ja", "en"):
            out = Path(tmp) / lang
            env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
            done = run(["make", "demo", f"DEMO_OUT={out}", f"LANG_OUT={lang}", "NO_PDF=1"], cwd=root, env=env)
            if done.returncode:
                raise SystemExit(done.stderr)
        result["bytes"] = {lang: {n: (Path(tmp) / lang / n).stat().st_size for n in ("dashboard.html", "report.html")} for lang in ("ja", "en")}
        with sync_playwright() as driver:
            browser = driver.chromium.launch(executable_path=chromium)
            for (vp_name, (w, h)) in VIEWPORTS.items():
                for scheme in ("light", "dark"):
                    context = browser.new_context(viewport=dict(width=w, height=h), color_scheme=scheme, locale="ja-JP")
                    page = context.new_page()
                    errors = []
                    page.on("pageerror", lambda e: errors.append(str(e)))
                    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
                    page.goto(f"file://{tmp}/ja/dashboard.html")
                    key = f"{vp_name}-{scheme}"
                    row = page.evaluate(PAGE_PROBE)
                    row["errors"] = errors
                    if shots:
                        Path(shots).mkdir(parents=True, exist_ok=True)
                        page.screenshot(path=f"{shots}/dashboard-{key}.png", full_page=True)
                        for number in (7, 8, 9, 1, 2, 3, 4, 5, 6):
                            if vp_name != "tablet" and scheme == "light" or number == 2:
                                page.locator(f"#fig-d{number}").screenshot(path=f"{shots}/fig-d{number}-{key}.png")
                    if vp_name == "desktop" or vp_name == "mobile":
                        page.locator("button.finding-toggle").first.click()
                        row["axe"] = axe_summary(page, axe)
                    result[f"dashboard/{key}"] = row
                    if scheme == "light":
                        report_page = context.new_page()
                        report_page.goto(f"file://{tmp}/ja/report.html")
                        probe = report_page.evaluate(PAGE_PROBE)
                        result[f"report/{vp_name}"] = {k: probe[k] for k in ("overflow", "minFontPx", "textBelow10px", "overlaps", "overBox", "figureTabStops", "focusable")}
                        if axe and vp_name == "desktop":
                            result["report/axe"] = axe_summary(report_page, axe)
                        if shots and vp_name == "desktop":
                            report_page.screenshot(path=f"{shots}/report-desktop.png", full_page=True)
                        report_page.close()
                    context.close()
            context = browser.new_context(viewport=dict(width=1440, height=900), locale="ja-JP")
            page = context.new_page()
            url = f"file://{tmp}/ja/dashboard.html"
            result["tasks"] = tasks(page, url)
            result["perf"] = perf(page, url)
            page.goto(url)
            result["focus_visibility"] = focus_visibility(page)
            page.goto(f"file://{tmp}/en/dashboard.html")
            result["en_figures"] = page.evaluate(r"""() => { const t = document.querySelector('#figures').innerHTML;
              return {ideographic_separators: (t.match(/ ・ |、/g) || []).length}; }""")
            result["en_axe"] = None
            browser.close()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=("code", "ui"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--root", default=str(HERE))
    parser.add_argument("--shots")
    parser.add_argument("--axe")
    parser.add_argument("--chromium", help="browser binary, when Playwright's pinned one is not installed")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    data = code_audit(root) if args.mode == "code" else ui_audit(root, args.shots, args.axe, args.chromium)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(data, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
