"""The bug-scan figures: inline SVG plus a table of the same facts, drawn only from the record.

A figure is presentation, never evidence. Every element comes from a record ID, every recorded
string is escaped, and a label cut to fit stays whole in the table. Standard library only.
"""
from collections import Counter, defaultdict
from datetime import date
from html import escape

from common import DEFECT_TYPES, LEVELS, RISK_TABLE, clip, clip_left, location_path, pattern_name

MIN_DEFECTS_FOR_HISTORY_FIGURES = 20
BLAMED_DASH = "9 5"
KIND_ORDER = ("screen", "api", "job", "db", "ext", "cfg")

TEXT = {
    "ja": dict(
        section="図解", section_note="図は記録から生成した表現で、証拠そのものではない。各図の表に同じ内容がある。",
        table="表で見る", omitted="省略", no_data="描画できる記録がありません。",
        channel=dict(feature="新機能", fix="修正", refactor="リファクタ", dependency="依存更新", config="設定", migration="移行", generated="生成・コピー", merge="マージ", unknown="不明", none="混入元なし（欠落）"),
        stage=dict(dev="開発中", ci="CI", release="リリース後", unknown="UNKNOWN"),
        gate_status=dict(present="✓ あり", absent="✕ なし", unknown="? UNKNOWN"),
        kind=dict(screen="画面", api="API", job="ジョブ", db="DB", ext="外部", cfg="設定"),
        level=dict(Low="低", Medium="中", High="高"),
        count="{n}件", traced="Traced（差分を読み因果を説明）", blamed="Blamed（blame のみ・未確認）", unattr="薄い帯: Unattributable（混入元なし）",
        solid="実線: Traced", dashed="破線: Blamed", release_key="リリース後に検知", other_key="それ以外",
        d1="混入経路マップ", d1q="どの変更から入り、どのゲートで止められたはずで、どこで見つかったか",
        d1cols=("変更経路", "止められたはずのゲート（推定）", "検知した段階"), no_gate="ゲート未記録",
        d1foot="欠陥と分類した {n} 件のうち {r} 件がリリース後に検知された。ゲートの列はレビューでの推定で、実際に通過したことは示さない。判定できない段階は UNKNOWN のまま描く。",
        d1heads=("変更経路", "パターン", "ゲート", "検知", "根拠", "件数"),
        d2="パターン × モジュール", d2q="どこで何が繰り返しているか", d2key="Traced 件数", d2cell="セルの表記: Traced / 全件", d2hot="Traced 3件以上（繰り返し）", d2total="計",
        d2foot="色は Traced の件数だけで決める。Blamed と混入元なしは分母にのみ入れる。",
        d2heads=("モジュール", "パターン", "Traced", "全件"),
        d3="fix 連鎖", d3q="修正が次の修正を生んでいないか", d3fix="fix commit", d3other="fix 以外の commit", d3orphan="混入元のない fix",
        d3foot="基準率と並べて読む: 混入元候補のうち fix は {a}/{b} 件（{p}%）、期間内の全 commit のうち fix は {c}/{d} 件（{q}%）。1 行が 1 つの連鎖で、長い順に上位 {n} 件を描く。行内の間隔は読みやすさのため時刻どおりではない（日付はホバーで確認できる）。",
        d3heads=("モジュール", "混入元", "修正", "根拠"),
        d3cut="長い連鎖は新しい {n} 件だけを描く。全件は表にある。", d3thin="欠陥修正が {n} 件で、基準の {m} 件に満たないか履歴が shallow のため省略した。傾向を読める量がない。",
        d4="ホットスポット象限", d4q="危険な場所はどこか", d4x="変更頻度（期間内の commit 数）", d4y="欠陥修正の密度（100 commit あたり）", d4tested="テストあり", d4untested="テストなし（ファイル名から推定）", d4median="中央値", d4hot="よく変わり、欠陥も多い",
        d4foot="ラベルは注目点だけに付け、残りはホバーと表で読む。テストの有無はファイル名からの推定。commit 数が少ないほど密度はぶれやすい。",
        d4heads=("モジュール", "commit", "欠陥修正", "密度/100", "テストファイル"),
        d5="現存の入口", d5q="同じバグが今どの経路で起きうるか", d5state=dict(allowed="✓", blocked="■", unknown="?"), d5unreached="（未到達）", d5events="根拠の修正履歴: ",
        d5foot="最初の blocked または UNKNOWN で判定を止める。止まった経路も確認した結果として残す。",
        d5heads=("ID", "from", "to", "判定", "場所", "理由"),
        d6="課題 → パターン", d6q="どのコード課題がどのパターンを生んでいるか", d6cols=("コード課題", "バグパターン（欠陥修正の件数）", "現在のコードでの結果"), d6none="現在の入口は未確認",
        d6foot="太線は最も重い不具合に至る経路。つながりは因果の証明ではなく、直して再計測して確かめる仮説。",
        d6heads=("課題", "場所", "パターン"),
        d7="不具合の関連", d7q="どの不具合がどれとつながり、どれを先に直すべきか", d7shared="同じ DB またはジョブを使用（自動算出）",
        relation=dict(regression_of="再発", caused_by="原因", same_root_cause="同根", blocks="先に直す", duplicate_of="重複"),
        d7foot="矢印は根拠つきの関連。細い線は対象の共有から機械的に求めたもので、因果を意味しない。関連のない {n} 件は描いていない。",
        d7heads=("from", "関連", "to", "根拠の強さ", "根拠"), d7auto="自動算出",
        d8="対象マップ（画面 → API → DB）", d8q="この不具合はどの画面、API、テーブルに及ぶか", d8pick="不具合", d8all="選択なし（全体）", d8open="未解決 {n}", d8imports="他 scan {n}", d8cols=("画面", "API・ジョブ", "DB・外部"),
        d8foot="不具合が参照する対象と、その隣接だけを描く。対応は静的な読み取りで、動的な呼び出しは漏れることがある。",
        d8heads=("ID", "種別", "名前", "場所", "読み取り", "関連する不具合", "他 scan の指摘"),
        d9="リスク × 危険性", d9q="どれが危なく、どれを先に見るべきか", d9x="発生可能性", d9y="影響", d9risk="リスク", d9irr="不可逆", d9silent="無音",
        d9foot="未解決の不具合だけを置く。段階は固定の表で決め、数値スコアは作らない。発生可能性はコードからの推定で、実測ではない。",
        d9heads=("ID", "発生可能性", "影響", "リスク", "危険性", "不可逆", "無音", "判定根拠"),
    ),
    "en": dict(
        section="Figures", section_note="Figures are drawn from the record and are not evidence themselves. Each has a table of the same facts.",
        table="Show as table", omitted="Omitted", no_data="Nothing recorded to draw.",
        channel=dict(feature="Feature", fix="Fix", refactor="Refactor", dependency="Dependency", config="Config", migration="Migration", generated="Generated", merge="Merge", unknown="Unknown", none="No origin (omission)"),
        stage=dict(dev="In development", ci="CI", release="After release", unknown="UNKNOWN"),
        gate_status=dict(present="✓ present", absent="✕ absent", unknown="? UNKNOWN"),
        kind=dict(screen="Screen", api="API", job="Job", db="DB", ext="External", cfg="Config"),
        level=dict(Low="Low", Medium="Medium", High="High"),
        count="{n}", traced="Traced (diffs read, cause explained)", blamed="Blamed (blame only, unconfirmed)", unattr="Faint band: Unattributable (no origin)",
        solid="Solid: Traced", dashed="Dashed: Blamed", release_key="Detected after release", other_key="Other",
        d1="Injection path map", d1q="Which change let it in, which gate should have stopped it, and where was it found",
        d1cols=("Change channel", "Gate that should have stopped it (judged)", "Detected at"), no_gate="No gate recorded",
        d1foot="{r} of {n} classified defects were detected after release. The gate column is a judgement from review and does not show what a change passed. Stages that cannot be read stay UNKNOWN.",
        d1heads=("Channel", "Pattern", "Gate", "Detected", "Strength", "Count"),
        d2="Pattern by module", d2q="What repeats, and where", d2key="Traced count", d2cell="Cell: Traced / all", d2hot="3 or more Traced (recurring)", d2total="Sum",
        d2foot="Colour follows the Traced count only. Blamed and unattributable events count only in the denominator.",
        d2heads=("Module", "Pattern", "Traced", "All"),
        d3="Fix chains", d3q="Do fixes breed further fixes", d3fix="Fix commit", d3other="Other commit", d3orphan="Fix with no origin",
        d3foot="Read against the base rate: fixes are {a}/{b} of origin candidates ({p}%) and {c}/{d} of all commits in the window ({q}%). Each row is one chain, longest first ({n} drawn); spacing inside a row is not to scale (hover for the date).",
        d3heads=("Module", "Origin", "Fix", "Strength"),
        d3cut="Long chains show their newest {n} commits; the table has them all.", d3thin="Omitted: {n} defect fixes is below the {m} needed to read a trend, or the history is shallow.",
        d4="Hotspot quadrant", d4q="Where is it dangerous", d4x="Change frequency (commits in the window)", d4y="Defect-fix density (per 100 commits)", d4tested="Tests present", d4untested="No tests (judged from file names)", d4median="median", d4hot="Changes often, many defects",
        d4foot="Only the notable points are labelled; hover or read the table for the rest. Test presence is judged from file names. Density swings more at low commit counts.",
        d4heads=("Module", "Commits", "Defect fixes", "Density/100", "Test files"),
        d5="Live entry points", d5q="How could the same bug happen today", d5state=dict(allowed="✓", blocked="■", unknown="?"), d5unreached=" (not reached)", d5events="Fix history: ",
        d5foot="A path stops at its first blocked or UNKNOWN hop. Stopped paths stay on record as what was checked.",
        d5heads=("ID", "From", "To", "State", "Location", "Why"),
        d6="Issues to patterns", d6q="Which code issues feed which patterns", d6cols=("Code issue", "Bug pattern (defect fixes)", "Result in current code"), d6none="Live entry not confirmed",
        d6foot="The bold line leads to the most severe record. A link is a hypothesis to test by fixing and measuring again, not a proof of cause.",
        d6heads=("Issue", "Where", "Patterns"),
        d7="Related defects", d7q="What connects to what, and what to fix first", d7shared="Same DB or job (computed)",
        relation=dict(regression_of="Regression", caused_by="Cause", same_root_cause="Same root", blocks="Fix first", duplicate_of="Duplicate"),
        d7foot="Arrows carry evidence. Thin lines are computed from shared surfaces and do not imply cause. {n} records with no relation are not drawn.",
        d7heads=("From", "Relation", "To", "Strength", "Evidence"), d7auto="computed",
        d8="Surface map (screen → API → DB)", d8q="Which screens, APIs and tables does this defect reach", d8pick="Defect", d8all="None (everything)", d8open="{n} open", d8imports="{n} other scan", d8cols=("Screen", "API and job", "DB and external"),
        d8foot="Only surfaces a defect cites, and their neighbours, are drawn. Links come from static reading, so dynamic calls can be missed.",
        d8heads=("ID", "Kind", "Name", "Location", "Basis", "Defects", "Other scans"),
        d9="Risk and hazard", d9q="What is dangerous, and what to look at first", d9x="Likelihood", d9y="Impact", d9risk="Risk", d9irr="irreversible", d9silent="silent",
        d9foot="Unresolved records only. Levels come from a fixed table, with no numeric score. Likelihood is judged from code, not measured.",
        d9heads=("ID", "Likelihood", "Impact", "Risk", "Hazard", "Irreversible", "Silent", "Basis"),
    ),
}


def e(value):
    return escape(str(value), quote=True)


def tip(text):
    return f' tabindex="0" data-tip="{e(text)}"'


def text(x, y, value, cls="", anchor="start", halo=False):
    suffix = " halo" if halo else ""
    return f'<text x="{x:.1f}" y="{y:.1f}" class="{cls}{suffix}" text-anchor="{anchor}">{e(value)}</text>'


def svg(width, height, body, label):
    return f'<svg viewBox="0 0 {width} {height:.0f}" role="img" aria-label="{e(label)}" xmlns="http://www.w3.org/2000/svg">{body}</svg>'


def line_key(dash=""):
    extra = f' stroke-dasharray="{dash}"' if dash else ""
    return f'<svg width="34" height="10" aria-hidden="true"><line x1="1" y1="5" x2="33" y2="5" class="k-line"{extra}/></svg>'


def legend(items):
    return '<div class="legend">' + "".join(f'<span class="key">{mark}{e(label)}</span>' for mark, label in items) + "</div>"


def arrow_def(name):
    return (f'<defs><marker id="{name}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto">'
            '<path d="M0 0 L10 5 L0 10 z" class="arrow"/></marker></defs>')


def fig(number, title, question, body=None, foot="", heads=(), rows=(), legend_html="", omitted=None, control=""):
    return dict(number=number, title=title, question=question, svg=body, foot=foot, heads=heads, rows=rows,
                legend=legend_html, omitted=omitted, control=control)


def defects(record):
    return [ev for ev in record.get("fix_events", []) if ev.get("type") in DEFECT_TYPES]


def d1(record, t, lang):
    events = defects(record)
    if not events:
        return fig(1, t["d1"], t["d1q"], omitted=t["no_data"])
    gates = {g["id"]: g for g in record.get("gates", [])}
    gate_of = lambda ev: (ev.get("gate_missed") or [None])[0] or "none"
    tot = [Counter(), Counter(), Counter()]
    first, second = Counter(), Counter()
    for ev in events:
        origin, gate = ev["origin"], gate_of(ev)
        tot[0][origin["channel"]] += 1
        tot[1][gate] += 1
        tot[2][ev["detected"]] += 1
        first[(origin["channel"], gate, origin["strength"])] += 1
        second[(gate, ev["detected"], origin["strength"])] += 1
    orders = [[c for c in t["channel"] if tot[0][c]], [g for g in [*gates, "none"] if tot[1][g]], [s for s in t["stage"] if tot[2][s]]]
    width, top, gap = 960, 46, 26
    k = min(6.5, 300 / len(events))
    xs = [175, 470, 810]
    spans = [sum(tot[i][n] * k for n in order) + gap * (len(order) - 1) for i, order in enumerate(orders)]
    tallest = max(spans)
    pos = [{}, {}, {}]
    for i, order in enumerate(orders):
        y = top + (tallest - spans[i]) / 2
        for name in order:
            pos[i][name] = y
            y += tot[i][name] * k + gap
    out = [text(x, 22, head, "colhead", "middle") for x, head in zip(xs, t["d1cols"])]
    gate_name = lambda g: gates[g]["name"] if g in gates else t["no_gate"]
    used = [defaultdict(float) for _ in range(4)]

    def ribbons(flows, column, left, right, colour, label_of):
        for (a, b, strength), n in sorted(flows.items(), key=lambda row: (orders[column].index(row[0][0]), orders[column + 1].index(row[0][1]), row[0][2])):
            thick = n * k
            y1 = pos[column][a] + used[left][a] + thick / 2
            y2 = pos[column + 1][b] + used[right][b] + thick / 2
            used[left][a] += thick
            used[right][b] += thick
            x1, x2 = xs[column] + 7, xs[column + 1] - 7
            middle = (x1 + x2) / 2
            dash = ' stroke-dasharray="10 5"' if strength == "Blamed" else ""
            faint = " rib-u" if strength == "Unattributable" else ""
            label = f"{label_of(a)} → {label_of(b)}: {n} ({strength})"
            out.append(f'<path d="M{x1} {y1:.1f} C{middle} {y1:.1f} {middle} {y2:.1f} {x2} {y2:.1f}" class="rib {colour(b)}{faint}" stroke-width="{thick:.1f}"{dash}{tip(label)}/>')

    ribbons(first, 0, 0, 1, lambda _: "rib-a", lambda n: t["channel"].get(n) or gate_name(n))
    ribbons(second, 1, 2, 3, lambda s: "rib-b" if s == "release" else "rib-a", lambda n: t["stage"].get(n) or gate_name(n))
    for i, order in enumerate(orders):
        for name in order:
            height = tot[i][name] * k
            cls = "node-b" if name == "release" else "node"
            out.append(f'<rect x="{xs[i] - 7}" y="{pos[i][name]:.1f}" width="14" height="{max(height, 2):.1f}" rx="3" class="{cls}"/>')
            middle = pos[i][name] + height / 2 + 5
            count = t["count"].format(n=tot[i][name])
            if i == 0:
                out.append(text(xs[i] - 14, middle, f"{t['channel'][name]} {count}", "lab", "end"))
            elif i == 1:
                status = t["gate_status"][gates[name]["status"]] if name in gates else t["gate_status"]["unknown"]
                out.append(text(xs[i] + 14, middle, f"{clip(gate_name(name), 26)} {status} / {count}", "lab", halo=True))
            else:
                out.append(text(xs[i] + 14, middle, f"{t['stage'][name]} {count}", "lab"))
    rows = Counter((ev["origin"]["channel"], ev["pattern"], gate_of(ev), ev["detected"], ev["origin"]["strength"]) for ev in events)
    table = [(t["channel"][c], pattern_name(p, lang), gate_name(g), t["stage"][d], s, n) for (c, p, g, d, s), n in rows.items()]
    keys = legend([(line_key(), t["solid"]), (line_key("10 5"), t["dashed"]), ('<i class="sw sw-u"></i>', t["unattr"]),
                   ('<i class="sw sw-b"></i>', t["release_key"]), ('<i class="sw sw-a"></i>', t["other_key"])])
    foot = t["d1foot"].format(n=len(events), r=tot[2]["release"])
    return fig(1, t["d1"], t["d1q"], svg(width, top + tallest + 22, "".join(out), t["d1"]), foot, t["d1heads"], table, keys)


def d2(record, t, lang):
    events = defects(record)
    if not events:
        return fig(2, t["d2"], t["d2q"], omitted=t["no_data"])
    all_counts, traced = Counter(), Counter()
    per_module = Counter()
    for ev in events:
        all_counts[(ev["module"], ev["pattern"])] += 1
        per_module[ev["module"]] += 1
        if ev["origin"]["strength"] == "Traced":
            traced[(ev["module"], ev["pattern"])] += 1
    modules = [m for m, _ in per_module.most_common(16)]
    patterns = sorted({ev["pattern"] for ev in events})
    cell_w, cell_h = 62, 40
    left = 12 + min(max(len(m) for m in modules) * 7.2, 210)
    top = 120
    width = max(left + cell_w * len(patterns) + 60, 480)
    height = top + cell_h * len(modules) + 12
    out = []
    for i, pattern in enumerate(patterns):
        cx = left + cell_w * i + cell_w / 2
        out.append(f'<text transform="translate({cx + 4:.1f},{top - 10}) rotate(-40)" class="sub">{e(clip(pattern_name(pattern, lang), 20))}</text>')
    for j, module in enumerate(modules):
        y = top + cell_h * j
        out.append(text(left - 10, y + cell_h / 2 + 4, clip(module, 30), "lab", "end"))
        for i, pattern in enumerate(patterns):
            x = left + cell_w * i
            n, tr = all_counts[(module, pattern)], traced[(module, pattern)]
            if not n:
                out.append(f'<rect x="{x + 1:.1f}" y="{y + 1}" width="{cell_w - 2}" height="{cell_h - 2}" rx="3" class="h-empty"/>')
                continue
            shade = f"h{min(tr, 4)}"
            hot = " hot" if tr >= 3 else ""
            label = f"{module} × {pattern_name(pattern, lang)}: Traced {tr} / {n}"
            out.append(f'<rect x="{x + 1:.1f}" y="{y + 1}" width="{cell_w - 2}" height="{cell_h - 2}" rx="3" class="{shade}{hot}"{tip(label)}/>')
            cls = "cell-h4" if tr >= 4 else "cell-d" if tr == 3 else "cell"
            out.append(text(x + cell_w / 2, y + cell_h / 2 + 5, f"{tr}/{n}", cls, "middle"))
        out.append(text(left + cell_w * len(patterns) + 12, y + cell_h / 2 + 4, per_module[module], "sub"))
    out.append(text(left + cell_w * len(patterns) + 12, top - 10, t["d2total"], "sub"))
    steps = "".join(f'<i class="sw {c}"></i>' for c in ("h0", "h1", "h2", "h3", "h4"))
    keys = (f'<div class="legend"><span class="key">{e(t["d2key"])} {steps} 0 → 4+</span><span class="key">{e(t["d2cell"])}</span>'
            f'<span class="key"><i class="sw hot-key"></i>{e(t["d2hot"])}</span></div>')
    rows = [(m, pattern_name(p, lang), traced[(m, p)], n) for (m, p), n in all_counts.items()]
    return fig(2, t["d2"], t["d2q"], svg(int(width), height, "".join(out), t["d2"]), t["d2foot"], t["d2heads"], rows, keys)


def resolve(history, ref):
    for sha, info in history.get("commits", {}).items():
        if sha.startswith(ref):
            return sha, info
    return ref, {}


def chains(record, history):
    """Fix events joined through origin commits, longest chains first. Each chain is a set of commits."""
    parent = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    edges = []
    for ev in defects(record):
        fix = ev["commit"]
        find(fix)
        for origin in ev["origin"].get("commits", []):
            parent[find(origin)] = find(fix)
            edges.append((origin, fix, ev["origin"]["strength"], ev["module"]))
    groups = defaultdict(lambda: dict(nodes=set(), edges=[]))
    for ev in defects(record):
        groups[find(ev["commit"])]["nodes"].add(ev["commit"])
    for origin, fix, strength, module in edges:
        group = groups[find(fix)]
        group["nodes"] |= {origin, fix}
        group["edges"].append((origin, fix, strength, module))
    return sorted((g for g in groups.values() if g["edges"]), key=lambda g: (-len(g["nodes"]), sorted(g["nodes"])))


def d3(record, history, t):
    events = defects(record)
    shallow = history.get("quality", {}).get("shallow")
    if len(events) < MIN_DEFECTS_FOR_HISTORY_FIGURES or shallow:
        return fig(3, t["d3"], t["d3q"], omitted=t["d3thin"].format(n=len(events), m=MIN_DEFECTS_FOR_HISTORY_FIGURES))
    groups = chains(record, history)[:6]
    if not groups:
        return fig(3, t["d3"], t["d3q"], omitted=t["no_data"])
    fixes = {ev["commit"] for ev in events}
    width, row_h, top = 960, 86, 14
    left = 12 + min(max(len(m) for g in groups for *_, m in g["edges"]) * 7.4, 200)
    limit, cut = 10, False
    out = [arrow_def("ar3")]
    rows = []
    for index, group in enumerate(groups):
        y = top + index * row_h + 32
        module = group["edges"][0][3]
        out.append(f'<line x1="{left + 4:.1f}" y1="{y}" x2="{width - 10}" y2="{y}" class="grid"/>')
        out.append(text(left - 6, y + 4, clip(module, 28), "mono", "end"))
        dated = sorted(group["nodes"], key=lambda node: resolve(history, node)[1].get("date", ""))
        if len(dated) > limit:
            dated, cut = dated[-limit:], True
        days = [date.fromisoformat(resolve(history, node)[1]["date"]) for node in dated if resolve(history, node)[1].get("date")]
        if not days:
            continue
        start, span = min(days), max((max(days) - min(days)).days, 1)
        usable = width - left - 70
        gap = min(72, usable / max(len(dated) - 1, 1))
        pos, previous = {}, None
        for node in dated:
            info = resolve(history, node)[1]
            x = left + 28 + (date.fromisoformat(info["date"]) - start).days * (usable - gap * (len(dated) - 1)) / span if info.get("date") else left + 28
            x += gap * len(pos)
            if previous is not None:
                x = max(x, previous + gap)
            pos[node] = x
            previous = x
        for origin, fix, strength, edge_module in group["edges"]:
            rows.append((edge_module, origin[:10], fix[:10], strength))
            if origin not in pos or fix not in pos:
                continue
            x1, x2 = pos[origin], pos[fix]
            dash = ' stroke-dasharray="9 5"' if strength == "Blamed" else ""
            if any(min(x1, x2) < other < max(x1, x2) for other in pos.values()):
                out.append(f'<path d="M{x1 + 4:.1f} {y + 7} C{x1 + 30:.1f} {y + 36} {x2 - 30:.1f} {y + 36} {x2 - 4:.1f} {y + 9}" class="edge" marker-end="url(#ar3)"{dash}/>')
            else:
                out.append(f'<path d="M{x1 + 9:.1f} {y} L{x2 - 11:.1f} {y}" class="edge" marker-end="url(#ar3)"{dash}/>')
        for node, x in pos.items():
            info = resolve(history, node)[1]
            label = f"{node[:10]} {info.get('date', '')}: {info.get('subject', '')}"
            if node in fixes:
                mark = f'<circle cx="{x:.1f}" cy="{y}" r="8" class="dot-b"/>'
            else:
                mark = f'<rect x="{x - 8:.1f}" y="{y - 8}" width="16" height="16" rx="3" class="dot-a"/>'
            out.append(f'<g{tip(label)}><circle cx="{x:.1f}" cy="{y}" r="14" class="hit"/>{mark}</g>')
            out.append(text(x, y - 15, node[:7], "mono-s", "middle", True))
    height = top + len(groups) * row_h + 8
    attributed = [ev for ev in events if ev["origin"]["strength"] in ("Traced", "Blamed")]
    fix_origin = sum(1 for ev in attributed if ev["origin"]["channel"] == "fix")
    total = history.get("quality", {}).get("commits", 0)
    fix_commits = history.get("kinds", {}).get("fix", 0)
    foot = t["d3foot"].format(a=fix_origin, b=len(attributed), p=round(fix_origin * 100 / len(attributed)) if attributed else 0,
                              c=fix_commits, d=total, q=round(fix_commits * 100 / total) if total else 0, n=len(groups))
    if cut:
        foot += " " + t["d3cut"].format(n=limit)
    keys = legend([(line_key(), "Traced"), (line_key(BLAMED_DASH), "Blamed"),
                   ('<svg width="14" height="14" aria-hidden="true"><rect x="1" y="1" width="12" height="12" rx="3" class="dot-a"/></svg>', t["d3other"]),
                   ('<svg width="14" height="14" aria-hidden="true"><circle cx="7" cy="7" r="6" class="dot-b"/></svg>', t["d3fix"])])
    return fig(3, t["d3"], t["d3q"], svg(width, height, "".join(out), t["d3"]), foot, t["d3heads"], rows, keys)


def nice_step(maximum, ticks=7):
    for step in (1, 2, 5, 10, 20, 25, 50, 100, 200, 250, 500, 1000, 2000, 5000):
        if maximum / step <= ticks:
            return step
    return maximum


def d4(record, history, t):
    defect_counts = Counter(ev["module"] for ev in defects(record))
    modules = [m for m in history.get("modules", []) if m["commits"]]
    if not modules:
        return fig(4, t["d4"], t["d4q"], omitted=t["no_data"])
    modules = sorted(modules, key=lambda m: -m["commits"])[:30]
    points = [(m["module"], m["commits"], defect_counts[m["module"]] * 100 / m["commits"], m.get("test_files", 0)) for m in modules]
    width, height, left, right, top, bottom = 960, 430, 70, 170, 20, 56
    xstep, ystep = nice_step(max(p[1] for p in points)), nice_step(max(max(p[2] for p in points), 1), 6)
    xmax = (max(p[1] for p in points) // xstep + 1) * xstep
    ymax = (int(max(p[2] for p in points)) // ystep + 1) * ystep
    X = lambda v: left + v * (width - left - right) / xmax
    Y = lambda v: height - bottom - v * (height - top - bottom) / ymax

    def median(values):
        ordered, n = sorted(values), len(values)
        return ordered[n // 2] if n % 2 else (ordered[n // 2 - 1] + ordered[n // 2]) / 2

    mx, my = median([p[1] for p in points]), median([p[2] for p in points])
    out = []
    for v in range(0, xmax + 1, xstep):
        out += [f'<line x1="{X(v):.1f}" y1="{height - bottom}" x2="{X(v):.1f}" y2="{height - bottom + 5}" class="axis"/>', text(X(v), height - bottom + 20, v, "tick", "middle")]
    for v in range(0, ymax + 1, ystep):
        out += [f'<line x1="{left}" y1="{Y(v):.1f}" x2="{width - right}" y2="{Y(v):.1f}" class="grid"/>', text(left - 8, Y(v) + 4, v, "tick", "end")]
    out += [f'<line x1="{left}" y1="{height - bottom}" x2="{width - right}" y2="{height - bottom}" class="axis"/>',
            f'<line x1="{X(mx):.1f}" y1="{top}" x2="{X(mx):.1f}" y2="{height - bottom}" class="median"/>',
            f'<line x1="{left}" y1="{Y(my):.1f}" x2="{width - right}" y2="{Y(my):.1f}" class="median"/>',
            text((left + width - right) / 2, height - 10, t["d4x"], "sub", "middle"),
            f'<text transform="translate(18,{(top + height - bottom) / 2}) rotate(-90)" class="sub" text-anchor="middle">{e(t["d4y"])}</text>',
            text(width - right - 6, top + 14, t["d4hot"], "sub", "end", True),
            text(width - right + 8, Y(my) + 4, f"{t['d4median']} {my:.1f}", "sub"),
            text(X(mx) + 5, top + 14, f"{t['d4median']} {mx:g}", "sub", halo=True)]
    notable = {p[0] for p in sorted(points, key=lambda p: -(p[1] * (p[2] + 1)))[:4]} | {max(points, key=lambda p: p[2])[0]}
    for module, commits, density, tests in points:
        px, py = X(commits), Y(density)
        label = f"{module}: {commits} commits, {defect_counts[module]} defect fixes, {density:.1f}/100, {tests} test files"
        if tests:
            mark = f'<circle cx="{px:.1f}" cy="{py:.1f}" r="6.5" class="pt"/>'
        else:
            mark = f'<path d="M{px:.1f} {py - 8:.1f} L{px + 8:.1f} {py:.1f} L{px:.1f} {py + 8:.1f} L{px - 8:.1f} {py:.1f} z" class="pt-o"/>'
        out.append(f'<g{tip(label)}><circle cx="{px:.1f}" cy="{py:.1f}" r="14" class="hit"/>{mark}</g>')
        if module in notable:
            out.append(text(px + 12, py - 6, clip(module, 24), "lab", halo=True))
    rows = [(m, c, defect_counts[m], f"{d:.1f}", tf) for m, c, d, tf in points]
    keys = legend([('<svg width="14" height="14" aria-hidden="true"><circle cx="7" cy="7" r="5.5" class="pt"/></svg>', t["d4tested"]),
                   ('<svg width="16" height="16" aria-hidden="true"><path d="M8 1 L15 8 L8 15 L1 8 z" class="pt-o"/></svg>', t["d4untested"])])
    return fig(4, t["d4"], t["d4q"], svg(width, height, "".join(out), t["d4"]), t["d4foot"], t["d4heads"], rows, keys)


def d5(record, t):
    items = [f for f in record.get("findings", []) if f.get("path")][:10]
    if not items:
        return fig(5, t["d5"], t["d5q"], omitted=t["no_data"])
    width, box_h, row = 960, 76, 158
    out = [arrow_def("ar5")]
    rows = []
    for j, finding in enumerate(items):
        hops = finding["path"]
        names = [hops[0]["from"]] + [hop["to"] for hop in hops]
        gap = 66
        box_w = min(220, (width - 6 - gap * (len(names) - 1)) / len(names))
        y = 8 + row * j
        grade = " ・ ".join(str(v) for v in (finding.get("severity"), finding.get("confidence"), finding.get("status")) if v)
        out += [text(3, y + 16, finding["id"], "lab-b"), text(70, y + 16, f"{grade} ・ {clip(finding['title'], 70)}", "sub")]
        by = y + 32
        stopped = False
        for i, name in enumerate(names):
            x = 3 + (box_w + gap) * i
            cls = "box-off" if stopped else "box-end" if i == len(names) - 1 else "box"
            full = name + (t["d5unreached"] if stopped else "")
            at = hops[i - 1].get("at", "") if i else ""
            label = f"{finding['id']}: {full} {at}".strip()
            out.append(f'<rect x="{x:.1f}" y="{by}" width="{box_w:.1f}" height="{box_h}" rx="5" class="{cls}"{tip(label)}/>')
            chars = int((box_w - 18) / 6.9)
            if at:
                out.append(text(x + 10, by + 23, clip_left(at, chars), "mono-s"))
            out.append(text(x + 10, by + 46, clip(full, chars), "lab" if not stopped else "sub"))
            if i < len(hops):
                hop = hops[i]
                state = hop["state"]
                x1, x2, cy = x + box_w + 3, x + box_w + gap - 4, by + box_h / 2
                middle = (x1 + x2) / 2
                if stopped:
                    out.append(f'<line x1="{x1:.1f}" y1="{cy}" x2="{x2:.1f}" y2="{cy}" class="edge-off"/>')
                else:
                    dash = ' stroke-dasharray="9 5"' if state == "unknown" else ""
                    marker = "" if state == "blocked" else ' marker-end="url(#ar5)"'
                    out.append(f'<line x1="{x1:.1f}" y1="{cy}" x2="{x2:.1f}" y2="{cy}" class="edge"{dash}{marker}/>')
                    if state == "blocked":
                        out.append(f'<line x1="{middle:.1f}" y1="{cy - 10}" x2="{middle:.1f}" y2="{cy + 10}" class="edge-bar"/>')
                    out.append(text(middle, cy - 14, t["d5state"][state], "state", "middle"))
                    out.append(text(middle, cy + 22, state, "tiny", "middle"))
                rows.append((finding["id"], hop["from"], hop["to"], state, hop.get("at", ""), hop.get("why", "")))
                if state != "allowed":
                    stopped = True
        if finding.get("events"):
            out.append(text(3, by + box_h + 20, t["d5events"] + ", ".join(finding["events"][:8]), "sub"))
    return fig(5, t["d5"], t["d5q"], svg(width, 8 + row * len(items), "".join(out), t["d5"]), t["d5foot"], t["d5heads"], rows)


def d6(record, t, lang):
    issues = record.get("issues", [])
    if not issues:
        return fig(6, t["d6"], t["d6q"], omitted=t["no_data"])
    counts = Counter(ev["pattern"] for ev in defects(record))
    patterns = []
    for issue in issues:
        for pattern in issue["feeds"]:
            if pattern not in patterns:
                patterns.append(pattern)
    items = [f for f in record.get("findings", []) if f.get("pattern") in patterns and f.get("status") not in ("Fixed", "Verified")]
    items.sort(key=lambda f: ("High", "Medium", "Low", "Info").index(f.get("severity", "Info")))
    items = items[:12]
    claimed = {f["pattern"] for f in items}
    unknown = [p for p in patterns if p not in claimed]
    results = [(f["id"], f"{f['id']} ・ {f.get('severity', '')}", f["title"], [f["pattern"]]) for f in items]
    if unknown:
        results.append(("unknown", t["d6none"], "", unknown))
    top, row = 34, 46
    height = top + row * max(len(patterns), len(issues), len(results)) + 12
    width, x0, x1, x2, w0, w1 = 960, 8, 340, 650, 240, 230
    place = lambda n, total: top + (height - top - 12) * (n + 0.5) / total
    ys_i = {i["id"]: place(n, len(issues)) for n, i in enumerate(issues)}
    ys_p = {p: place(n, len(patterns)) for n, p in enumerate(patterns)}
    ys_r = {r[0]: place(n, len(results)) for n, r in enumerate(results)}
    out = [text(x, 20, head, "colhead") for x, head in zip((x0, x1, x2), t["d6cols"])]
    lead = items[0]["id"] if items else None
    hot = {items[0]["pattern"]} if items else set()
    for issue in issues:
        for pattern in issue["feeds"]:
            cls = "link-hi" if pattern in hot else "link"
            xa, ya, yb = x0 + w0, ys_i[issue["id"]], ys_p[pattern]
            out.append(f'<path d="M{xa} {ya:.1f} C{xa + 50} {ya:.1f} {x1 - 50} {yb:.1f} {x1} {yb:.1f}" class="{cls}"/>')
    for rid, _, _, sources in results:
        for pattern in sources:
            cls = "link-hi" if rid == lead else "link"
            xa, ya, yb = x1 + w1, ys_p[pattern], ys_r[rid]
            out.append(f'<path d="M{xa} {ya:.1f} C{xa + 40} {ya:.1f} {x2 - 40} {yb:.1f} {x2} {yb:.1f}" class="{cls}"/>')
    for issue in issues:
        y = ys_i[issue["id"]]
        label = f"{issue['id']} {issue['kind']}: {issue['at']}"
        out.append(f'<rect x="{x0}" y="{y - 20:.1f}" width="{w0}" height="40" rx="5" class="box"{tip(label)}/>')
        out += [text(x0 + 10, y - 3, clip(f"{issue['id']} {issue['kind']}", 32), "lab"), text(x0 + 10, y + 13, clip(issue["at"], 36), "tiny-l")]
    for pattern in patterns:
        y = ys_p[pattern]
        cls = "box-hi" if pattern in hot else "box"
        name = f"{pattern} {pattern_name(pattern, lang)}"
        label = f"{name}: {counts[pattern]}"
        out.append(f'<rect x="{x1}" y="{y - 16:.1f}" width="{w1}" height="32" rx="5" class="{cls}"{tip(label)}/>')
        out += [text(x1 + 10, y + 5, clip(name, 28), "lab"), text(x1 + w1 - 10, y + 5, counts[pattern], "sub", "end")]
    for rid, head, title, _ in results:
        y = ys_r[rid]
        cls = "box-hi" if rid == lead else "box-off" if rid == "unknown" else "box"
        label = f"{head}: {title}"
        out.append(f'<rect x="{x2}" y="{y - 20:.1f}" width="{width - x2 - 8}" height="40" rx="5" class="{cls}"{tip(label)}/>')
        if title:
            out += [text(x2 + 10, y - 3, head, "lab"), text(x2 + 10, y + 13, clip(title, 44), "tiny-l")]
        else:
            out.append(text(x2 + 10, y + 5, head, "sub"))
    rows = [(f"{i['id']} {i['kind']}", i["at"], ", ".join(i["feeds"])) for i in issues]
    return fig(6, t["d6"], t["d6q"], svg(width, height, "".join(out), t["d6"]), t["d6foot"], t["d6heads"], rows)


def relation_edges(findings):
    """Direct each relation from cause to effect so the drawing reads left to right."""
    edges = []
    for finding in findings:
        for relation in finding.get("relations", []):
            backward = relation["type"] in ("regression_of", "caused_by")
            source, target = (relation["to"], finding["id"]) if backward else (finding["id"], relation["to"])
            edges.append((source, target, relation["type"], relation["strength"], relation["evidence"]))
    return edges


def shared_surfaces(findings, kinds, asserted):
    pairs = []
    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            if frozenset((a["id"], b["id"])) in asserted:
                continue
            ours = {s["id"] for s in a.get("surfaces", [])}
            common = [s["id"] for s in b.get("surfaces", []) if s["id"] in ours and kinds.get(s["id"]) in ("db", "job")]
            if common:
                pairs.append((a["id"], b["id"], common))
    return pairs


def d7(record, surfaces, t):
    findings = record.get("findings", [])
    edges = relation_edges(findings)
    kinds = {s["id"]: s["kind"] for s in surfaces.get("surfaces", [])}
    asserted = {frozenset((a, b)) for a, b, _, _, _ in edges}
    shared = shared_surfaces(findings, kinds, asserted)
    linked = {x for a, b, *_ in edges for x in (a, b)} | {x for a, b, _ in shared for x in (a, b)}
    if not linked:
        return fig(7, t["d7"], t["d7q"], omitted=t["no_data"])
    depth = {node: 0 for node in linked}
    for _ in linked:
        for source, target, *_ in edges:
            depth[target] = max(depth[target], depth[source] + 1)
    by_id = {f["id"]: f for f in findings}
    groups = {node: node for node in linked}

    def root(node):
        while groups[node] != node:
            groups[node] = groups[groups[node]]
            node = groups[node]
        return node

    for source, target, *_ in edges:
        groups[root(source)] = root(target)
    for a, b, _ in shared:
        groups[root(a)] = root(b)
    components = defaultdict(list)
    for node in sorted(linked):
        components[root(node)].append(node)
    count = min(max(depth.values()), 3) + 1
    width, box_w, box_h = 960, min(240, (960 - 20 - 60 * (count - 1)) / max(count, 1)), 74
    gap_x = (width - 20 - box_w * count) / max(count - 1, 1) if count > 1 else 0
    pos, row = {}, 0
    for nodes in sorted(components.values(), key=lambda v: (-len(v), v)):
        used = defaultdict(int)
        for node in nodes:
            column = min(depth[node], 3)
            pos[node] = (10 + column * (box_w + gap_x), 12 + (row + used[column]) * 108)
            used[column] += 1
        row += max(used.values())
    height = 12 + row * 108 + 30
    out = [arrow_def("ar7")]
    for a, b, common in shared:
        (ax, ay), (bx, by) = pos[a], pos[b]
        label = f"{a} / {b}: {', '.join(common)}"
        x1, x2 = ax + box_w / 2, bx + box_w / 2
        if ay == by:
            out.append(f'<path d="M{x1:.1f} {ay + box_h} C{x1:.1f} {ay + box_h + 40} {x2:.1f} {by + box_h + 40} {x2:.1f} {by + box_h}" class="shared"{tip(label)}/>')
        else:
            out.append(f'<path d="M{x1:.1f} {ay + box_h / 2} L{x2:.1f} {by + box_h / 2}" class="shared"{tip(label)}/>')
    for source, target, kind, strength, evidence in edges:
        (ax, ay), (bx, by) = pos[source], pos[target]
        dash = ' stroke-dasharray="9 5"' if strength == "Blamed" else ""
        x1, y1, x2, y2 = ax + box_w, ay + box_h / 2, bx - 3, by + box_h / 2
        if ax >= bx:
            x1, y1, x2, y2 = ax + box_w / 2, ay + box_h, bx + box_w / 2, by - 3
        label = f"{source} {kind} {target}: {evidence}"
        out.append(f'<path d="M{x1:.1f} {y1:.1f} L{x2:.1f} {y2:.1f}" class="edge" marker-end="url(#ar7)"{dash}{tip(label)}/>')
        out.append(text((x1 + x2) / 2, (y1 + y2) / 2 - 8, t["relation"][kind], "tiny-l", "middle", True))
    chars = int((box_w - 20) / 6.9)
    for node, (x, y) in pos.items():
        finding = by_id[node]
        cls = "box-hi" if finding.get("severity") == "High" and finding.get("status") not in ("Fixed", "Verified") else "box-off" if finding.get("status") in ("Fixed", "Verified") else "box"
        label = f"{node}: {finding['title']}"
        out.append(f'<rect x="{x:.1f}" y="{y}" width="{box_w:.1f}" height="{box_h}" rx="5" class="{cls}"{tip(label)}/>')
        status = " ・ ".join(str(v) for v in (finding.get("status"), finding.get("severity")) if v)
        out += [text(x + 10, y + 22, node, "lab-b"), text(x + box_w - 10, y + 22, status, "sub", "end"), text(x + 10, y + 46, clip(finding["title"], chars), "sub"),
                text(x + 10, y + 64, clip("、".join((finding.get("hazard") or {}).get("classes", [])), chars), "tiny-l")]
    rows = [(s, k, d, st, ev) for s, d, k, st, ev in edges] + [(a, "shares_surface", b, t["d7auto"], ", ".join(c)) for a, b, c in shared]
    keys = legend([(line_key(), "Traced"), (line_key(BLAMED_DASH), "Blamed"),
                   ('<svg width="34" height="10" aria-hidden="true"><line x1="1" y1="5" x2="33" y2="5" class="shared"/></svg>', t["d7shared"])])
    return fig(7, t["d7"], t["d7q"], svg(width, height, "".join(out), t["d7"]), t["d7foot"].format(n=len(findings) - len(linked)), t["d7heads"], rows, keys)


def d8(record, surfaces, t):
    findings = record.get("findings", [])
    catalog = {s["id"]: s for s in surfaces.get("surfaces", [])}
    cited = {s["id"] for f in findings for s in f.get("surfaces", [])}
    links = [l for l in surfaces.get("links", []) if l["from"] in cited or l["to"] in cited]
    shown = set(cited) | {x for l in links for x in (l["from"], l["to"])}
    shown = {s for s in shown if s in catalog}
    if not shown:
        return fig(8, t["d8"], t["d8q"], omitted=t["no_data"])
    column_of = dict(screen=0, api=1, job=1, db=2, ext=2, cfg=2)
    columns = [[], [], []]
    for sid in sorted(shown, key=lambda s: (KIND_ORDER.index(catalog[s]["kind"]), s)):
        columns[column_of[catalog[sid]["kind"]]].append(sid)
    width, box_w, box_h, row, top = 960, 250, 56, 72, 34
    xs = [8, 355, 702]
    deepest = max(len(c) for c in columns)
    height = top + row * deepest + 8
    pos = {}
    for i, column in enumerate(columns):
        spare = row * deepest - row * len(column)
        for j, sid in enumerate(column):
            pos[sid] = (xs[i], top + spare / 2 + j * row + (row - box_h) / 2)
    out = [text(x, 20, head, "colhead") for x, head in zip(xs, t["d8cols"])]
    for link in links:
        if link["from"] not in pos or link["to"] not in pos:
            continue
        (ax, ay), (bx, by) = pos[link["from"]], pos[link["to"]]
        dash = ' stroke-dasharray="9 5"' if link.get("basis") != "traced" else ""
        if ax == bx:
            path = f"M{ax + box_w / 2} {ay + box_h:.1f} L{bx + box_w / 2} {by:.1f}" if by > ay else f"M{ax + box_w / 2} {ay:.1f} L{bx + box_w / 2} {by + box_h:.1f}"
        else:
            y1, y2 = ay + box_h / 2, by + box_h / 2
            path = f"M{ax + box_w} {y1:.1f} C{ax + box_w + 50} {y1:.1f} {bx - 50} {y2:.1f} {bx} {y2:.1f}"
        out.append(f'<path d="{path}" class="link maplink"{dash} data-a="{e(link["from"])}" data-b="{e(link["to"])}"/>')
    imports = record.get("imports", [])
    defect_ids, import_ids = {}, {}
    for sid, (x, y) in pos.items():
        item = catalog[sid]
        related = [f for f in findings if any(s["id"] == sid for s in f.get("surfaces", []))]
        open_count = sum(1 for f in related if f.get("status") not in ("Fixed", "Verified"))
        place = location_path(item.get("location", ""))
        overlays = [i["key"] for i in imports if place and any(location_path(l) == place for l in i.get("location", []))]
        defect_ids[sid], import_ids[sid] = [f["id"] for f in related], overlays
        note = t["d8open"].format(n=open_count) + (f" ・ {t['d8imports'].format(n=len(overlays))}" if overlays else "")
        label = f"{sid} {item['name']}: {note}"
        out.append(f'<g class="mapnode" data-s="{e(sid)}"{tip(label)}><rect x="{x}" y="{y:.1f}" width="{box_w}" height="{box_h}" rx="5" class="box"/>'
                   + text(x + 10, y + 22, clip(item["name"], 22), "lab") + text(x + 10, y + 42, clip_left(item.get("location", ""), 40), "tiny-l")
                   + text(x + box_w - 10, y + 22, note, "sub", "end") + "</g>")
    options = ""
    for finding in findings:
        if finding.get("surfaces"):
            cited_ids = " ".join(s["id"] for s in finding["surfaces"])
            options += f'<option value="{e(finding["id"])}" data-surf="{e(cited_ids)}">{e(finding["id"])} {e(clip(finding["title"], 44))}</option>'
    control = f'<div class="pick no-print"><label>{e(t["d8pick"])} <select class="mapsel"><option value="">{e(t["d8all"])}</option>{options}</select></label></div>'
    rows = [(sid, t["kind"][catalog[sid]["kind"]], catalog[sid]["name"], catalog[sid].get("location", ""), catalog[sid].get("basis", ""),
             ", ".join(defect_ids[sid]), ", ".join(import_ids[sid])) for sid in sorted(pos)]
    return fig(8, t["d8"], t["d8q"], svg(width, height, "".join(out), t["d8"]), t["d8foot"], t["d8heads"], rows, control=control)


def d9(record, t):
    items = [f for f in record.get("findings", []) if isinstance(f.get("risk"), dict) and f.get("status") not in ("Fixed", "Verified")
             and (f.get("validation") or {}).get("verdict") not in ("FalsePositive", "NotApplicable")]
    if not items:
        return fig(9, t["d9"], t["d9q"], omitted=t["no_data"])
    cell_w, cell_h, left, top = 250, 112, 100, 14
    cells = defaultdict(list)
    for finding in items:
        cells[(finding["risk"]["likelihood"], finding["risk"]["impact"])].append(finding)
    deepest = max(max((len(v) for v in cells.values()), default=1), 3)
    cell_h = max(cell_h, 44 + deepest * 28)
    out = []
    shade = dict(Low="h0", Medium="h1", High="h2")
    for r, impact in enumerate(reversed(LEVELS)):
        y = top + cell_h * r
        out.append(text(left - 12, y + cell_h / 2 + 4, f"{t['d9y']} {t['level'][impact]}", "sub", "end"))
        for c, likelihood in enumerate(LEVELS):
            x = left + cell_w * c
            level = RISK_TABLE[(likelihood, impact)]
            out.append(f'<rect x="{x + 1}" y="{y + 1}" width="{cell_w - 2}" height="{cell_h - 2}" rx="4" class="{shade[level]}"/>')
            out.append(text(x + 10, y + 20, f"{t['d9risk']} {t['level'][level]}", "tiny-l"))
            for n, finding in enumerate(cells[(likelihood, impact)]):
                yy = y + 44 + n * 28
                hazard = finding.get("hazard") or {}
                marks = " ".join(label for key, label in (("irreversible", t["d9irr"]), ("silent", t["d9silent"])) if hazard.get(key) == "yes")
                first = (hazard.get("classes") or [""])[0]
                label = f"{finding['id']}: {finding['title']}"
                out.append(f'<g{tip(label)}>' + text(x + 10, yy, finding["id"], "lab-b")
                           + text(x + 74, yy, clip(f"{marks} {first}".strip(), 24), "sub") + "</g>")
    for c, likelihood in enumerate(LEVELS):
        out.append(text(left + cell_w * c + cell_w / 2, top + cell_h * 3 + 22, f"{t['d9x']} {t['level'][likelihood]}", "sub", "middle"))
    rows = [(f["id"], f["risk"]["likelihood"], f["risk"]["impact"], f["risk"]["level"], "、".join((f.get("hazard") or {}).get("classes", [])),
             (f.get("hazard") or {}).get("irreversible", ""), (f.get("hazard") or {}).get("silent", ""), f["risk"]["basis"]) for f in items]
    return fig(9, t["d9"], t["d9q"], svg(left + cell_w * 3 + 8, top + cell_h * 3 + 40, "".join(out), t["d9"]), t["d9foot"], t["d9heads"], rows)


def d1_guarded(record, history, t, lang):
    events = defects(record)
    if events and (len(events) < MIN_DEFECTS_FOR_HISTORY_FIGURES or history.get("quality", {}).get("shallow")):
        return fig(1, t["d1"], t["d1q"], omitted=t["d3thin"].format(n=len(events), m=MIN_DEFECTS_FOR_HISTORY_FIGURES))
    return d1(record, t, lang)


def figures(record, surfaces, history, lang):
    t = TEXT[lang]
    return [d7(record, surfaces, t), d8(record, surfaces, t), d9(record, t), d1_guarded(record, history, t, lang), d2(record, t, lang),
            d3(record, history, t), d4(record, history, t), d5(record, t), d6(record, t, lang)]


def table_html(figure):
    head = "".join(f"<th>{e(h)}</th>" for h in figure["heads"])
    body = "".join("<tr>" + "".join(f"<td>{e(c)}</td>" for c in row) + "</tr>" for row in figure["rows"])
    return f'<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>'


def section_html(figs, lang, printable):
    t = TEXT[lang]
    out = [f'<section id="figures" class="bsf"><h2>{e(t["section"])}</h2><p class="q">{e(t["section_note"])}</p>']
    for figure in figs:
        out.append(f'<div class="card" id="fig-d{figure["number"]}"><p class="fig">D{figure["number"]}</p><h3>{e(figure["title"])}</h3><p class="q">{e(figure["question"])}</p>')
        if figure["omitted"]:
            out.append(f'<p class="note"><b>{e(t["omitted"])}:</b> {e(figure["omitted"])}</p></div>')
            continue
        if not printable:
            out.append(figure["control"])
        out.append(figure["legend"])
        out.append(f'<div class="plot">{figure["svg"]}</div><p class="note">{e(figure["foot"])}</p>')
        if figure["rows"]:
            out.append(f'<div class="tw">{table_html(figure)}</div>' if printable else
                       f'<details class="twd"><summary>{e(t["table"])}</summary><div class="tw">{table_html(figure)}</div></details>')
        out.append("</div>")
    out.append("</section>")
    return "".join(out)


LIGHT = ("--bs-a:#2a78d6;--bs-b:#eb6834;--bs-h0:#e8f1fc;--bs-h1:#cde2fb;--bs-h2:#86b6ef;--bs-h3:#2a78d6;--bs-h4:#184f95;--bs-on4:#fff;"
         "--bs-off:#f0efec;--bs-tint:#eef4fc;--bs-ink:#1b1b1b;--bs-ink2:#52514e;--bs-muted:#6f6e69;--bs-grid:#e1e0d9;--bs-axis:#c3c2b7;--bs-surface:#fff")
DARK = ("--bs-a:#3987e5;--bs-b:#d95926;--bs-h0:#17263a;--bs-h1:#184f95;--bs-h2:#256abf;--bs-h3:#3987e5;--bs-h4:#86b6ef;--bs-on4:#0b0b0b;"
        "--bs-off:#2a2a2e;--bs-tint:#182436;--bs-ink:#ece9e2;--bs-ink2:#c3c2b7;--bs-muted:#a3a29a;--bs-grid:#2c2c2a;--bs-axis:#4a4a46;--bs-surface:#1f1f23")
RULES = """
.bsf{margin:24px 0;color:var(--bs-ink)}.bsf h2{margin:0 0 4px}.bsf h3{margin:0;font-size:1.05em;line-height:1.4}
.bsf .card{border:1px solid var(--bs-grid);border-radius:8px;padding:18px 20px;margin:14px 0;background:var(--bs-surface);break-inside:avoid}
.bsf .fig{margin:0;font-size:12px;color:var(--bs-muted);font-weight:600}.bsf .q{margin:2px 0 10px;color:var(--bs-ink2);font-size:.92em}
.bsf .plot svg{display:block;width:100%;height:auto}.bsf .note{margin:10px 0 6px;font-size:.88em;color:var(--bs-ink2)}
.bsf .legend{display:flex;flex-wrap:wrap;gap:6px 18px;margin:0 0 10px;font-size:.84em;color:var(--bs-ink2)}.bsf .key{display:inline-flex;align-items:center;gap:6px}
.bsf .sw{display:inline-block;width:14px;height:14px;border-radius:3px}.bsf .sw-a{background:var(--bs-a);opacity:.5}.bsf .sw-b{background:var(--bs-b);opacity:.6}.bsf .sw-u{background:var(--bs-a);opacity:.2}
.bsf i.h0{background:var(--bs-h0)}.bsf i.h1{background:var(--bs-h1)}.bsf i.h2{background:var(--bs-h2)}.bsf i.h3{background:var(--bs-h3)}.bsf i.h4{background:var(--bs-h4)}.bsf .hot-key{outline:2px solid var(--bs-ink);outline-offset:-2px}
.bsf details.twd{font-size:.88em}.bsf summary{cursor:pointer;color:var(--bs-ink2)}.bsf .tw{overflow:auto;margin-top:8px}.bsf table{border-collapse:collapse;width:100%;font-size:.86em;font-variant-numeric:tabular-nums}.bsf th,.bsf td{text-align:left;padding:4px 8px;border-bottom:1px solid var(--bs-grid);overflow-wrap:anywhere}.bsf th{color:var(--bs-ink2);font-weight:600}
.bsf .pick{margin:0 0 10px;font-size:.88em;color:var(--bs-ink2)}.bsf select{font:inherit;max-width:420px}
.bsf svg text{fill:var(--bs-ink);font:13px system-ui,-apple-system,"Hiragino Sans","Noto Sans CJK JP",sans-serif}.bsf svg .halo{paint-order:stroke;stroke:var(--bs-surface);stroke-width:4px;stroke-linejoin:round}
.bsf svg .lab{font-weight:500}.bsf svg .lab-b{font-weight:700;font-size:14px}.bsf svg .sub{fill:var(--bs-ink2);font-size:12px}.bsf svg .tiny{fill:var(--bs-muted);font-size:11px}.bsf svg .tiny-l{fill:var(--bs-ink2);font-size:11.5px}.bsf svg .tick{fill:var(--bs-muted);font-size:12px;font-variant-numeric:tabular-nums}
.bsf svg .colhead{fill:var(--bs-ink2);font-size:12.5px;font-weight:600}.bsf svg .mono{font:12px ui-monospace,Menlo,monospace}.bsf svg .mono-s{font:11.5px ui-monospace,Menlo,monospace;fill:var(--bs-ink2)}.bsf svg .state{font-size:15px;font-weight:700}.bsf svg .cell{font-size:12.5px}.bsf svg .cell-d{font-size:12.5px;font-weight:700;fill:#fff}.bsf svg .cell-h4{font-size:12.5px;font-weight:700;fill:var(--bs-on4)}
.bsf .rib{fill:none;opacity:.42}.bsf .rib-a{stroke:var(--bs-a)}.bsf .rib-b{stroke:var(--bs-b);opacity:.62}.bsf .rib-u{opacity:.2}.bsf .rib:hover,.bsf .rib:focus{opacity:.8;outline:none}.bsf .node{fill:var(--bs-ink2)}.bsf .node-b{fill:var(--bs-b)}
.bsf rect.h-empty{fill:var(--bs-off);opacity:.5}.bsf rect.h0{fill:var(--bs-h0)}.bsf rect.h1{fill:var(--bs-h1)}.bsf rect.h2{fill:var(--bs-h2)}.bsf rect.h3{fill:var(--bs-h3)}.bsf rect.h4{fill:var(--bs-h4)}.bsf rect.hot{stroke:var(--bs-ink);stroke-width:2}
.bsf .k-line{stroke:var(--bs-ink2);stroke-width:2.5}.bsf .grid{stroke:var(--bs-grid);stroke-width:1}.bsf .axis{stroke:var(--bs-axis);stroke-width:1}.bsf .median{stroke:var(--bs-axis);stroke-width:1.5}
.bsf .edge{fill:none;stroke:var(--bs-ink2);stroke-width:2}.bsf .edge-off{stroke:var(--bs-grid);stroke-width:2}.bsf .edge-bar{stroke:var(--bs-ink);stroke-width:4;stroke-linecap:round}.bsf .arrow{fill:var(--bs-ink2)}
.bsf .dot-a{fill:var(--bs-ink2)}.bsf .dot-b{fill:var(--bs-a);stroke:var(--bs-surface);stroke-width:2}.bsf .hit{fill:transparent}.bsf .pt{fill:var(--bs-a);stroke:var(--bs-surface);stroke-width:2}.bsf .pt-o{fill:var(--bs-b);stroke:var(--bs-surface);stroke-width:2}
.bsf .box{fill:var(--bs-surface);stroke:var(--bs-axis);stroke-width:1}.bsf .box-hi{fill:var(--bs-tint);stroke:var(--bs-a);stroke-width:2}.bsf .box-off{fill:var(--bs-off);stroke:var(--bs-grid);stroke-width:1}.bsf .box-end{fill:var(--bs-tint);stroke:var(--bs-a);stroke-width:1.5}
.bsf .link{fill:none;stroke:var(--bs-axis);stroke-width:1.5}.bsf .link-hi{fill:none;stroke:var(--bs-a);stroke-width:2.5}.bsf .shared{fill:none;stroke:var(--bs-axis);stroke-width:1}
.bsf .dim{opacity:.18}.bsf .on rect{stroke:var(--bs-a);stroke-width:2.5;fill:var(--bs-tint)}.bsf path.on{stroke:var(--bs-a);stroke-width:3}.bsf [data-tip]:focus{outline:none}.bsf rect[data-tip]:hover,.bsf rect[data-tip]:focus{stroke:var(--bs-ink);stroke-width:2}
#bs-tip{position:fixed;z-index:50;max-width:340px;pointer-events:none;background:var(--panel,#fff);color:var(--text,#1b1b1b);border:1px solid var(--line,#ccc);border-radius:5px;padding:6px 10px;font-size:13px;box-shadow:0 2px 10px rgba(0,0,0,.15);display:none}
"""
SCRIPT = """
(function(){var t=document.getElementById('bs-tip');
function show(el,x,y){t.textContent=el.getAttribute('data-tip');t.style.display='block';t.style.left=Math.min(x+14,innerWidth-t.offsetWidth-8)+'px';t.style.top=Math.max(8,y-t.offsetHeight-10)+'px'}
document.querySelectorAll('.bsf [data-tip]').forEach(function(el){el.addEventListener('pointermove',function(ev){show(el,ev.clientX,ev.clientY)});el.addEventListener('pointerleave',function(){t.style.display='none'});
el.addEventListener('focus',function(){var b=el.getBoundingClientRect();show(el,b.left+b.width/2,b.top)});el.addEventListener('blur',function(){t.style.display='none'})});
document.querySelectorAll('.bsf .mapsel').forEach(function(sel){var fig=sel.closest('.card');sel.addEventListener('input',function(){var o=sel.options[sel.selectedIndex],on=new Set(o&&o.value?o.getAttribute('data-surf').split(' '):[]);
fig.querySelectorAll('.mapnode').forEach(function(g){g.classList.toggle('on',on.has(g.getAttribute('data-s')));g.classList.toggle('dim',on.size>0&&!on.has(g.getAttribute('data-s')))});
fig.querySelectorAll('.maplink').forEach(function(l){var hit=on.has(l.getAttribute('data-a'))&&on.has(l.getAttribute('data-b'));l.classList.toggle('on',hit);l.classList.toggle('dim',on.size>0&&!hit)})})})})();
"""


def dashboard_css():
    return (f":root{{{LIGHT}}}@media(prefers-color-scheme:dark){{:root:not([data-theme=\"light\"]){{{DARK}}}}}"
            f":root[data-theme=\"dark\"]{{{DARK}}}@media print{{:root,:root[data-theme]{{{LIGHT}}}.bsf .no-print{{display:none}}}}{RULES}")


def document_css():
    return f":root{{{LIGHT}}}{RULES}"
