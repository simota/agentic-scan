"""The shared visual system (docs/design.md) as strings ready to inline into a page."""

from pathlib import Path

ASSETS = Path(__file__).resolve().parent / "report_assets"


def _asset(name):
    return (ASSETS / name).read_text(encoding="utf-8")


def dashboard_css():
    """Stylesheet for the interactive dashboard (light and dark themes)."""
    return _asset("dashboard.css")



SEVERITY_TONES = {"High": "high", "Medium": "medium", "Low": "low", "Info": "info"}
VERDICT_TONES = {"Valid": "strong", "Likely": "mid", "Unverified": "hatch", "Unlikely": "weak"}


def console_css():
    return _asset("console.css")


def console_js():
    return _asset("console.js")


def document_css(title):
    footer = title.replace("\\", "\\\\").replace('"', '\\"')
    return _asset("document.css").replace("__RUNNING_FOOTER__", footer)


def console_header(tools):
    return ("<header class='cx-band'><div class='cx-band-in'><div data-cx='ident'></div>"
            "<div class='cx-side'><dl class='cx-readout' data-cx='readout'></dl>"
            f"<div class='cx-tools'>{tools}</div></div></div></header>")


def console_slots(labels, esc):
    return ("<div class='cx' id='console'><div class='cx-grid'>"
            "<section class='cx-p cx-sev' data-cx='severity' aria-labelledby='cx-sev-h'></section>"
            "<section class='cx-p cx-ver' data-cx='verdicts' aria-labelledby='cx-ver-h'></section>"
            "<section class='cx-p cx-cov' data-cx='perspectives' aria-labelledby='cx-cov-h'></section>"
            "<section class='cx-triage' id='triage' tabindex='-1' aria-labelledby='cx-triage-h'>"
            f"<h2 class='cx-ph' id='cx-triage-h'><b>{esc(labels['board_h'])}</b>"
            f"<span>{esc(labels['board_note'])}</span></h2>"
            "<div class='cx-triage-in'><div class='cx-board' data-cx='board'></div>"
            "<aside class='cx-insp' data-cx='inspector' aria-live='polite'></aside></div></section></div></div>")


def perspective_lamps(doc, records, result):
    by_category = {}
    for finding, card in zip(doc.get("findings", []), records):
        by_category.setdefault(finding["category"], []).append(card)
    lamps = []
    for p in doc.get("perspectives", []):
        matched = by_category.get(p["name"], ())
        opened = [card for card in matched if card["open"]]
        if opened:
            severity = min((card["severity"] for card in opened), key=tuple(SEVERITY_TONES).index)
            tone = SEVERITY_TONES[severity]
        elif any(card["lane"] == "closed" for card in matched):
            tone = "ink"
        else:
            tone = "accent" if matched else "muted"
        lamps.append({"name": p["name"], "result": result(p["status"]), "note": p.get("note", ""),
                      "tone": tone, "on": bool(opened)})
    return lamps


def console_band_html(cm, esc, kind):
    """Static band header (assessment): wordmark, skill, title, context and the open / closed / excluded readout."""
    meta, counts, L = cm["meta"], cm["counts"], cm["labels"]
    context = "".join(f"<span>{esc(part)}</span>" for part in meta["context"] if part)
    readout = "".join(f"<div><dt>{esc(L['readout_' + key])}</dt><dd>{counts[key]}</dd></div>"
                      for key in ("open", "closed", "excluded"))
    return (f"<header class='cx-band'><div class='cx-band-in'><div>"
            f"<p class='cx-wm'><span><span class='cx-perm' aria-hidden='true'>r--</span> agentic-scan</span>"
            f"<span class='cx-skill'>{esc(meta['skill'])}</span></p>"
            f"<p class='cx-kind'>{esc(kind)}</p>"
            f"<h1 id='{esc(meta['title_id'])}'>{esc(meta['title'])}</h1>" + (f"<p class='cx-ctx'>{context}</p>" if context else "") +
            f"</div><dl class='cx-readout' aria-label='{esc(L['readout'])}' data-cx-readout>{readout}</dl></div></header>")


def console_tiles_html(cm, esc):
    """Static severity tiles: one cell per included record, filled while it is open."""
    L, included = cm["labels"], [f for f in cm["findings"] if not f["excluded"]]
    tiles = []
    for sev in cm["severities"]:
        items = [f for f in included if f["severity"] == sev]
        opened = [f for f in items if f["open"]]
        cells = "".join("<i class='cx-on'></i>" for _ in opened[:120]) + "<i></i>" * max(0, min(len(items), 120) - len(opened))
        if len(items) > 120:
            cells += f"<span class='cx-more'>+{len(items) - 120}</span>"
        ids = " ".join(f["id"] for f in opened[:6]) + (" …" if len(opened) > 6 else "")
        sub = L["tile_sub"].format(open=len(opened), closed=len(items) - len(opened)) + (f" · {ids}" if ids else "")
        tiles.append(f"<div class='cx-tile cx-c-{SEVERITY_TONES[sev]}' data-severity='{esc(sev)}'>"
                     f"<span class='cx-l'>{esc(sev)}</span><span class='cx-n'>{len(items)}</span>"
                     f"<span class='cx-cells' aria-hidden='true'>{cells}</span><span class='cx-s'>{esc(sub)}</span></div>")
    note = L["severity_note"].format(n=len(included), x=len(cm["findings"]) - len(included))
    return (f"<section class='cx-sev' aria-labelledby='cx-sev-h'><h2 class='cx-ph' id='cx-sev-h'><b>{esc(L['severity_h'])}</b>"
            f"<span>{esc(note)}</span></h2><div class='cx-tiles'>{''.join(tiles)}</div>"
            f"<p class='cx-legend'>{esc(L['legend_cell'])}<i class='cx-on'></i>{esc(L['legend_open'])} "
            f"<i></i>{esc(L['legend_closed'])}</p></section>")


def console_lanes_html(cm, esc, open_body):
    queue, closed = [], []
    L = cm["labels"]
    for n, lane in enumerate(cm["lanes"], 1):
        key = lane["key"]
        records = [f for f in cm["findings"] if f["lane"] == key]
        if key in ("closed", "excluded"):
            dest = closed
            rows = "".join(
                f"<li><span><a href='#{esc(f['anchor'])}'>{esc(f['id'])}</a><br>{esc(f['severity'])}</span>"
                f"<span>{esc(f['title'])}<span class='cx-loc'>{esc(f['location'])}</span></span>"
                f"<span class='cx-state'>{esc(f['status_label'])} · {esc(f['verdict'])}</span></li>"
                for f in records)
            body = f"<ul class='cx-doc-list'>{rows}</ul>" if rows else ""
        else:
            dest = queue
            body = open_body(records) if records else ""
        if not body:
            body = f"<p class='small'>{esc(L['lane_empty'])}</p>"
        dest.append(f"<div class='cx-doc-lane cx-c-{lane['tone']}' id='lane-{key}' data-lane='{key}'>"
                    f"<h3><span>{n}. {esc(lane['label'])}</span><span class='cx-count'>{len(records)}</span></h3>"
                    f"<p class='cx-lane-note small'>{esc(lane['note'])}</p>{body}</div>")
    return (f"<section id='triage-lanes'><h2>{esc(L['board_h'])}</h2>"
            f"<div id='priority-queue'>{''.join(queue)}</div><div id='closed-lanes'>{''.join(closed)}</div></section>")
