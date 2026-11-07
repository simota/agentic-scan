#!/usr/bin/env python3
"""Count requests to the inventory's routes and public assets in access logs (reference/usage.md).

    python3 usage.py INVENTORY LOG... [--findings FINDINGS] [--mount PREFIX]... [--json OUT] [--lang en|ja]

INVENTORY is inventory.py's output (or the review directory holding it). Each
LOG is an access log the requester supplied: Common or Combined Log Format
(nginx, Apache), a load balancer line holding "METHOD URL HTTP/x", or JSON
lines (nginx/Caddy/pino/GCP-style fields); .gz files are read compressed.
Every server and client route in inventory.json's routes and every public
asset in assets_unreferenced gets its request count, status classes and first
and last request seen, plus an evidence line for validation.evidence naming
the source, the window and the query. --mount PREFIX also matches a request
with that prefix removed (a router mounted under /api). --findings ties each
open finding to the routes and assets at its location and occurrences.

Only aggregate counts and path shapes reach the output: no client address,
user agent, query string or header, and id-like or secret-looking path
segments of unmatched requests are masked. Zero requests is evidence for the
window only; a client route counts only full page loads. Standard library only.
Exit status: 0 counted, 2 invalid input or unwritable output (reasons on stderr).
"""

import argparse
import gzip
import json
import os
import re
import sys
from collections import Counter
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from findings import (EXCLUDED, PURPOSE_FAMILIES, RecordError, check_findings, dump, load_json,  # noqa: E402
                      units_beside)
from inventory import PARAM, REGEX_ROUTE_TOKEN  # noqa: E402
from safe_output import SAFE_OUTPUT, tolerant_stdout, write_output_at  # noqa: E402
from safe_paths import open_directory  # noqa: E402
from safe_source import sensitive_source  # noqa: E402
from scan_report_kit.output import write_output  # noqa: E402

METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT")
# Route definitions that serve any method (Flask route, Django path, FastAPI api_route, Express all).
ANY_METHOD = {"", "ROUTE", "PATH", "RE_PATH", "API_ROUTE", "ALL", "WEBSOCKET"}
UNMATCHED_SHOWN = 20
MAX_LINE = 64 * 1024

CLF = re.compile(r'\[(?P<time>[^\]]{10,40})\]\s+"(?P<method>[A-Z]{3,7}) (?P<target>\S+)(?: [A-Z]+/[0-9.]+)?"\s+'
                 r'(?P<status>[0-9]{3})\b')
REQUEST = re.compile(r'"(?P<method>[A-Z]{3,7}) (?P<target>\S+) [A-Z]+/[0-9.]+"')
ISO_TIME = re.compile(r"\b[0-9]{4}-[0-9]{2}-[0-9]{2}[T ][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?")
JSON_METHOD = ("method", "request_method", "http_method", "httpMethod", "verb", "request.method", "req.method",
               "httpRequest.requestMethod", "http.request.method")
JSON_TARGET = ("path", "uri", "url", "request_uri", "requestUri", "request.uri", "request.path", "req.url",
               "httpRequest.requestUrl", "url.path", "url.original")
JSON_STATUS = ("status", "status_code", "statusCode", "response.status", "res.statusCode", "httpRequest.status",
               "http.response.status_code")
JSON_TIME = ("time", "timestamp", "@timestamp", "ts", "time_local", "date", "receiveTimestamp")

# Path segments of unmatched requests that could identify a person, a record or a secret.
# A file name with an extension (index-4f2a9c.js) is kept: tokens and record ids rarely carry one.
ID_SEGMENT = re.compile(r"[0-9]+|[0-9a-fA-F]{8,}|[0-9a-fA-F-]{32,36}|(?!.*\.[A-Za-z][A-Za-z0-9]{0,4}\Z)"
                        r".*[0-9].*[0-9].*[0-9].*")

TEXT = {
    "en": {
        "evidence": "{source}, {window} ({parsed} requests parsed{unparsed}): {hits} {noun} to {what}{mount}",
        "window": "{first} to {last} UTC", "no_window": "window unknown (no timestamps)",
        "unparsed": ", {n} lines not read as requests", "mount": " (also under {prefixes})",
        "one": "request", "many": "requests",
        "page": " - a client route counts full page loads only, not in-app navigation",
        "used": "requested in the window: evidence of use; reconsider the finding (Unlikely, or reduce)",
        "used_purpose": ("requested in the window: usage does not settle a purpose or over-built finding; "
                         "name these users in subtraction.loses"),
        "page_zero": "no full page load in the window: weak evidence, in-app navigation is not logged",
        "zero": ("no request in the window: settles the in-window question; check the window covers every "
                 "consumer's cadence before raising confidence"),
    },
    "ja": {
        "evidence": "{source}、{window}(解析したリクエスト {parsed} 件{unparsed}):{what} へのリクエスト {hits} 件{mount}",
        "window": "{first}〜{last} UTC", "no_window": "期間不明(タイムスタンプなし)",
        "unparsed": "、リクエストとして読めなかった行 {n} 行", "mount": "({prefixes} 配下も含む)",
        "one": "", "many": "",
        "page": "。クライアントルートはページの直接読み込みのみを数え、アプリ内遷移は含まない",
        "used": "期間内にリクエストあり:利用の証拠。指摘を見直す(Unlikely、または reduce)",
        "used_purpose": "期間内にリクエストあり:目的適合・過剰構築の指摘は利用量では決まらない。この利用者を subtraction.loses に書く",
        "page_zero": "期間内にページの直接読み込みなし:アプリ内遷移は記録されないため弱い証拠",
        "zero": "期間内にリクエストなし:期間内の利用は否定できる。確信度を上げる前に、期間が各利用者の周期を覆うか確認する",
    },
}


CLF_TIME = re.compile(r"([0-9]{2})/([A-Z][a-z]{2})/([0-9]{4}):([0-9]{2}):([0-9]{2}):([0-9]{2}) ([+-])([0-9]{2})([0-9]{2})\Z")
MONTHS = {m: i for i, m in enumerate(("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov",
                                      "Dec"), 1)}
MATCH_CACHE = 65536


class UsageError(Exception):
    pass


def dig(obj, dotted):
    for part in dotted.split("."):
        if not isinstance(obj, dict) or part not in obj:
            return None
        obj = obj[part]
    return obj


def first_value(obj, keys):
    """The first scalar among keys: an object under "url" (ECS) gives way to "url.path"."""
    for key in keys:
        value = dig(obj, key)
        if isinstance(value, (str, int, float)) and not isinstance(value, bool) and value != "":
            return value
    return None


def parse_time(value):
    """A UTC datetime from a CLF, ISO 8601 or epoch timestamp, or None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 1e11 else value  # Milliseconds since the epoch.
        try:
            return datetime.fromtimestamp(seconds, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        return None
    text = value.strip()
    m = CLF_TIME.match(text)  # strptime would cost more than the rest of a line's work.
    if m and m[2] in MONTHS:
        try:
            local = datetime(int(m[3]), MONTHS[m[2]], int(m[1]), int(m[4]), int(m[5]), int(m[6]))
        except ValueError:
            return None
        offset = (int(m[8]) * 60 + int(m[9])) * (1 if m[7] == "+" else -1)
        return (local - timedelta(minutes=offset)).replace(tzinfo=timezone.utc)
    text = re.sub(r"Z\Z", "+00:00", text.replace(" ", "T", 1))
    # Python 3.10's fromisoformat takes exactly 3 or 6 fraction digits: use microseconds.
    text = re.sub(r"\.([0-9]+)", lambda m: "." + (m.group(1) + "000000")[:6], text, count=1)
    text = re.sub(r"([+-][0-9]{2})([0-9]{2})\Z", r"\1:\2", text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return (parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)


def parse_line(line):
    """(method, target, status, time) of one request line, or None for a line that is not one."""
    line = line.strip()
    if not line:
        return None
    if line.startswith("{"):
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            return None
        if not isinstance(obj, dict):
            return None
        target = first_value(obj, JSON_TARGET)
        method = first_value(obj, JSON_METHOD)
        request = obj.get("request")
        if target is None and isinstance(request, str):  # nginx JSON with "$request": "GET /x HTTP/1.1".
            parts = request.split()
            if len(parts) >= 2:
                method, target = method or parts[0], parts[1]
        if not isinstance(target, str):
            return None
        status = first_value(obj, JSON_STATUS)
        status = int(status) if isinstance(status, (int, str)) and str(status).isdigit() else None
        return (str(method).upper() if isinstance(method, str) else "", target, status,
                parse_time(first_value(obj, JSON_TIME)))
    m = CLF.search(line)
    if m:
        return m["method"], m["target"], int(m["status"]), parse_time(m["time"])
    m = REQUEST.search(line)
    if m:
        t = ISO_TIME.search(line)
        return m["method"], m["target"], None, parse_time(t.group(0)) if t else None
    return None


def request_path(target):
    """The decoded path of a request target, without scheme, host, query or fragment."""
    if "://" in target[:12]:
        target = urlsplit(target).path or "/"
    target = target.split("?", 1)[0].split("#", 1)[0]
    if not target.startswith("/"):
        return None
    path = re.sub(r"/{2,}", "/", unquote(target))
    return path.rstrip("/") or "/"


def route_regex(route, method):
    """A full-match regex for request paths a route serves (inventory.py's PARAM syntax)."""
    route = route.removeprefix("^")
    route = route[:-1] if route.endswith("$") and not route.endswith("\\$") else route
    if method == "RE_PATH":
        route = "".join("<param>" if m.group(1) else m.group(2) or m.group(3)
                        for m in REGEX_ROUTE_TOKEN.finditer(route.removesuffix("/?")))
    route = route if route.startswith("/") else "/" + route
    pieces, last = [], 0
    for m in PARAM.finditer(route):
        pieces.append(re.escape(route[last:m.start()]))
        token = m.group(0)
        # A catch-all (<path:p>, *splat, [...slug], [[...slug]]) spans segments; any other parameter one.
        pieces.append(".*" if token.startswith("*") or token.startswith("<path:") or "..." in token else "[^/]+")
        last = m.end()
    pieces.append(re.escape(route[last:]))
    # Request paths lose their trailing slash (request_path), so the route does too.
    return re.compile(("".join(pieces).rstrip("/") or "/") + r"\Z")


def public_url_path(path):
    """The URL path a public asset is served at: what follows its public/, static/ or www/ directory."""
    m = re.match(r"(?:.*/)?(?:public|static|www)/(.+)\Z", path)
    return "/" + m.group(1) if m else None


class Target:
    def __init__(self, kind, label, row, regex=None, url=None, method=""):
        self.kind, self.label, self.row, self.regex, self.url = kind, label, row, regex, url
        self.method = method
        self.literal = len(PARAM.sub("", row["route"])) if kind != "asset" else len(url)
        self.hits, self.statuses, self.methods = 0, Counter(), Counter()
        self.first = self.last = None

    def serves(self, method):
        if self.kind == "asset" or self.method in ANY_METHOD or not method:
            return True
        return method == self.method or (self.method == "GET" and method == "HEAD")

    def count(self, method, status, when):
        self.hits += 1
        self.methods[method or "?"] += 1
        self.statuses[f"{status // 100}xx" if status else "unknown"] += 1
        if when is not None:
            self.first = when if self.first is None or when < self.first else self.first
            self.last = when if self.last is None or when > self.last else self.last


def build_targets(inventory):
    targets, buckets, wildcard, assets = [], {}, [], {}
    for row in inventory.get("routes", []):
        if not isinstance(row, dict) or not isinstance(row.get("route"), str):
            continue
        method = str(row.get("method", "")).upper()
        regex = route_regex(row["route"], method)
        label = f"{method} {row['route']}" if method and method not in ANY_METHOD else row["route"]
        t = Target(row.get("kind", "server"), label, row, regex=regex, method=method)
        targets.append(t)
        # The first literal segment narrows which routes a path could match.
        first = row["route"].removeprefix("^").lstrip("/").split("/")[0]
        if first and not PARAM.search(first) and not re.search(r"[\\()\[\]?*+.|]", first):
            buckets.setdefault(first, []).append(t)
        else:
            wildcard.append(t)
    for row in inventory.get("assets_unreferenced", []):
        if not isinstance(row, dict) or not row.get("public") or not isinstance(row.get("path"), str):
            continue
        url = public_url_path(row["path"])
        if url:
            t = Target("asset", url, row, url=url)
            targets.append(t)
            assets.setdefault(url, []).append(t)
    return targets, buckets, wildcard, assets


def candidates(path, buckets, wildcard):
    first = path.lstrip("/").split("/")[0]
    return buckets.get(first, []) + wildcard


def mask_path(path):
    """The shape of an unmatched path: id-like, long or secret-looking segments masked."""
    out = []
    for seg in path.split("/")[1:]:
        if not seg:
            continue
        if ID_SEGMENT.fullmatch(seg):
            out.append("{id}")
        elif len(seg) > 40 or "@" in seg or "=" in seg or sensitive_source(seg):
            out.append("{redacted}")
        else:
            out.append(seg)
    return "/" + "/".join(out)


def open_log(path):
    raw = open(path, "rb")
    try:
        head = raw.read(2)
        raw.seek(0)
        stream = gzip.open(raw) if head == b"\x1f\x8b" else raw
    except OSError:
        raw.close()
        raise
    return raw, stream


def count_logs(paths, targets_index, mounts):
    _, buckets, wildcard, assets = targets_index
    totals = {"lines": 0, "parsed": 0, "unparsed": 0, "matched": 0, "first": None, "last": None}
    unmatched, cache = Counter(), {}
    for path in paths:
        raw, stream = open_log(path)
        with raw:
            try:
                for data in stream:
                    totals["lines"] += 1
                    if len(data) > MAX_LINE:
                        totals["unparsed"] += 1
                        continue
                    request = parse_line(data.decode("utf-8", "replace"))
                    target_path = request_path(request[1]) if request else None
                    if target_path is None:
                        totals["unparsed"] += int(bool(data.strip()))
                        continue
                    method, _, status, when = request
                    totals["parsed"] += 1
                    if when is not None:
                        totals["first"] = when if totals["first"] is None or when < totals["first"] else totals["first"]
                        totals["last"] = when if totals["last"] is None or when > totals["last"] else totals["last"]
                    key = (method, target_path)
                    hit = cache.get(key, False)
                    if hit is False:
                        hit = match(target_path, method, buckets, wildcard, assets, mounts)
                        if len(cache) < MATCH_CACHE:  # Paths repeat; a bounded cache keeps memory flat.
                            cache[key] = hit
                    if hit:
                        totals["matched"] += 1
                        for t in hit:
                            t.count(method, status, when)
                    else:
                        unmatched[mask_path(target_path)] += 1
            except (OSError, EOFError, gzip.BadGzipFile) as e:
                raise UsageError(f"{path}: cannot read: {e}") from None
    return totals, unmatched


def match(path, method, buckets, wildcard, assets, mounts):
    """The targets one request reaches: the most literal route for the path, or a public asset."""
    stripped = [path[len(m):] or "/" for m in mounts if path == m or path.startswith(m + "/")]
    for mounted, candidate in [(False, path)] + [(True, c) for c in stripped]:
        if not mounted and candidate in assets:
            return assets[candidate]
        # A mount prefix is a server router's; a page or an asset is served at its own path.
        hits = [t for t in candidates(candidate, buckets, wildcard)
                if (t.kind == "server" or not mounted) and t.regex.match(candidate) and t.serves(method)]
        if hits:
            # /items/new beats /items/<id>: keep the routes with the most literal characters.
            best = max(t.literal for t in hits)
            return [t for t in hits if t.literal == best]
    return None


def iso(when):
    return when.strftime("%Y-%m-%dT%H:%M:%SZ") if when else None


def evidence(t, totals, sources, mounts, lang):
    T = TEXT[lang]
    window = (T["window"].format(first=iso(totals["first"])[:10], last=iso(totals["last"])[:10])
              if totals["first"] else T["no_window"])
    noun = T["one"] if t.hits == 1 else T["many"]
    text = T["evidence"].format(
        source=", ".join(sources), window=window, parsed=f"{totals['parsed']:,}",
        unparsed=T["unparsed"].format(n=f"{totals['unparsed']:,}") if totals["unparsed"] else "",
        hits=f"{t.hits:,}", noun=noun, what=t.label,
        mount=T["mount"].format(prefixes=", ".join(mounts)) if mounts and t.kind != "asset" else "")
    text = re.sub(r" {2,}", " ", text)
    return text + (T["page"] if t.kind == "client" else "")


def location_file(location):
    return re.sub(r":[1-9][0-9]*(?:-[1-9][0-9]*)?\Z", "", location)


def tie_findings(record, rows, lang):
    """Open, counted findings with the routes and assets they name, by location and occurrences."""
    by_location, by_file = {}, {}
    for row in rows:
        if row["kind"] == "asset":
            by_file.setdefault(row["path"], []).append(row)
        else:
            by_location.setdefault(row["location"], []).append(row)
    tied = []
    for f in record["findings"]:
        if f["status"] != "Open" or f["validation"]["verdict"] in EXCLUDED:
            continue
        places = [f["location"], *f.get("occurrences", [])]
        hit = [r for p in places for r in by_location.get(p, []) + by_file.get(location_file(p), [])]
        hit = list({id(r): r for r in hit}.values())
        if not hit:
            continue
        total = sum(r["requests"] for r in hit)
        if total:
            key = "used_purpose" if f["perspective"][:2] in PURPOSE_FAMILIES else "used"
        else:
            key = "page_zero" if any(r["kind"] == "client" for r in hit) else "zero"
        reading = TEXT[lang][key]
        tied.append({"id": f["id"], "element": f["element"], "confidence": f["confidence"],
                     "verdict": f["validation"]["verdict"], "requests": total,
                     "targets": [r["target"] for r in hit], "reading": reading})
    return tied


def checked_inventory(path):
    target = Path(path)
    if target.is_dir():
        target = target / "inventory.json"
    data = load_json(target)
    if not isinstance(data, dict) or data.get("tool") != "inventory.py":
        raise UsageError(f"{path}: not an inventory.py output")
    return target, data


def main(argv=None):
    tolerant_stdout()
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("inventory", help="inventory.py output (inventory.json, or the review directory holding it)")
    p.add_argument("logs", nargs="+", metavar="LOG", help="access log files (CLF, combined, JSON lines; .gz read)")
    p.add_argument("--findings", help="findings.json: tie each open finding to the routes and assets it names")
    p.add_argument("--mount", action="append", default=[], metavar="PREFIX",
                   help="also match requests with this path prefix removed (a router mounted under /api); repeatable")
    p.add_argument("--json", help="write the counts as JSON to this file (scratch, not the reviewed repository)")
    p.add_argument("--lang", choices=("en", "ja"), default="en",
                   help="language of the evidence lines (default: en)")
    a = p.parse_args(argv)
    mounts = []
    for prefix in a.mount:
        clean = "/" + prefix.strip("/")
        if clean == "/" or not re.fullmatch(r"(?:/[^/\s?#]+)+", clean):
            print(f"usage.py: --mount {prefix!r}: expected a path prefix such as /api", file=sys.stderr)
            return 2
        mounts.append(clean)
    try:
        inventory_path, inventory = checked_inventory(a.inventory)
        record = None
        if a.findings:
            record = check_findings(load_json(a.findings), units_beside(a.findings), ordered=False)
        for log in a.logs:
            if not Path(log).is_file():
                raise UsageError(f"{log}: not a file")
        index = build_targets(inventory)
        totals, unmatched = count_logs(a.logs, index, mounts)
    except (UsageError, RecordError, OSError) as e:
        print(f"usage.py: {e}", file=sys.stderr)
        return 2
    sources = [Path(x).name for x in a.logs]
    rows = []
    for t in index[0]:
        row = {"target": t.label, "kind": t.kind, "requests": t.hits,
               "statuses": dict(sorted(t.statuses.items())), "first_seen": iso(t.first), "last_seen": iso(t.last),
               "evidence": evidence(t, totals, sources, mounts, a.lang)}
        if t.kind == "asset":
            row["path"] = t.row["path"]
        else:
            row.update(route=t.row["route"], method=t.row.get("method", ""), location=t.row.get("location", ""))
            if t.methods and t.method in ANY_METHOD:
                row["methods"] = dict(sorted(t.methods.items()))
        for key in ("unit", "mentions"):
            if key in t.row:
                row[key] = t.row[key]
        rows.append(row)
    truncated = {k: v for k, v in (inventory.get("truncated") or {}).items()
                 if k in ("routes", "assets_unreferenced")}
    result = {
        "tool": "usage.py", "version": 1, "sources": sources, "mounts": mounts,
        "window": {"first": iso(totals["first"]), "last": iso(totals["last"])},
        "lines": totals["lines"], "requests_parsed": totals["parsed"], "lines_unparsed": totals["unparsed"],
        "requests_matched": totals["matched"], "inventory_truncated": truncated,
        "targets": rows,
        "unmatched": [{"path": k, "requests": v} for k, v in unmatched.most_common(UNMATCHED_SHOWN)],
        "unmatched_paths": len(unmatched),
    }
    if record is not None:
        result["findings"] = tie_findings(record, rows, a.lang)
    if a.json:
        protected = []
        for path in [inventory_path, *a.logs, *([a.findings] if a.findings else [])]:
            try:
                protected.append(os.stat(path))
            except OSError:
                pass
        output = Path(a.json)
        try:
            text = dump(result)
            with ExitStack() as resources:
                if SAFE_OUTPUT:
                    selected = output.parent.stat()
                    directory = open_directory(output.parent.resolve(strict=True), readable=False,
                                               expected_stat=selected)
                    resources.callback(os.close, directory)
                    write_output_at(directory, output.name, text, protected=tuple(protected))
                else:
                    if output.exists() and any(os.path.samestat(os.stat(output), s) for s in protected):
                        raise OSError("output would overwrite an input")
                    write_output(output, text)
        except (OSError, ValueError, RecordError) as e:
            print(f"usage.py: cannot write {a.json}: {e}", file=sys.stderr)
            return 2
    print(text_report(result))
    return 0


def text_report(result):
    w = result["window"]
    window = f"{w['first'][:10]} to {w['last'][:10]}" if w["first"] else "window unknown"
    lines = [f"prune-scan usage: {result['requests_parsed']:,} requests ({window}), "
             f"{result['requests_matched']:,} matched; {len(result['targets'])} routes and public assets counted; "
             f"{result['lines_unparsed']:,} line{'' if result['lines_unparsed'] == 1 else 's'} not read as requests"]
    zero = [r for r in result["targets"] if not r["requests"]]
    used = [r for r in result["targets"] if r["requests"]]
    if zero:
        lines.append("no request in the window:")
        lines += [f"  {r['target']}  {r.get('location') or r.get('path')}"
                  + ("  (client route: page loads only)" if r["kind"] == "client" else "") for r in zero]
    if used:
        lines.append("requested:")
        lines += [f"  {r['target']}  {r['requests']:,}  last {r['last_seen'] or '?'}" for r in used]
    for f in result.get("findings", []):
        lines.append(f"finding {f['id']} ({f['confidence']}, {f['verdict']}): {f['requests']:,} requests - "
                     f"{f['reading']}")
    if result["unmatched"]:
        lines.append(f"unmatched paths ({result['unmatched_paths']:,} shapes; a route the inventory missed "
                     "or a consumer to name): "
                     + ", ".join(f"{u['path']} {u['requests']:,}" for u in result["unmatched"][:5]))
    if result["inventory_truncated"]:
        lines.append("inventory truncated (unlisted routes count as unmatched): "
                     + ", ".join(f"{k} +{v}" for k, v in result["inventory_truncated"].items()))
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
