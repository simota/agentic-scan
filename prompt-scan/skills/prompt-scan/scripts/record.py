"""The findings.json record: its vocabulary, strict parsing, structural validation and safe replacement.

Every tool shares this contract: findings.py merges into it, inventory.py writes its L-* findings and Git
state into it, render.py renders it and contract_check.py checks a finished run against it. The schema
itself is documented in reference/findings-schema.md.
"""
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile

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
# Report languages; render.py holds a label set for each.
LANGS = ("en", "ja")
# Whether the requester confirmed the trust boundary severity is judged against (meta.axis).
AXES = ("confirmed", "assumed")
MAX_JSON_DEPTH = 100


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
    _validate_meta(data.get("meta", {}))
    for key in ("prompts", "findings", "eval_runs", "perspectives", *STRING_LISTS):
        if not isinstance(data.get(key, []), list):
            raise SchemaError(f"{key} must be a list")
    for key in STRING_LISTS:
        if not all(isinstance(x, str) and x.strip() for x in data.get(key, [])):
            raise SchemaError(f"{key} entries must be nonblank strings")
    prompts = _validate_prompts(data.get("prompts", []))
    findings = _validate_findings(data.get("findings", []), prompts)
    _validate_eval_runs(data.get("eval_runs", []), findings)
    _validate_perspectives(data.get("perspectives", []))
    return data


def _validate_meta(meta):
    if not isinstance(meta, dict):
        raise SchemaError("meta must be an object")
    for key in ("target", "date", "assessor", "scope", "lang"):
        _str(meta, key, "meta")
    # Any other value would silently fall back to a Japanese report.
    if meta.get("lang") is not None and meta["lang"] not in LANGS:
        raise SchemaError(f"meta.lang must be one of {', '.join(sorted(LANGS))} "
                          '(findings.py merge a fragment {"meta": {"lang": ...}} to set it)')
    if meta.get("axis") is not None and meta["axis"] not in AXES:
        raise SchemaError(f"meta.axis must be one of {', '.join(AXES)}")
    if meta.get("commit") is not None and not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(meta["commit"])):
        raise SchemaError("meta.commit must be a full Git object id or null")
    if meta.get("dirty") is not None and not isinstance(meta["dirty"], bool):
        raise SchemaError("meta.dirty must be true, false or null")


def _validate_prompts(prompts):
    """The recorded prompt ids, once every prompt record is checked."""
    seen = set()
    for i, p in enumerate(prompts):
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
    return seen


def _validate_findings(findings, prompts):
    """The recorded finding ids, once every finding is checked against the recorded prompt ids."""
    seen = set()
    for i, f in enumerate(findings):
        if not isinstance(f, dict) or not FINDING_ID.fullmatch(str(f.get("id", ""))):
            raise SchemaError(f"findings[{i}].id must be F-NNN or L-NNN")
        if f["id"] in seen:
            raise SchemaError(f"duplicate finding id {f['id']}")
        seen.add(f["id"])
        _validate_finding(f, f"findings[{f['id']}]", prompts)
    return seen


def _validate_finding(f, where, prompts):
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


def _validate_eval_runs(runs, findings):
    seen = set()
    for i, run in enumerate(runs):
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


def _validate_perspectives(perspectives):
    for i, p in enumerate(perspectives):
        where = f"perspectives[{i}]"
        if not isinstance(p, dict):
            raise SchemaError(f"{where} must be an object")
        _str(p, "name", where, True)
        _enum(p, "result", RESULTS, where)
        _str(p, "note", where)


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


def read_regular(path):
    """Read a regular file, never a FIFO, device or symlink."""
    path = Path(path)
    if not stat.S_ISREG(os.lstat(str(path)).st_mode):
        raise OSError(f"{path}: not a regular file")
    return path.read_bytes()


def read_json(path, raw=None):
    try:
        raw = read_regular(path) if raw is None else raw
    except OSError as e:
        raise SchemaError(f"{path}: {e}") from None
    return parse_json(raw, path)


class MergeConflict(Exception):
    pass


def write_report(path, data, original):
    """Replace path atomically unless another writer changed it since it was read."""
    path = Path(path)
    lock = path.with_name(path.name + ".lock")
    try:
        fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise MergeConflict(f"{lock}: a writer lock exists; check the other writer before removing a stale lock") from None
    os.close(fd)
    temp = None
    try:
        current = path.read_bytes() if path.exists() else None
        if path.is_symlink() or current != original:
            raise MergeConflict(f"{path}: file changed concurrently; no update written")
        # Keep an existing file's permissions; a new one is private, like the rendered outputs.
        mode = stat.S_IMODE(os.stat(str(path)).st_mode) if current is not None else 0o600
        fd, temp = tempfile.mkstemp(prefix="." + path.name + ".", dir=str(path.parent))
        with os.fdopen(fd, "wb") as stream:
            stream.write((json.dumps(data, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None and os.path.exists(temp):
            os.unlink(temp)
        lock.unlink(missing_ok=True)

