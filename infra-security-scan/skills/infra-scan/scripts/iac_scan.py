#!/usr/bin/env python3
"""Inventory infrastructure as code and apply deterministic baseline rules.

    python3 iac_scan.py REPO [--out iac.json] [--into findings.json]

Reads, never executes: Terraform/OpenTofu (`*.tf`), Terraform plan JSON
(`terraform show -json` output the requester produced), CloudFormation JSON,
Kubernetes YAML manifests and read-only config snapshots (AWS
describe-security-groups, a bucket policy, a GCP IAM policy, a GCP firewall
list). It never runs terraform, a cloud CLI or an SDK, and never follows
symlinks.

Each rule hit is a hypothesis, not a finding: hits are grouped per (rule, file)
into `I-*` findings with verdict `Unverified`, to be triaged in REVIEW. Values
the parser cannot resolve (variables, references, functions) are UNKNOWN and
never produce a hit — precision over completeness. A secret is recorded by
location and kind only; its value never reaches the output. Benchmark controls
name the section title only; section numbers vary by edition.

--out writes the inventory (`iac.json`); without it the inventory goes to stdout.
--into replaces every `I-*` finding in findings.json (creating it when absent),
keeps every other finding, and sets `meta.commit` and `inventory`.

Exit codes: 0 scanned (hits do not change it), 2 unreadable REPO or findings.json.
"""
import argparse
import bisect
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv", "__pycache__"}
MAX_BYTES = 2 * 1024 * 1024
WORLD = ("0.0.0.0/0", "::/0")
SEV_RANK = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
SENSITIVE_PORTS = {
    22: "SSH", 23: "Telnet", 445: "SMB", 1433: "SQL Server", 1521: "Oracle", 2375: "Docker",
    2376: "Docker", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 6443: "Kubernetes API", 9042: "Cassandra",
    9200: "Elasticsearch", 9300: "Elasticsearch", 10250: "Kubelet", 11211: "Memcached",
    27017: "MongoDB",
}

# Controls name the benchmark and the section title only. Section numbers change
# between editions; the reviewer copies the number from the edition in use.
# id: (title, default severity, perspective, provider, controls, cwe)
RULES = {
    "AWS-NET-001": ("Security group allows internet ingress to an admin or data port", "High",
                    "Network exposure", "aws", ["CIS AWS Foundations — no security group allows 0.0.0.0/0 to admin ports", "CIS AWS Foundations — no security group allows ::/0 to admin ports"], "CWE-284"),
    "AWS-S3-001": ("S3 bucket ACL grants public access", "High", "Data protection", "aws",
                   ["CIS AWS Foundations — S3 Block Public Access is enabled"], "CWE-200"),
    "AWS-S3-002": ("S3 public access block leaves a protection off", "Medium", "Data protection",
                   "aws", ["CIS AWS Foundations — S3 Block Public Access is enabled"], "CWE-200"),
    "AWS-S3-003": ("Resource policy allows any principal without a condition", "High",
                   "Data protection", "aws", ["CIS AWS Foundations — S3 Block Public Access is enabled"], "CWE-284"),
    "AWS-IAM-001": ("IAM policy grants all actions on all resources", "High",
                    "Identity and privilege", "aws", ["CIS AWS Foundations — no IAM policy grants full *:* admin privileges"], "CWE-250"),
    "AWS-IAM-002": ("IAM policy grants iam:PassRole on any role", "Medium",
                    "Identity and privilege", "aws", [], "CWE-269"),
    "AWS-IAM-003": ("Role trust policy lets any AWS principal assume the role", "High",
                    "Trust and federation", "aws", [], "CWE-284"),
    "AWS-IAM-004": ("GitHub OIDC trust does not pin the repository subject", "High",
                    "Trust and federation", "aws", [], "CWE-287"),
    "AWS-IAM-005": ("IAM user with long-lived credentials managed in IaC", "Medium",
                    "Identity and privilege", "aws", [], "CWE-798"),
    "AWS-RDS-001": ("Database instance is publicly accessible", "High", "Network exposure", "aws",
                    ["CIS AWS Foundations — RDS instances are not publicly accessible"], "CWE-668"),
    "AWS-RDS-002": ("Database storage not encrypted", "Low", "Data protection", "aws",
                    ["CIS AWS Foundations — RDS storage encryption is enabled"], "CWE-311"),
    "AWS-EC2-001": ("Instance metadata service does not require IMDSv2", "Medium",
                    "Compute and workload", "aws", ["CIS AWS Foundations — EC2 metadata service requires IMDSv2"], "CWE-918"),
    "AWS-EBS-001": ("EBS volume not encrypted", "Low", "Data protection", "aws",
                    ["CIS AWS Foundations — EBS volume encryption is enabled"], "CWE-311"),
    "AWS-LAMBDA-001": ("Lambda function URL requires no authentication", "Medium",
                       "Serverless and API edge", "aws", [], "CWE-306"),
    "AWS-LAMBDA-002": ("Lambda permission lets any principal invoke the function", "Medium",
                       "Serverless and API edge", "aws", [], "CWE-284"),
    "AWS-CT-001": ("CloudTrail not multi-region or without log file validation", "Low",
                   "Logging and detection", "aws", ["CIS AWS Foundations — CloudTrail is enabled in all regions", "CIS AWS Foundations — CloudTrail log file validation is enabled"], "CWE-778"),
    "AWS-KMS-001": ("KMS key rotation not enabled", "Low", "Secrets and keys", "aws",
                    ["CIS AWS Foundations — rotation is enabled for customer-managed KMS keys"], "CWE-324"),
    "AWS-EKS-001": ("EKS API endpoint public to any address", "Medium", "Kubernetes", "aws",
                    [], "CWE-284"),
    "GCP-NET-001": ("Firewall allows internet ingress to an admin or data port", "High",
                    "Network exposure", "gcp", ["CIS GCP Foundation — SSH is not open to the internet", "CIS GCP Foundation — RDP is not open to the internet"], "CWE-284"),
    "GCP-IAM-001": ("IAM binding grants a role to allUsers or allAuthenticatedUsers", "High",
                    "Data protection", "gcp", ["CIS GCP Foundation — Cloud Storage buckets are not publicly accessible"], "CWE-200"),
    "GCP-IAM-002": ("Basic role roles/owner or roles/editor granted", "Medium",
                    "Identity and privilege", "gcp", ["CIS GCP Foundation — service accounts hold no admin or basic roles"], "CWE-250"),
    "GCP-IAM-003": ("User-managed service account key created", "Medium",
                    "Identity and privilege", "gcp", ["CIS GCP Foundation — only GCP-managed service account keys exist"], "CWE-798"),
    "GCP-IAM-004": ("Service account impersonation role granted above the service account", "Medium",
                    "Trust and federation", "gcp", ["CIS GCP Foundation — no project-level Service Account User / Token Creator"], "CWE-269"),
    "GCP-GCS-001": ("Bucket without uniform access or enforced public access prevention", "Low",
                    "Data protection", "gcp", ["CIS GCP Foundation — uniform bucket-level access is enabled"], "CWE-284"),
    "GCP-SQL-001": ("Cloud SQL reachable from any address or without required TLS", "High",
                    "Network exposure", "gcp", ["CIS GCP Foundation — Cloud SQL is not open to 0.0.0.0/0", "CIS GCP Foundation — Cloud SQL requires SSL"], "CWE-668"),
    "GCP-GCE-001": ("Instance runs as the default compute service account", "Medium",
                    "Compute and workload", "gcp", ["CIS GCP Foundation — instances do not use the default service account", "CIS GCP Foundation — instances do not use the default service account with full API access"], "CWE-250"),
    "GCP-GCE-002": ("Instance metadata enables serial port or project-wide SSH keys", "Low",
                    "Compute and workload", "gcp", ["CIS GCP Foundation — block project-wide SSH keys is enabled", "CIS GCP Foundation — serial port access is disabled"], "CWE-284"),
    "GCP-GKE-001": ("GKE cluster control plane or identity hardening missing", "Medium",
                    "Kubernetes", "gcp", [], "CWE-284"),
    "GCP-WIF-001": ("Workload identity provider without an attribute condition", "High",
                    "Trust and federation", "gcp", [], "CWE-287"),
    "SEC-001": ("Literal secret committed to the repository", "High", "Secrets and keys",
                "multi", [], "CWE-798"),
    "SEC-002": ("Terraform state file committed to the repository", "High", "Secrets and keys",
                "multi", [], "CWE-312"),
    "PS-001": ("Module source not pinned to a version or commit", "Low", "Pipeline and state",
               "multi", [], "CWE-829"),
    "PS-002": ("Terraform state backend unencrypted or local", "Medium", "Pipeline and state",
               "multi", [], "CWE-312"),
    "PS-003": ("Provider block configures static credentials", "Medium", "Pipeline and state",
               "multi", [], "CWE-798"),
    "K8S-001": ("Pod runs privileged or with host access", "Medium", "Kubernetes", "kubernetes",
                [], "CWE-250"),
    "K8S-002": ("RBAC binding grants cluster-admin or binds every authenticated user", "High",
                "Kubernetes", "kubernetes", [], "CWE-269"),
    "K8S-003": ("Kubernetes Secret with data committed", "Medium", "Kubernetes", "kubernetes",
                [], "CWE-312"),
}


class _Unknown:
    __slots__ = ()

    def __repr__(self):
        return "UNKNOWN"


UNKNOWN = _Unknown()

# ---------------------------------------------------------------- HCL scanning

IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_]*)[ \t]*\r?\n")
NUMBER = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")
OPEN, CLOSE = "([{", ")]}"


def line_end(t, i):
    j = t.find("\n", i)
    return len(t) if j < 0 else j


def heredoc_span(t, m):
    """(content_start, content_end, after) for the heredoc opened by match m."""
    marker, pos = m.group(2), m.end()
    while pos < len(t):
        end = line_end(t, pos)
        if t[pos:end].strip() == marker:
            return m.end(), pos, end
        pos = end + 1
    return m.end(), len(t), len(t)


def skip_string(t, i):
    """t[i] is an opening quote; return the index after the closing one."""
    i += 1
    while i < len(t):
        c = t[i]
        if c == "\\":
            i += 2
        elif c == '"':
            return i + 1
        elif t.startswith(("$${", "%%{"), i):
            i += 3
        elif c in "$%" and t.startswith("{", i + 1):
            i = skip_balanced(t, i + 1)
        else:
            i += 1
    return len(t)


def skip_balanced(t, i):
    """t[i] is an opening bracket; return the index after its match."""
    depth = 0
    while i < len(t):
        c = t[i]
        if c == '"':
            i = skip_string(t, i)
            continue
        if c == "#" or t.startswith("//", i):
            i = line_end(t, i)
            continue
        if t.startswith("/*", i):
            j = t.find("*/", i + 2)
            i = len(t) if j < 0 else j + 2
            continue
        m = HEREDOC.match(t, i)
        if m:
            i = heredoc_span(t, m)[2]
            continue
        if c in OPEN:
            depth += 1
        elif c in CLOSE:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return len(t)


def scan_expr(t, i, end):
    """End of an attribute value starting at i: newline or '}' at depth 0."""
    while i < end:
        c = t[i]
        if c in "\n}" or c == "#" or t.startswith("//", i):
            return i
        if c == '"':
            i = skip_string(t, i)
        elif t.startswith("/*", i):
            j = t.find("*/", i + 2)
            i = end if j < 0 else j + 2
        elif HEREDOC.match(t, i):
            i = heredoc_span(t, HEREDOC.match(t, i))[2]
        elif c in OPEN:
            i = skip_balanced(t, i)
        else:
            i += 1
    return min(i, end)


def skip_space(t, i, end, newlines=True):
    while i < end:
        c = t[i]
        if c in " \t\r" or (newlines and c == "\n"):
            i += 1
        elif c == "#" or t.startswith("//", i):
            i = line_end(t, i)
        elif t.startswith("/*", i):
            j = t.find("*/", i + 2)
            i = end if j < 0 else j + 2
        else:
            break
    return i


class LineIndex:
    def __init__(self, text):
        self.starts = [0] + [i + 1 for i, c in enumerate(text) if c == "\n"]

    def __call__(self, pos):
        return bisect.bisect_right(self.starts, pos)


class Block:
    __slots__ = ("type", "labels", "attrs", "blocks", "line", "end")

    def __init__(self, type_, labels, line, end):
        self.type, self.labels, self.line, self.end = type_, labels, line, end
        self.attrs, self.blocks = {}, []


def parse_body(t, start, end, line_of):
    """Attributes {name: (raw, line)} and nested blocks of t[start:end]."""
    attrs, blocks, i = {}, [], start
    while True:
        i = skip_space(t, i, end)
        if i >= end:
            return attrs, blocks
        m = IDENT.match(t, i)
        if not m:
            i = line_end(t, i) + 1
            continue
        name, j = m.group(), skip_space(t, m.end(), end, newlines=False)
        if j < end and t[j] == "=" and not t.startswith("==", j):
            k = scan_expr(t, j + 1, end)
            attrs[name] = (t[j + 1:k].strip(), line_of(i))
            i = k
            continue
        labels = []
        while j < end and t[j] != "{":
            if t[j] == '"':
                k = skip_string(t, j)
                labels.append(t[j + 1:k - 1])
            else:
                lm = IDENT.match(t, j)
                if not lm:
                    break
                k = lm.end()
                labels.append(lm.group())
            j = skip_space(t, k, end, newlines=False)
        if j < end and t[j] == "{":
            close = skip_balanced(t, j)
            block = Block(name, labels, line_of(i), line_of(close - 1))
            block.attrs, block.blocks = parse_body(t, j + 1, close - 1, line_of)
            blocks.append(block)
            i = close
            continue
        i = line_end(t, i) + 1


def parse_hcl(text):
    return parse_body(text, 0, len(text), LineIndex(text))[1]


class _Lit:
    """Literal HCL values: strings, numbers, bools, lists, objects, jsonencode().

    Anything else (references, functions, operators, templates) is UNKNOWN."""

    SEP = ",]})\n"

    def __init__(self, s):
        self.s, self.i = s, 0

    def ws(self, newlines=True):
        self.i = skip_space(self.s, self.i, len(self.s), newlines)

    def value(self):
        self.ws()
        start = self.i
        v = self.primary()
        self.ws(newlines=False)
        if self.i < len(self.s) and self.s[self.i] not in self.SEP:
            self.skip_term()
            return UNKNOWN
        if self.i == start:
            self.skip_term()
            return UNKNOWN
        return v

    def primary(self):
        s, i = self.s, self.i
        if i >= len(s):
            return UNKNOWN
        c = s[i]
        if c == '"':
            j = skip_string(s, i)
            self.i = j
            return unquote(s[i + 1:j - 1])
        m = HEREDOC.match(s, i)
        if m:
            a, b, after = heredoc_span(s, m)
            self.i = after
            return s[a:b]
        if c == "[":
            return self.seq()
        if c == "{":
            return self.obj()
        m = NUMBER.match(s, i)
        if m:
            self.i = m.end()
            text = m.group()
            return int(text) if re.fullmatch(r"-?\d+", text) else float(text)
        m = IDENT.match(s, i)
        if m:
            word, after = m.group(), m.end()
            nxt = s[after:after + 1]
            if word in ("true", "false", "null") and nxt not in (".", "(", "["):
                self.i = after
                return {"true": True, "false": False, "null": None}[word]
            if word in ("jsonencode", "tolist", "toset") and nxt == "(":
                self.i = after + 1
                v = self.value()
                self.ws()
                if self.i < len(s) and s[self.i] == ")":
                    self.i += 1
                    return v
                self.i = skip_balanced(s, after)
                return UNKNOWN
        self.skip_term()
        return UNKNOWN

    def seq(self):
        s, start = self.s, self.i
        self.i += 1
        out = []
        while True:
            self.ws()
            if self.i >= len(s):
                return UNKNOWN
            if s[self.i] == "]":
                self.i += 1
                return out
            if s.startswith("for ", self.i):
                self.i = skip_balanced(s, start)
                return UNKNOWN
            before = self.i
            out.append(self.value())
            self.ws()
            if self.i < len(s) and s[self.i] == ",":
                self.i += 1
            elif self.i == before:
                self.i += 1

    def obj(self):
        s, start = self.s, self.i
        self.i += 1
        out = {}
        while True:
            self.ws()
            if self.i >= len(s):
                return UNKNOWN
            if s[self.i] == "}":
                self.i += 1
                return out
            if s.startswith("for ", self.i):
                self.i = skip_balanced(s, start)
                return UNKNOWN
            if s[self.i] == '"':
                j = skip_string(s, self.i)
                key = unquote(s[self.i + 1:j - 1])
                self.i = j
            elif s[self.i] == "(":
                self.i = skip_balanced(s, self.i)
                key = UNKNOWN
            else:
                m = IDENT.match(s, self.i)
                if not m:
                    self.i = skip_balanced(s, start)
                    return UNKNOWN
                key, self.i = m.group(), m.end()
            self.ws(newlines=False)
            if self.i >= len(s) or s[self.i] not in "=:":
                self.i = skip_balanced(s, start)
                return UNKNOWN
            self.i += 1
            v = self.value()
            if isinstance(key, str):
                out[key] = v
            self.ws()
            if self.i < len(s) and s[self.i] == ",":
                self.i += 1

    def skip_term(self):
        s, i = self.s, self.i
        while i < len(s):
            c = s[i]
            if c in self.SEP or c == "#" or s.startswith("//", i):
                break
            if c == '"':
                i = skip_string(s, i)
            elif c in OPEN:
                i = skip_balanced(s, i)
            elif HEREDOC.match(s, i):
                i = heredoc_span(s, HEREDOC.match(s, i))[2]
            else:
                i += 1
        self.i = i


def unquote(raw):
    if re.search(r"(?<![$%])[$%]\{", raw):
        return UNKNOWN
    raw = raw.replace("$${", "${").replace("%%{", "%{")
    try:
        return json.loads('"' + raw + '"')
    except ValueError:
        return raw


def literal(raw):
    p = _Lit(raw)
    v = p.value()
    p.ws()
    return v if p.i >= len(raw) else UNKNOWN


# ---------------------------------------------------------------- views

class HclView:
    def __init__(self, block):
        self.block = block
        self._cache = {}

    def get(self, name):
        if name not in self.block.attrs:
            return None
        if name not in self._cache:
            self._cache[name] = literal(self.block.attrs[name][0])
        return self._cache[name]

    def raw(self, name):
        attr = self.block.attrs.get(name)
        return attr[0] if attr else None

    def blocks(self, name):
        found = [HclView(b) for b in self.block.blocks if b.type == name]
        if found or name not in self.block.attrs:
            return found
        return DictView.wrap(self.get(name), self.line(name))

    def line(self, name=None):
        if name and name in self.block.attrs:
            return self.block.attrs[name][1]
        return self.block.line


class DictView:
    def __init__(self, data, line):
        self.data, self._line = data, line

    @staticmethod
    def wrap(value, line):
        if isinstance(value, dict):
            return [DictView(value, line)]
        if isinstance(value, list):
            return [DictView(v, line) for v in value if isinstance(v, dict)]
        return []

    def get(self, name):
        return self.data.get(name)

    def raw(self, name):
        return None

    def blocks(self, name):
        return self.wrap(self.data.get(name), self._line)

    def line(self, name=None):
        return self._line


class Res:
    __slots__ = ("type", "address", "file", "line", "view", "dir")

    def __init__(self, type_, address, file, line, view=None, dir_=""):
        self.type, self.address, self.file, self.line = type_, address, file, line
        self.view, self.dir = view, dir_


def aslist(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def to_int(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and re.fullmatch(r"-?\d+", value.strip()):
        return int(value)
    return None


def provider_of(type_):
    for prefix, name in (("aws_", "aws"), ("google_", "gcp"), ("azurerm_", "azure"),
                         ("kubernetes_", "kubernetes"), ("AWS::", "aws")):
        if type_.startswith(prefix):
            return name
    return "other"


# ---------------------------------------------------------------- policies

DOC_REF = re.compile(r'^"?(?:\$\{)?data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)\.json\}?"?$')


def norm_statements(doc):
    if not isinstance(doc, dict):
        return None
    sts = doc.get("Statement")
    if isinstance(sts, dict):
        sts = [sts]
    if not isinstance(sts, list):
        return None
    out = []
    for st in sts:
        if not isinstance(st, dict):
            continue
        principals = []
        p = st.get("Principal")
        if p == "*":
            principals.append(("*", "*"))
        elif isinstance(p, dict):
            for kind, ids in p.items():
                principals.extend((kind, x) for x in aslist(ids))
        elif p is not None:
            principals.append((UNKNOWN, UNKNOWN))
        cond = st.get("Condition")
        conds = []
        if isinstance(cond, dict):
            for op, pairs in cond.items():
                if isinstance(pairs, dict):
                    conds.extend((op, key, aslist(vals)) for key, vals in pairs.items())
                else:
                    conds.append((op, UNKNOWN, [UNKNOWN]))
        elif cond is not None:
            conds.append((UNKNOWN, UNKNOWN, [UNKNOWN]))
        out.append({"effect": st.get("Effect"), "actions": aslist(st.get("Action")),
                    "not_action": "NotAction" in st, "resources": aslist(st.get("Resource")),
                    "principals": principals, "conditions": conds})
    return out


def doc_statements(view):
    """Statements of a data "aws_iam_policy_document" block."""
    out = []
    for st in view.blocks("statement"):
        effect = st.get("effect")
        principals = []
        for p in st.blocks("principals"):
            principals.extend((p.get("type"), x) for x in aslist(p.get("identifiers")))
        conds = [(c.get("test"), c.get("variable"), aslist(c.get("values")))
                 for c in st.blocks("condition")]
        out.append({"effect": "Allow" if effect is None else effect,
                    "actions": aslist(st.get("actions")),
                    "not_action": st.get("not_actions") is not None,
                    "resources": aslist(st.get("resources")),
                    "principals": principals, "conditions": conds})
    return out


def lower_strs(values):
    return {v.lower() for v in values if isinstance(v, str)}


# ---------------------------------------------------------------- the scan

class Scan:
    def __init__(self, root):
        self.root = root
        self.files, self.resources, self.modules, self.backends = [], [], [], []
        self.not_run, self.hits = [], []
        self.policy_docs = {}
        self.tf_dirs = {}

    def hit(self, rule, res, line, detail, severity=None, strong=False):
        self.hits.append({"rule": rule, "file": res.file, "line": line or res.line,
                          "address": res.address, "detail": detail,
                          "severity": severity or RULES[rule][1], "strong": strong})

    def add_resource(self, res, provider=None):
        self.resources.append({"address": res.address, "type": res.type,
                               "provider": provider or provider_of(res.type),
                               "file": res.file, "line": res.line})

    # --- shared checks

    def identity_policy(self, res, stmts, line):
        for st in stmts or []:
            if st["effect"] != "Allow" or st["not_action"]:
                continue
            acts = lower_strs(st["actions"])
            if "*" not in st["resources"]:
                continue
            if acts & {"*", "*:*"}:
                self.hit("AWS-IAM-001", res, line, "Allow Action * on Resource *")
            elif acts & {"iam:passrole", "iam:*", "iam:pass*"}:
                self.hit("AWS-IAM-002", res, line, "Allow iam:PassRole on Resource *")

    def trust_policy(self, res, stmts, line):
        for st in stmts or []:
            if st["effect"] != "Allow":
                continue
            if not st["conditions"] and any(k in ("*", "AWS") and x == "*" for k, x in st["principals"]):
                self.hit("AWS-IAM-003", res, line, "Principal * without a condition")
            gap = github_trust_gap(st)
            if gap:
                self.hit("AWS-IAM-004", res, line, gap)

    def resource_policy(self, res, stmts, line):
        for st in stmts or []:
            if st["effect"] == "Allow" and not st["conditions"] and \
                    any(k in ("*", "AWS") and x == "*" for k, x in st["principals"]):
                self.hit("AWS-S3-003", res, line, "Allow to Principal * without a condition")

    def ingress(self, res, line, cidrs, proto, lo, hi, rule="AWS-NET-001"):
        open_from = [c for c in cidrs if c in WORLD]
        if not open_from:
            return
        ports = sensitive_ports(proto, lo, hi)
        if ports:
            self.hit(rule, res, line, f"ingress from {open_from[0]} to {', '.join(ports[:5])}")

    def statements(self, res, attr, view=None):
        view = view or res.view
        value = view.get(attr)
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except ValueError:
                return None
        if isinstance(value, dict):
            return norm_statements(value)
        raw = view.raw(attr)
        if raw:
            m = DOC_REF.match(raw.strip())
            if m:
                return self.policy_docs.get((res.dir, m.group(1)))
        return None

    def gcp_iam(self, res, role, members, line):
        role_text = role if isinstance(role, str) else "a role"
        public = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
        if public:
            self.hit("GCP-IAM-001", res, line, f"{role_text} granted to {public[0]}")
        if role in ("roles/owner", "roles/editor"):
            self.hit("GCP-IAM-002", res, line, f"{role} granted")
        if role in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser") and \
                res.type.startswith(("google_project_iam_", "google_folder_iam_",
                                     "google_organization_iam_")):
            self.hit("GCP-IAM-004", res, line, f"{role} granted at {res.type.split('_')[1]} level")

    def firewall(self, res, line, direction, disabled, ranges, allows):
        if disabled is True or str(disabled).lower() == "true":
            return
        if direction not in (None, "INGRESS"):
            return
        open_from = [r for r in aslist(ranges) if r in WORLD]
        if not open_from:
            return
        for proto, ports in allows:
            if proto == "all":
                spans = [(0, 65535)]
            elif proto in ("tcp", "6"):
                if ports is None or ports == []:
                    spans = [(0, 65535)]
                else:
                    spans = [port_span(p) for p in aslist(ports)]
            else:
                continue
            found = []
            for span in spans:
                if span:
                    found += sensitive_ports("tcp", *span)
            if found:
                self.hit("GCP-NET-001", res, line,
                         f"ingress from {open_from[0]} to {', '.join(sorted(set(found))[:5])}")
                return


def port_span(value):
    if isinstance(value, int):
        return value, value
    if isinstance(value, str):
        m = re.fullmatch(r"\s*(\d+)\s*(?:-\s*(\d+))?\s*", value)
        if m:
            return int(m.group(1)), int(m.group(2) or m.group(1))
    return None


def sensitive_ports(proto, lo, hi):
    proto = str(to_int(proto)) if to_int(proto) is not None else proto
    if isinstance(proto, str):
        proto = proto.lower()
    if proto in ("-1", "all"):
        lo, hi = 0, 65535
    elif proto not in ("tcp", "6"):
        return []
    lo, hi = to_int(lo), to_int(hi)
    if lo is None or hi is None:
        return []
    return [f"{p}/{name}" for p, name in sorted(SENSITIVE_PORTS.items()) if lo <= p <= hi]


def github_trust_gap(st):
    if st["effect"] != "Allow":
        return None
    fed = any(k == "Federated" and isinstance(x, str) and "token.actions.githubusercontent.com" in x
              for k, x in st["principals"])
    keyed = any(isinstance(key, str) and "token.actions.githubusercontent.com" in key
                for _, key, _ in st["conditions"])
    if not (fed or keyed):
        return None
    subs = [vals for _, key, vals in st["conditions"]
            if isinstance(key, str) and key.lower().endswith(":sub")]
    if not subs:
        return "no :sub condition on the GitHub OIDC token"
    for vals in subs:
        for v in vals:
            if isinstance(v, str) and (v == "*" or v.startswith("repo:*")):
                return f"sub condition allows {v}"
    return None


# ---------------------------------------------------------------- Terraform rules

ADMIN_ARN = re.compile(r":policy/AdministratorAccess$")
GCP_IAM = re.compile(r"^google_\w+_iam_(member|binding)$")
DEFAULT_SA = re.compile(r"-compute@developer\.gserviceaccount\.com$")
SSL_MODES = ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")


def check_tf(scan, res):
    t, v = res.type, res.view
    if t == "aws_security_group":
        for rule in v.blocks("ingress"):
            scan.ingress(res, rule.line(), aslist(rule.get("cidr_blocks")) +
                         aslist(rule.get("ipv6_cidr_blocks")), rule.get("protocol"),
                         rule.get("from_port"), rule.get("to_port"))
    elif t == "aws_security_group_rule":
        if v.get("type") == "ingress":
            scan.ingress(res, res.line, aslist(v.get("cidr_blocks")) + aslist(v.get("ipv6_cidr_blocks")),
                         v.get("protocol"), v.get("from_port"), v.get("to_port"))
    elif t == "aws_vpc_security_group_ingress_rule":
        scan.ingress(res, res.line, [v.get("cidr_ipv4"), v.get("cidr_ipv6")], v.get("ip_protocol"),
                     v.get("from_port"), v.get("to_port"))
    elif t in ("aws_s3_bucket", "aws_s3_bucket_acl"):
        if v.get("acl") in ("public-read", "public-read-write", "authenticated-read"):
            scan.hit("AWS-S3-001", res, v.line("acl"), f"acl = {v.get('acl')}")
        if t == "aws_s3_bucket" and v.get("policy") is not None:
            scan.resource_policy(res, scan.statements(res, "policy"), v.line("policy"))
    elif t in ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"):
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls",
                 "restrict_public_buckets")
        off = [f for f in flags if v.get(f) is False or v.get(f) is None]
        if off:
            scan.hit("AWS-S3-002", res, res.line, "off: " + ", ".join(off))
    elif t == "aws_s3_bucket_policy":
        scan.resource_policy(res, scan.statements(res, "policy"), v.line("policy"))
    elif t in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
        scan.identity_policy(res, scan.statements(res, "policy"), v.line("policy"))
    elif t == "aws_iam_role":
        scan.trust_policy(res, scan.statements(res, "assume_role_policy"), v.line("assume_role_policy"))
        for inline in v.blocks("inline_policy"):
            scan.identity_policy(res, scan.statements(res, "policy", inline), inline.line())
        if any(isinstance(a, str) and ADMIN_ARN.search(a) for a in aslist(v.get("managed_policy_arns"))):
            scan.hit("AWS-IAM-001", res, v.line("managed_policy_arns"), "AdministratorAccess attached")
    elif t in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
               "aws_iam_group_policy_attachment", "aws_iam_policy_attachment"):
        arn = v.get("policy_arn")
        if isinstance(arn, str) and ADMIN_ARN.search(arn):
            scan.hit("AWS-IAM-001", res, v.line("policy_arn"), "AdministratorAccess attached")
    elif t == "aws_iam_access_key":
        scan.hit("AWS-IAM-005", res, res.line, "access key for an IAM user")
    elif t == "aws_iam_user_login_profile":
        scan.hit("AWS-IAM-005", res, res.line, "console password for an IAM user", "Low")
    elif t in ("aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance"):
        if v.get("publicly_accessible") is True:
            scan.hit("AWS-RDS-001", res, v.line("publicly_accessible"), "publicly_accessible = true")
        if t != "aws_rds_cluster_instance" and v.get("storage_encrypted") in (False, None) \
                and v.get("replicate_source_db") is None:
            scan.hit("AWS-RDS-002", res, v.line("storage_encrypted"), "storage_encrypted not true")
    elif t in ("aws_instance", "aws_launch_template"):
        opts = v.blocks("metadata_options")
        if not opts:
            scan.hit("AWS-EC2-001", res, res.line, "no metadata_options; IMDSv1 allowed")
        else:
            tokens = opts[0].get("http_tokens")
            if tokens is None or (isinstance(tokens, str) and tokens != "required"):
                scan.hit("AWS-EC2-001", res, opts[0].line("http_tokens"),
                         f"http_tokens = {tokens if tokens else 'unset'}")
    elif t == "aws_ebs_volume":
        if v.get("encrypted") in (False, None):
            scan.hit("AWS-EBS-001", res, res.line, "encrypted not true")
    elif t == "aws_lambda_function_url":
        if v.get("authorization_type") == "NONE":
            scan.hit("AWS-LAMBDA-001", res, v.line("authorization_type"), "authorization_type = NONE")
    elif t == "aws_lambda_permission":
        if v.get("principal") == "*" and all(v.get(k) is None for k in
                                             ("source_arn", "source_account", "principal_org_id")):
            scan.hit("AWS-LAMBDA-002", res, v.line("principal"), "principal = * without a source condition")
    elif t == "aws_cloudtrail":
        off = [k for k in ("is_multi_region_trail", "enable_log_file_validation")
               if v.get(k) in (False, None)]
        if off:
            scan.hit("AWS-CT-001", res, res.line, "not true: " + ", ".join(off))
    elif t == "aws_kms_key":
        spec = v.get("customer_master_key_spec") or v.get("key_spec")
        if spec in (None, "SYMMETRIC_DEFAULT") and v.get("enable_key_rotation") in (False, None):
            scan.hit("AWS-KMS-001", res, res.line, "enable_key_rotation not true")
    elif t == "aws_eks_cluster":
        for cfg in v.blocks("vpc_config"):
            public = cfg.get("endpoint_public_access")
            cidrs = cfg.get("public_access_cidrs")
            if public in (True, None) and (cidrs is None or
                                           (isinstance(cidrs, list) and "0.0.0.0/0" in cidrs)):
                scan.hit("AWS-EKS-001", res, cfg.line(), "public endpoint open to 0.0.0.0/0")
    elif t == "google_compute_firewall":
        allows = [(a.get("protocol"), a.get("ports")) for a in v.blocks("allow")]
        scan.firewall(res, res.line, v.get("direction"), v.get("disabled"), v.get("source_ranges"), allows)
    elif GCP_IAM.match(t):
        members = [v.get("member")] if v.get("member") is not None else aslist(v.get("members"))
        scan.gcp_iam(res, v.get("role"), members, v.line("role"))
    elif t == "google_iam_policy":
        for b in v.blocks("binding"):
            scan.gcp_iam(res, b.get("role"), aslist(b.get("members")), b.line())
    elif t == "google_service_account_key":
        scan.hit("GCP-IAM-003", res, res.line, "google_service_account_key resource")
    elif t == "google_storage_bucket":
        gaps = []
        if v.get("uniform_bucket_level_access") in (False, None):
            gaps.append("uniform_bucket_level_access not true")
        pap = v.get("public_access_prevention")
        if pap is None or (isinstance(pap, str) and pap != "enforced"):
            gaps.append("public_access_prevention not enforced")
        if gaps:
            scan.hit("GCP-GCS-001", res, res.line, "; ".join(gaps))
    elif t == "google_sql_database_instance":
        for settings in v.blocks("settings"):
            for ipc in settings.blocks("ip_configuration"):
                if any(n.get("value") in WORLD for n in ipc.blocks("authorized_networks")):
                    scan.hit("GCP-SQL-001", res, ipc.line(), "authorized network 0.0.0.0/0")
                if ipc.get("ipv4_enabled") is True and ipc.get("require_ssl") in (False, None) and \
                        (ipc.get("ssl_mode") is None or ipc.get("ssl_mode") not in (*SSL_MODES, UNKNOWN)):
                    scan.hit("GCP-SQL-001", res, ipc.line(), "public IP without required TLS", "Low")
    elif t in ("google_compute_instance", "google_compute_instance_template"):
        for sa in v.blocks("service_account"):
            email = sa.get("email")
            if email is None or (isinstance(email, str) and DEFAULT_SA.search(email)):
                scopes = lower_strs(aslist(sa.get("scopes")))
                full = any(s.endswith("cloud-platform") for s in scopes)
                scan.hit("GCP-GCE-001", res, sa.line(),
                         "default compute service account" + (" with cloud-platform scope" if full else ""))
        meta = v.get("metadata")
        if isinstance(meta, dict):
            gaps = []
            if str(meta.get("serial-port-enable")).lower() in ("true", "1"):
                gaps.append("serial-port-enable = true")
            if str(meta.get("block-project-ssh-keys")).lower() == "false":
                gaps.append("block-project-ssh-keys = false")
            if gaps:
                scan.hit("GCP-GCE-002", res, v.line("metadata"), "; ".join(gaps))
    elif t == "google_container_cluster":
        if v.get("enable_legacy_abac") is True:
            scan.hit("GCP-GKE-001", res, v.line("enable_legacy_abac"), "enable_legacy_abac = true", "High")
        private = v.blocks("private_cluster_config")
        private_endpoint = bool(private) and private[0].get("enable_private_endpoint") is True
        if not v.blocks("master_authorized_networks_config") and not private_endpoint:
            scan.hit("GCP-GKE-001", res, res.line, "no master authorized networks and no private endpoint")
        if not v.blocks("workload_identity_config"):
            scan.hit("GCP-GKE-001", res, res.line, "no workload_identity_config", "Low")
    elif t == "google_iam_workload_identity_pool_provider":
        if v.blocks("oidc") and v.get("attribute_condition") in (None, ""):
            scan.hit("GCP-WIF-001", res, res.line, "OIDC provider without attribute_condition")


# ---------------------------------------------------------------- file handlers

def find_line(text, pattern, default=1):
    m = re.search(pattern, text)
    return text.count("\n", 0, m.start()) + 1 if m else default


GIT_SOURCE = re.compile(r"^(git::|git@|github\.com/|bitbucket\.org/)|\.git(//|$|\?)")
REGISTRY_SOURCE = re.compile(r"^([A-Za-z0-9.-]+\.[a-z]+/)?[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$")
PROD_DIR = re.compile(r"(^|/)(prod|production|prd)(/|$)")


def handle_terraform(scan, parsed):
    """parsed: [(rel, blocks)]. Policy documents first, then rules."""
    for rel, blocks in parsed:
        d = str(Path(rel).parent)
        for b in blocks:
            if b.type == "data" and len(b.labels) == 2 and b.labels[0] == "aws_iam_policy_document":
                scan.policy_docs[(d, b.labels[1])] = doc_statements(HclView(b))
    for rel, blocks in parsed:
        d = str(Path(rel).parent)
        info = scan.tf_dirs.setdefault(d, {"resources": False, "backend": False, "file": rel})
        for b in blocks:
            view = HclView(b)
            if b.type == "resource" and len(b.labels) == 2:
                res = Res(b.labels[0], f"{b.labels[0]}.{b.labels[1]}", rel, b.line, view, d)
                scan.add_resource(res)
                info["resources"] = True
                check_tf(scan, res)
            elif b.type == "data" and len(b.labels) == 2 and b.labels[0] == "google_iam_policy":
                check_tf(scan, Res(b.labels[0], f"data.{b.labels[0]}.{b.labels[1]}", rel, b.line, view, d))
            elif b.type == "module" and b.labels:
                handle_module(scan, rel, b, view)
            elif b.type == "provider" and b.labels:
                for key in ("access_key", "secret_key"):
                    if key in b.attrs:
                        scan.hit("PS-003", Res("provider", f"provider.{b.labels[0]}", rel, b.line),
                                 view.line(key), f"{key} set in provider block")
                        break
            elif b.type == "terraform":
                for inner in b.blocks:
                    if inner.type == "cloud" or (inner.type == "backend" and inner.labels):
                        info["backend"] = True
                    if inner.type == "backend" and inner.labels:
                        handle_backend(scan, rel, inner)


def handle_module(scan, rel, b, view):
    source, version = view.get("source"), view.get("version")
    name = b.labels[0]
    scan.modules.append({"name": name, "source": source if isinstance(source, str) else "UNKNOWN",
                         "version": version if isinstance(version, str) else None,
                         "file": rel, "line": b.line})
    if not isinstance(source, str) or source.startswith(("./", "../")):
        return
    scan.not_run.append(f"remote module not read: module.{name} ({source}) at {rel}:{b.line}")
    res = Res("module", f"module.{name}", rel, b.line)
    if GIT_SOURCE.search(source):
        m = re.search(r"[?&]ref=([^&]+)", source)
        if not m:
            scan.hit("PS-001", res, view.line("source"), "git source without ?ref=")
        elif m.group(1) in ("main", "master", "HEAD", "develop", "trunk"):
            scan.hit("PS-001", res, view.line("source"), f"ref={m.group(1)} is a branch")
    elif REGISTRY_SOURCE.match(source) and version is None:
        scan.hit("PS-001", res, view.line("source"), "registry module without version")


def handle_backend(scan, rel, block):
    kind = block.labels[0]
    view = HclView(block)
    scan.backends.append({"type": kind, "file": rel, "line": block.line})
    res = Res("backend", f"terraform.backend.{kind}", rel, block.line)
    if kind == "s3" and view.get("encrypt") in (False, None) and view.get("kms_key_id") is None:
        scan.hit("PS-002", res, block.line, "s3 backend without encrypt = true")
    elif kind == "local" and PROD_DIR.search(rel):
        scan.hit("PS-002", res, block.line, "local state for a production directory", "Low")


def finish_dirs(scan):
    for d, info in sorted(scan.tf_dirs.items()):
        if info["resources"] and not info["backend"] and PROD_DIR.search(d + "/"):
            scan.hit("PS-002", Res("backend", "terraform.backend.local", info["file"], 1), 1,
                     "no backend in a production root module; state is local", "Low")


def handle_plan(scan, rel, text, doc):
    def walk(module):
        for r in module.get("resources", []) or []:
            if not isinstance(r, dict) or r.get("mode") == "data":
                continue
            address, type_ = r.get("address", ""), r.get("type", "")
            line = find_line(text, r'"address"\s*:\s*' + re.escape(json.dumps(address)))
            res = Res(type_, address, rel, line, DictView(r.get("values") or {}, line), rel)
            scan.add_resource(res)
            check_tf(scan, res)
        for child in module.get("child_modules", []) or []:
            if isinstance(child, dict):
                walk(child)
    root = (doc.get("planned_values") or {}).get("root_module") or {}
    walk(root)


def handle_cfn(scan, rel, text, doc):
    for lid, r in (doc.get("Resources") or {}).items():
        if not isinstance(r, dict):
            continue
        type_ = r.get("Type", "")
        props = r.get("Properties") or {}
        if not isinstance(props, dict):
            props = {}
        line = find_line(text, re.escape(json.dumps(lid)) + r"\s*:")
        res = Res(type_, f"cfn:{lid}", rel, line, DictView(props, line))
        scan.add_resource(res, "aws")
        if type_ == "AWS::EC2::SecurityGroup":
            for rule in aslist(props.get("SecurityGroupIngress")):
                if isinstance(rule, dict):
                    cfn_ingress(scan, res, rule)
        elif type_ == "AWS::EC2::SecurityGroupIngress":
            cfn_ingress(scan, res, props)
        elif type_ == "AWS::S3::Bucket":
            if props.get("AccessControl") in ("PublicRead", "PublicReadWrite", "AuthenticatedRead"):
                scan.hit("AWS-S3-001", res, line, f"AccessControl = {props['AccessControl']}")
            pab = props.get("PublicAccessBlockConfiguration")
            if isinstance(pab, dict):
                off = [k for k, val in pab.items() if val is False or val == "false"]
                if off:
                    scan.hit("AWS-S3-002", res, line, "off: " + ", ".join(off))
        elif type_ == "AWS::S3::BucketPolicy":
            scan.resource_policy(res, norm_statements(props.get("PolicyDocument")), line)
        elif type_ in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"):
            scan.identity_policy(res, norm_statements(props.get("PolicyDocument")), line)
        elif type_ == "AWS::IAM::Role":
            scan.trust_policy(res, norm_statements(props.get("AssumeRolePolicyDocument")), line)
            for p in aslist(props.get("Policies")):
                if isinstance(p, dict):
                    scan.identity_policy(res, norm_statements(p.get("PolicyDocument")), line)
            if any(isinstance(a, str) and ADMIN_ARN.search(a) for a in aslist(props.get("ManagedPolicyArns"))):
                scan.hit("AWS-IAM-001", res, line, "AdministratorAccess attached")
        elif type_ == "AWS::RDS::DBInstance":
            if props.get("PubliclyAccessible") in (True, "true"):
                scan.hit("AWS-RDS-001", res, line, "PubliclyAccessible = true")
            if props.get("StorageEncrypted") in (False, "false", None) and "SourceDBInstanceIdentifier" not in props:
                scan.hit("AWS-RDS-002", res, line, "StorageEncrypted not true")
        elif type_ == "AWS::Lambda::Url":
            if props.get("AuthType") == "NONE":
                scan.hit("AWS-LAMBDA-001", res, line, "AuthType = NONE")
        elif type_ == "AWS::Lambda::Permission":
            if props.get("Principal") == "*" and not ({"SourceArn", "SourceAccount", "PrincipalOrgID"} & props.keys()):
                scan.hit("AWS-LAMBDA-002", res, line, "Principal = * without a source condition")


def cfn_ingress(scan, res, rule):
    scan.ingress(res, res.line, [rule.get("CidrIp"), rule.get("CidrIpv6")], rule.get("IpProtocol"),
                 rule.get("FromPort"), rule.get("ToPort"))


def handle_snapshot(scan, rel, text, doc):
    if isinstance(doc, dict) and isinstance(doc.get("SecurityGroups"), list):
        for sg in doc["SecurityGroups"]:
            if not isinstance(sg, dict):
                continue
            gid = str(sg.get("GroupId", ""))
            line = find_line(text, r'"GroupId"\s*:\s*' + re.escape(json.dumps(gid)))
            res = Res("aws_security_group", f"snapshot:{gid}", rel, line)
            scan.add_resource(res, "aws")
            for perm in aslist(sg.get("IpPermissions")):
                if not isinstance(perm, dict):
                    continue
                cidrs = [r.get("CidrIp") for r in aslist(perm.get("IpRanges")) if isinstance(r, dict)]
                cidrs += [r.get("CidrIpv6") for r in aslist(perm.get("Ipv6Ranges")) if isinstance(r, dict)]
                scan.ingress(res, line, cidrs, perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
        return True
    if isinstance(doc, dict) and isinstance(doc.get("Policy"), str):
        try:
            doc = json.loads(doc["Policy"])
        except ValueError:
            return False
    if isinstance(doc, dict) and "Statement" in doc:
        res = Res("resource_policy", f"snapshot:{Path(rel).name}", rel, 1)
        scan.add_resource(res, "aws")
        scan.resource_policy(res, norm_statements(doc), find_line(text, r'"Statement"'))
        return True
    if isinstance(doc, dict) and isinstance(doc.get("bindings"), list):
        res = Res("google_project_iam_policy", f"snapshot:{Path(rel).name}", rel, 1)
        scan.add_resource(res, "gcp")
        for b in doc["bindings"]:
            if isinstance(b, dict) and isinstance(b.get("role"), str):
                line = find_line(text, r'"role"\s*:\s*' + re.escape(json.dumps(b["role"])))
                scan.gcp_iam(res, b["role"], aslist(b.get("members")), line)
        return True
    if isinstance(doc, list) and doc and all(isinstance(x, dict) for x in doc) \
            and any("sourceRanges" in x for x in doc):
        for fw in doc:
            name = str(fw.get("name", ""))
            line = find_line(text, r'"name"\s*:\s*' + re.escape(json.dumps(name)))
            res = Res("google_compute_firewall", f"snapshot:{name}", rel, line)
            scan.add_resource(res, "gcp")
            allows = [(a.get("IPProtocol"), a.get("ports")) for a in aslist(fw.get("allowed"))
                      if isinstance(a, dict)]
            scan.firewall(res, line, fw.get("direction"), fw.get("disabled"), fw.get("sourceRanges"), allows)
        return True
    return False


K8S_HOST = [(re.compile(r"^\s*-?\s*privileged:\s*true\b"), "privileged: true"),
            (re.compile(r"^\s*-?\s*hostNetwork:\s*true\b"), "hostNetwork: true"),
            (re.compile(r"^\s*-?\s*hostPID:\s*true\b"), "hostPID: true"),
            (re.compile(r"^\s*-?\s*hostIPC:\s*true\b"), "hostIPC: true"),
            (re.compile(r"^\s*-?\s*hostPath:"), "hostPath volume")]
K8S_BROAD = re.compile(r"^\s*-?\s*name:\s*[\"']?(cluster-admin|system:authenticated|system:unauthenticated|system:anonymous)[\"']?\s*$")


def handle_k8s(scan, rel, lines):
    docs, current, start = [], [], 1
    for n, line in enumerate(lines, 1):
        if line.startswith("---"):
            docs.append((start, current))
            current, start = [], n + 1
        else:
            current.append(line)
    docs.append((start, current))
    for start, body in docs:
        kind = name = None
        for line in body:
            m = re.match(r"^kind:\s*[\"']?([A-Za-z]+)", line)
            if m and not kind:
                kind = m.group(1)
        if not kind:
            continue
        in_meta = False
        for line in body:
            if re.match(r"^metadata:", line):
                in_meta = True
            elif in_meta and re.match(r"^\s+name:\s*(\S+)", line):
                name = re.match(r"^\s+name:\s*[\"']?([^\"'\s]+)", line).group(1)
                break
            elif in_meta and re.match(r"^\S", line):
                in_meta = False
        res = Res(kind, f"k8s:{kind}/{name or '?'}", rel, start)
        scan.add_resource(res, "kubernetes")
        seen = set()
        for offset, line in enumerate(body):
            lineno = start + offset
            if line.lstrip().startswith("#"):
                continue
            for pattern, label in K8S_HOST:
                if label not in seen and pattern.match(line):
                    seen.add(label)
                    scan.hit("K8S-001", res, lineno, label)
            if kind in ("ClusterRoleBinding", "RoleBinding"):
                m = K8S_BROAD.match(line)
                if m:
                    scan.hit("K8S-002", res, lineno, f"binds {m.group(1)}")
            if kind == "Secret" and re.match(r"^(data|stringData):\s*(\{\s*\S.*)?$", line):
                rest = line.split(":", 1)[1].strip()
                nxt = body[offset + 1] if offset + 1 < len(body) else ""
                if (rest and rest != "{}") or re.match(r"^\s+\S", nxt):
                    scan.hit("K8S-003", res, lineno, "Secret manifest with data")


def handle_cfn_yaml(scan, rel, lines):
    for n, line in enumerate(lines, 1):
        m = re.match(r"^(\s+)Type:\s*[\"']?(AWS::[A-Za-z0-9:]+)", line)
        if not m:
            continue
        lid = "?"
        for back in range(n - 2, -1, -1):
            pm = re.match(r"^(\s*)([A-Za-z0-9]+):\s*$", lines[back])
            if pm and len(pm.group(1)) < len(m.group(1)):
                lid = pm.group(2)
                break
        scan.add_resource(Res(m.group(2), f"cfn:{lid}", rel, n), "aws")
    scan.not_run.append(f"cloudformation yaml: rules not applied (no YAML parser): {rel}")


SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
]
GENERIC_SECRET = re.compile(
    r'^\s*"?([A-Za-z0-9_-]*(?:password|passwd|secret|secret_key|secret_string|token|api_key|apikey|'
    r'access_key|private_key))"?\s*=\s*"([^"]*)"', re.IGNORECASE)
PLACEHOLDER = re.compile(r"^(|<.*>|[xX*._-]+|todo|tbd|replace[_-]?me|arn:.*|projects/.*)$", re.IGNORECASE)


def scan_secrets(scan, rel, text, kind):
    res = Res("file", rel, rel, 1)
    lines = text.splitlines()
    for n, line in enumerate(lines, 1):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                scan.hit("SEC-001", res, n, label, strong=True)
        if kind in ("terraform", "tfvars"):
            m = GENERIC_SECRET.match(line)
            if m and "${" not in m.group(2) and not PLACEHOLDER.match(m.group(2).strip()):
                scan.hit("SEC-001", res, n, f"literal value assigned to {m.group(1)}")
    if re.search(r'"type"\s*:\s*"service_account"', text) and re.search(r'"private_key"\s*:', text):
        scan.hit("SEC-001", res, find_line(text, r'"private_key"\s*:'), "GCP service account key JSON",
                 strong=True)


# ---------------------------------------------------------------- walking

def classify_json(doc):
    if isinstance(doc, dict) and "planned_values" in doc:
        return "plan"
    if isinstance(doc, dict) and isinstance(doc.get("Resources"), dict) and (
            "AWSTemplateFormatVersion" in doc or any(
                isinstance(r, dict) and str(r.get("Type", "")).startswith("AWS::")
                for r in doc["Resources"].values())):
        return "cloudformation"
    return None


def walk(root, scan):
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        base = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            full = base / d
            if d in SKIP_DIRS:
                continue
            if full.is_symlink():
                scan.not_run.append(f"symlink skipped: {full.relative_to(root).as_posix()}")
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            full = base / f
            rel = full.relative_to(root).as_posix()
            if full.is_symlink():
                scan.not_run.append(f"symlink skipped: {rel}")
            elif full.is_file():
                entries.append((full, rel))
    return entries


def run(root):
    root = Path(root)
    scan = Scan(root)
    parsed = []
    for full, rel in walk(root, scan):
        name = full.name
        if name.endswith((".tfstate", ".tfstate.backup")):
            scan.files.append({"path": rel, "kind": "state"})
            scan.hit("SEC-002", Res("file", rel, rel, 1), 1, "state file in the repository", strong=True)
            continue
        if full.stat().st_size > MAX_BYTES:
            scan.not_run.append(f"file too large to scan: {rel}")
            continue
        data = full.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            scan.not_run.append(f"not UTF-8, skipped: {rel}")
            continue
        kind = None
        if name.endswith(".tf"):
            kind = "terraform"
            parsed.append((rel, parse_hcl(text)))
        elif name.endswith(".tfvars"):
            kind = "tfvars"
        elif name.endswith(".json"):
            try:
                doc = json.loads(text)
            except ValueError:
                doc = None
                if "planned_values" in text or "AWSTemplateFormatVersion" in text:
                    scan.not_run.append(f"invalid JSON skipped: {rel}")
            kind = classify_json(doc)
            if kind == "plan":
                handle_plan(scan, rel, text, doc)
            elif kind == "cloudformation":
                handle_cfn(scan, rel, text, doc)
            elif doc is not None and handle_snapshot(scan, rel, text, doc):
                kind = "snapshot"
        elif name.endswith((".yaml", ".yml")):
            lines = text.splitlines()
            if "AWSTemplateFormatVersion" in text or re.search(r"^\s+Type:\s*[\"']?AWS::", text, re.M):
                kind = "cloudformation-yaml"
                handle_cfn_yaml(scan, rel, lines)
            elif re.search(r"^apiVersion:", text, re.M) and re.search(r"^kind:", text, re.M):
                kind = "kubernetes"
                handle_k8s(scan, rel, lines)
        if kind:
            scan.files.append({"path": rel, "kind": kind})
        scan_secrets(scan, rel, text, kind)
    handle_terraform(scan, parsed)
    finish_dirs(scan)
    return scan


def build_findings(hits):
    groups = {}
    for h in hits:
        groups.setdefault((h["rule"], h["file"]), []).append(h)
    items = []
    for (rule, file), hs in groups.items():
        title, _, category, provider, controls, cwe = RULES[rule]
        hs.sort(key=lambda h: h["line"])
        details = list(dict.fromkeys(h["detail"] for h in hs))
        items.append({
            "title": title,
            "severity": min((h["severity"] for h in hs), key=SEV_RANK.get),
            "confidence": "Confirmed" if any(h["strong"] for h in hs) else "Suspected",
            "category": category, "provider": provider,
            "resources": sorted({h["address"] for h in hs}),
            "location": f"{file}:{hs[0]['line']}", "rule": rule,
            "controls": list(controls), "cwe": cwe, "detail": "; ".join(details)[:600],
            "validation": {"verdict": "Unverified", "evidence": ""},
        })
    items.sort(key=lambda f: (SEV_RANK[f["severity"]], f["location"].rsplit(":", 1)[0],
                              int(f["location"].rsplit(":", 1)[1]), f["rule"]))
    for n, f in enumerate(items, 1):
        f["id"] = f"I-{n:03d}"
    return [{"id": f.pop("id"), **f} for f in items]


def git_commit(root):
    try:
        out = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True,
                             text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def inventory_of(scan):
    by_provider = {}
    for r in scan.resources:
        by_provider[r["provider"]] = by_provider.get(r["provider"], 0) + 1
    return {"resources": len(scan.resources), "by_provider": dict(sorted(by_provider.items())),
            "files": len(scan.files), "not_run": list(scan.not_run)}


def report(scan, root, commit, findings):
    hits = [{k: v for k, v in h.items() if k != "strong"} for h in scan.hits]
    return {"tool": "iac_scan", "version": 1, "repo": str(Path(root).resolve()), "commit": commit,
            "files": scan.files, "resources": scan.resources, "modules": scan.modules,
            "backends": scan.backends, "not_run": scan.not_run, "hits": hits, "findings": findings}


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


EMPTY_RECORD = ("attack_paths", "findings", "perspectives", "checked_ok", "decisions",
                "limitations", "next_steps")


def merge_into(path, findings, inventory, commit):
    path = Path(path)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("findings.json must hold a JSON object")
    else:
        data = {"schema_version": 1, "meta": {}}
    data.setdefault("schema_version", 1)
    meta = data.setdefault("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("meta must be an object")
    for key in EMPTY_RECORD:
        data.setdefault(key, [])
    meta["commit"] = commit
    data["inventory"] = inventory
    kept = [f for f in data["findings"] if not (isinstance(f, dict) and str(f.get("id", "")).startswith("I-"))]
    data["findings"] = kept + findings
    atomic_write(path, data)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo")
    p.add_argument("--out", help="write the inventory here (default: stdout)")
    p.add_argument("--into", help="findings.json whose I-* findings are replaced")
    args = p.parse_args(argv)
    root = Path(args.repo)
    if not root.is_dir():
        print(f"iac_scan: {root} is not a readable directory", file=sys.stderr)
        return 2
    scan = run(root)
    commit = git_commit(root)
    findings = build_findings(scan.hits)
    result = report(scan, root, commit, findings)
    if args.into:
        try:
            merge_into(args.into, findings, inventory_of(scan), commit)
        except (OSError, ValueError) as e:
            print(f"iac_scan: cannot update {args.into}: {e}", file=sys.stderr)
            return 2
    if args.out:
        atomic_write(args.out, result)
    else:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEV_RANK}
    print(f"iac_scan: {len(scan.files)} files, {len(scan.resources)} resources, {len(findings)} findings "
          f"(High {counts['High']}, Medium {counts['Medium']}, Low {counts['Low']}); "
          f"{len(scan.not_run)} not run", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
