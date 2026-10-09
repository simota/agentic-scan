#!/usr/bin/env python3
"""Inventory infrastructure as code and apply deterministic baseline rules.

    python3 iac_scan.py REPO [--snapshots DIR ...] [--out iac.json] [--into findings.json]

Reads, never executes: Terraform/OpenTofu (`*.tf`, `*.tofu`), Terraform plan JSON
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

--snapshots adds a directory of exports the requester ran, kept outside the
repository; its files appear as `@snapshots/<dir>/...` and get no source
excerpts. Scan the repository and every export directory in one run: each run
replaces the whole baseline.
--out writes the inventory (`iac.json`); without it the inventory goes to stdout.
Neither --out nor --into may point inside REPO or through a symlink.
--into replaces every `I-*` finding in findings.json (creating it when absent),
keeps every other finding, and sets `meta.commit` and `inventory`. Attack-path
references, I-IDs in review evidence and I-* triage verdicts follow the same
(rule, file, resources) after renumbering. Lost references require fresh review
of the finding and its paths. Terraform JSON (`*.tf.json`) and unreadable,
binary or deeply nested inputs are listed in `not_run`.

Exit codes: 0 scanned (hits do not change it), 2 unreadable REPO or findings.json.
"""
import argparse
import bisect
import codecs
import copy
import fnmatch
import ipaddress
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import subprocess
import sys
import tempfile

from redaction import module_source, split_lines

SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv", "__pycache__"}
MAX_BYTES = 2 * 1024 * 1024
# terraform.tfstate, .tfstate.backup and the timestamped backups that
# `terraform state` subcommands write (terraform.tfstate.1700000000.backup).
STATE_FILE = re.compile(r"\.tfstate(\.[^/]*)?$")
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
    "AWS-S3-003": ("Resource policy allows any principal without a narrowing condition", "High",
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

IDENT = re.compile(r"[^\W\d][\w-]*")  # HCL identifiers are Unicode letters, digits, _ and -
HEREDOC = re.compile(r"<<(-?)([A-Za-z_][A-Za-z0-9_-]*)[ \t]*\r?\n")
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
        self.unknown_object_keys = False

    def parse(self):
        value = self.value()
        self.ws()
        return value if self.i >= len(self.s) else UNKNOWN

    def ws(self, newlines=True):
        self.i = skip_space(self.s, self.i, len(self.s), newlines)

    def value(self, multiline=False):
        self.ws()
        start = self.i
        v = self.primary(multiline)
        self.ws(newlines=multiline)
        if self.i < len(self.s) and self.s[self.i] not in self.SEP:
            self.skip_term(multiline)
            return UNKNOWN
        if self.i == start:
            self.skip_term(multiline)
            return UNKNOWN
        return v

    def primary(self, multiline=False):
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
        self.skip_term(multiline)
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
            # Tuple elements end at commas, not newlines. An unsupported
            # multiline expression must stay one UNKNOWN, including its branches.
            # Object attributes retain their separate newline-delimited context.
            out.append(self.value(multiline=True))
            self.ws()
            if self.i < len(s) and s[self.i] == ",":
                self.i += 1
            elif self.i == before:
                self.i += 1

    def obj(self):
        s, start = self.s, self.i
        self.i += 1
        out = {}
        unknown_keys = False
        while True:
            self.ws()
            if self.i >= len(s):
                return UNKNOWN
            if s[self.i] == "}":
                self.i += 1
                return UNKNOWN if unknown_keys else out
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
            else:
                # An unresolved key can also name a known entry in this map.
                # Dropping it would turn unknown restrictions into absent ones.
                unknown_keys = self.unknown_object_keys = True
            self.ws()
            if self.i < len(s) and s[self.i] == ",":
                self.i += 1

    def skip_term(self, multiline=False):
        s, i = self.s, self.i
        while i < len(s):
            c = s[i]
            if c in self.SEP and (c != "\n" or not multiline):
                break
            if c == "#" or s.startswith("//", i):
                if not multiline:
                    break
                i = line_end(s, i)
            elif s.startswith("/*", i):
                j = s.find("*/", i + 2)
                i = len(s) if j < 0 else j + 2
            elif c == '"':
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
    return _Lit(raw).parse()


# ---------------------------------------------------------------- views

class HclView:
    def __init__(self, block, on_unknown_key=None):
        self.block = block
        self.known_present = True
        self._cache = {}
        self.on_unknown_key = on_unknown_key

    def get(self, name):
        if name not in self.block.attrs:
            return None
        if name not in self._cache:
            parser = _Lit(self.block.attrs[name][0])
            self._cache[name] = parser.parse()
            if parser.unknown_object_keys and self.on_unknown_key is not None:
                self.on_unknown_key(self.line(name))
        return self._cache[name]

    def raw(self, name):
        attr = self.block.attrs.get(name)
        return attr[0] if attr else None

    def blocks(self, name):
        found = [HclView(b, self.on_unknown_key) for b in self.block.blocks if b.type == name]
        if not found and name in self.block.attrs:
            found = DictView.wrap(self.get(name), self.line(name))
        # A dynamic block may generate zero or more blocks. Do not mistake its
        # unevaluated presence for an omitted setting, or discard known static
        # blocks when both forms occur together.
        found.extend(DictView(UNKNOWN, b.line) for b in self.block.blocks
                     if b.type == "dynamic" and b.labels == [name])
        return found

    def line(self, name=None):
        if name and name in self.block.attrs:
            return self.block.attrs[name][1]
        return self.block.line


class DictView:
    def __init__(self, data, line):
        self.data, self._line = data, line
        # An unknown block may be absent after apply; unknown attributes in
        # an existing dictionary do not make the block's presence unknown.
        self.known_present = data is not UNKNOWN

    @staticmethod
    def wrap(value, line):
        if value is UNKNOWN or isinstance(value, dict):
            return [DictView(value, line)]
        if isinstance(value, list):
            return [DictView(v, line) for v in value if v is UNKNOWN or isinstance(v, dict)]
        return []

    def get(self, name):
        return UNKNOWN if self.data is UNKNOWN else self.data.get(name)

    def raw(self, name):
        return None

    def blocks(self, name):
        return self.wrap(self.get(name), self._line)

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


def contains_unknown(value):
    if value is UNKNOWN:
        return True
    if isinstance(value, dict):
        return any(contains_unknown(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(contains_unknown(v) for v in value)
    return False


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

# file("policy.json") or file("${path.module}/policy.json"), relative to the module.
FILE_REF = re.compile(r'^(?:file|templatefile)\(\s*"(?:\$\{path\.module\}/)?([^"$]+)"\s*[,)]')
DOC_REF = re.compile(r'^"?(?:\$\{\s*)?data\.aws_iam_policy_document\.([A-Za-z0-9_-]+)(?:\[[^\]]*\])?'
                     r'\.(?:minified_)?json'
                     r'\s*\}?"?$')


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
        if "NotPrincipal" in st:
            # Allow + NotPrincipal grants everyone except the named principals.
            principals.append(("*", "*"))
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
    # Composition can introduce statements or replace local ones by Sid. Until
    # that merge is evaluated, even literal local statements are not final.
    # Empty inputs are known no-ops; keep checking ordinary documents that use
    # the provider's empty defaults explicitly, including the legacy aliases.
    if any(view.get(name) not in (None, [], "") for name in (
            "source_policy_documents", "override_policy_documents", "source_json", "override_json")):
        return UNKNOWN
    out = []
    for st in view.blocks("statement"):
        effect = st.get("effect")
        principals = []
        for p in st.blocks("principals"):
            principals.extend((p.get("type"), x) for x in aslist(p.get("identifiers")))
        if st.blocks("not_principals"):
            principals.append(("*", "*"))  # everyone except the named principals
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


def matches_action(st, action):
    """Match known Action values using IAM's case-insensitive * and ? syntax."""
    if st["not_action"]:
        return UNKNOWN
    unknown = False
    for value in st["actions"]:
        if not isinstance(value, str) or "${" in value or "%{" in value:
            unknown = True
            continue
        # Escape bracket expressions: IAM only treats * and ? as wildcards.
        pattern = value.lower().replace("[", "[[]")
        if fnmatch.fnmatchcase(action.lower(), pattern):
            return True
    return UNKNOWN if unknown else False


# ---------------------------------------------------------------- the scan

class Scan:
    def __init__(self, root):
        self.root = root
        self.files, self.resources, self.modules, self.backends = [], [], [], []
        self.not_run, self.hits = [], []
        self.policy_docs = {}
        self.local_module_dirs = set()
        # Principal-less policy JSON files: {rel: [statements, referenced?]}
        self.policy_files = {}
        self.tf_dirs = {}

    def hit(self, rule, res, line, detail, severity=None, strong=False):
        line = line or res.line
        self.hits.append({"rule": rule, "file": getattr(line, "file", res.file), "line": int(line),
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
            elif matches_action(st, "iam:PassRole") is True:
                self.hit("AWS-IAM-002", res, line, "Allow iam:PassRole on Resource *")

    def trust_policy(self, res, stmts, line):
        source = getattr(line, "file", res.file)
        for st in stmts or []:
            if st["effect"] != "Allow":
                continue
            if not st["conditions"] and any(k in ("*", "AWS") and x == "*" for k, x in st["principals"]):
                allows_assume = matches_action(st, "sts:AssumeRole")
                if allows_assume is UNKNOWN:
                    self.not_run.append("AWS-IAM-003: unknown or unsupported trust policy actions; "
                                        f"check not run: {source}:{line} ({res.address})")
                elif allows_assume:
                    self.hit("AWS-IAM-003", res, line, "Principal * without a condition")
            gap = github_trust_gap(st)
            if gap is UNKNOWN:
                self.not_run.append("AWS-IAM-004: unknown or unsupported GitHub OIDC actions or conditions "
                                    f"at {source}:{line} ({res.address})")
            elif gap:
                self.hit("AWS-IAM-004", res, line, gap)

    def resource_policy(self, res, stmts, line):
        for st in stmts or []:
            if st["effect"] == "Allow" and not narrowing(st["conditions"]) and \
                    any(k in ("*", "AWS") and x == "*" for k, x in st["principals"]):
                self.hit("AWS-S3-003", res, line, "Allow to Principal * without a narrowing condition")

    def ingress(self, res, line, cidrs, proto, lo, hi, rule="AWS-NET-001"):
        open_from = world_cidrs(cidrs)
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
                statements = self.policy_docs.get((res.dir, m.group(1)))
                return None if statements is UNKNOWN else statements
            m = FILE_REF.match(raw.strip())
            if m:
                entry = self.policy_files.get(posixpath.normpath(posixpath.join(res.dir, m.group(1))))
                if entry:
                    entry[1] = True
                    return entry[0]
            if value is UNKNOWN:
                line = view.line(attr)
                self.not_run.append(f"policy document not resolved from the inputs; {attr} checks not run: "
                                    f"{getattr(line, 'file', res.file)}:{line} ({res.address})")
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
        if disabled is UNKNOWN or disabled is True or str(disabled).lower() == "true":
            return
        if direction not in (None, "INGRESS"):
            return
        open_from = world_cidrs(ranges)
        if not open_from:
            return
        for proto, ports in allows:
            if isinstance(proto, (str, int)) and not isinstance(proto, bool):
                proto = str(proto).lower()
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


# Condition keys that hold for any caller, so they do not narrow Principal "*".
# Unknown keys count as narrowing: precision over completeness.
OPEN_CONDITION_KEYS = {
    "aws:securetransport", "aws:currenttime", "aws:epochtime", "aws:requestedregion",
    "aws:referer", "aws:useragent", "aws:multifactorauthpresent", "s3:tlsversion",
    "s3:signatureversion", "s3:signatureage", "s3:authtype", "s3:x-amz-content-sha256",
    "s3:x-amz-server-side-encryption", "s3:x-amz-server-side-encryption-aws-kms-key-id",
    "s3:x-amz-acl", "s3:prefix", "s3:delimiter", "s3:max-keys",
}


def narrowing(conditions):
    return any(not isinstance(key, str) or key.lower() not in OPEN_CONDITION_KEYS
               for _, key, _ in conditions)


def world_cidrs(values):
    """Canonical /0 ranges only; unknown, invalid and narrower ranges are skipped."""
    out = []
    for value in aslist(values):
        if not isinstance(value, str):
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            out.append(str(network))
    return out


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


GITHUB_ISSUER = "token.actions.githubusercontent.com"
GITHUB_REPO_SUB = re.compile(r"^repo:[^/*?:]+/[^/*?:]+:")


def github_trust_gap(st):
    """Return a gap, no gap, or UNKNOWN when subject conditions need review.

    Values within one condition are ORed; different conditions are ANDed.
    A fixed positive subject condition therefore bounds the whole statement,
    even when another condition contains a broad pattern. Negation and more
    complex intersections are left for review rather than called public.
    """
    if st["effect"] != "Allow":
        return None
    allows_assume = matches_action(st, "sts:AssumeRoleWithWebIdentity")
    if allows_assume is False:
        return None
    fed = any(k == "Federated" and isinstance(x, str) and
              (x == GITHUB_ISSUER or x.endswith(":oidc-provider/" + GITHUB_ISSUER))
              for k, x in st["principals"])
    keyed = any(isinstance(key, str) and key.lower().startswith(GITHUB_ISSUER + ":")
                for _, key, _ in st["conditions"])
    if not fed:
        if keyed and contains_unknown(st["principals"]):
            return UNKNOWN
        return None
    subs, unsupported = [], allows_assume is UNKNOWN or contains_unknown(st["conditions"])
    for op, key, vals in st["conditions"]:
        if not isinstance(key, str):
            unsupported = True
        elif key.lower() == GITHUB_ISSUER + ":sub":
            subs.append((op, vals))
        elif key.lower() != GITHUB_ISSUER + ":aud":
            # Other claims can narrow an otherwise broad subject. Do not
            # pretend to evaluate their effect on the set of repositories.
            unsupported = True
    broad = 0
    for op, vals in subs:
        if not vals or not all(isinstance(v, str) and "${" not in v for v in vals):
            unsupported = True
        elif op in ("StringEquals", "StringEqualsIgnoreCase"):
            # These operators do not expand '*' or '?'. Even a wildcard-
            # shaped value is an exact subject, not an all-repository grant.
            return None
        elif op == "StringLike":
            if all(not any(c in v for c in "*?") or GITHUB_REPO_SUB.match(v) for v in vals):
                return None
            broad += 1
        else:
            unsupported = True
    if unsupported or broad > 1:
        return UNKNOWN
    if not subs:
        return "no :sub condition on the GitHub OIDC token"
    return "GitHub :sub pattern does not pin the organization and repository"


# ---------------------------------------------------------------- Terraform rules

ADMIN_ARN = re.compile(r"\Aarn:[a-z0-9-]+:iam::aws:policy/AdministratorAccess\Z")
GCP_IAM = re.compile(r"^google_\w+_iam_(member|binding)$")
GCP_IAM_POLICY = re.compile(r"^google_\w+_iam_policy$")
DEFAULT_SA = re.compile(r"-compute@developer\.gserviceaccount\.com$")
SSL_MODES = ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")


def tf_bool(value):
    """Convert only arguments known to expect a Terraform bool.

    Terraform coerces the strings "true" and "false" at a typed argument,
    not inside arbitrary strings or policy documents. Preserve omission and
    uncertainty separately so neither unknown nor invalid values use defaults.
    """
    if value is None or value is UNKNOWN or isinstance(value, bool):
        return value
    if isinstance(value, str):
        if value == "true":
            return True
        if value == "false":
            return False
    return UNKNOWN


def check_tf(scan, res):
    t, v = res.type, res.view
    if t in ("aws_security_group", "aws_default_security_group"):
        for rule in v.blocks("ingress"):
            scan.ingress(res, rule.line(), aslist(rule.get("cidr_blocks")) +
                         aslist(rule.get("ipv6_cidr_blocks")), rule.get("protocol"),
                         rule.get("from_port"), rule.get("to_port"))
    elif t == "aws_security_group_rule":
        if v.get("type") == "ingress":
            # The open range's own line: an override may set it in another file.
            line = v.line("cidr_blocks") if v.get("cidr_blocks") is not None else v.line("ipv6_cidr_blocks")
            scan.ingress(res, line, aslist(v.get("cidr_blocks")) + aslist(v.get("ipv6_cidr_blocks")),
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
        off = [f for f in flags if tf_bool(v.get(f)) in (False, None)]
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
        if tf_bool(v.get("publicly_accessible")) is True:
            scan.hit("AWS-RDS-001", res, v.line("publicly_accessible"), "publicly_accessible = true")
        # Replicas and restores inherit encryption from their source; Aurora
        # Serverless v1 clusters are always encrypted.
        inherited = any(v.get(k) not in (None, "") for k in (
            "replicate_source_db", "snapshot_identifier", "replication_source_identifier"))
        if t != "aws_rds_cluster_instance" and tf_bool(v.get("storage_encrypted")) in (False, None) \
                and not inherited and v.get("engine_mode") != "serverless":
            scan.hit("AWS-RDS-002", res, v.line("storage_encrypted"), "storage_encrypted not true")
    elif t in ("aws_instance", "aws_launch_template"):
        opts = v.blocks("metadata_options")
        if not opts and t == "aws_instance" and v.blocks("launch_template"):
            scan.not_run.append("AWS-EC2-001: metadata options come from a launch template; check the "
                                f"template: {res.file}:{res.line} ({res.address})")
        elif not opts:
            scan.hit("AWS-EC2-001", res, res.line, "no metadata_options; IMDSv1 allowed")
        else:
            endpoint = opts[0].get("http_endpoint")
            tokens = opts[0].get("http_tokens")
            if endpoint == "disabled":
                return
            if endpoint is UNKNOWN:
                if tokens != "required":
                    line = opts[0].line("http_endpoint")
                    scan.not_run.append("AWS-EC2-001: unknown metadata endpoint; check not run: "
                                        f"{getattr(line, 'file', res.file)}:{line} ({res.address})")
                return
            if tokens is None or (isinstance(tokens, str) and tokens != "required"):
                scan.hit("AWS-EC2-001", res, opts[0].line("http_tokens"),
                         f"http_tokens = {tokens if tokens else 'unset'}")
    elif t == "aws_ebs_volume":
        if tf_bool(v.get("encrypted")) in (False, None):
            scan.hit("AWS-EBS-001", res, v.line("encrypted"), "encrypted not true")
    elif t == "aws_lambda_function_url":
        if v.get("authorization_type") == "NONE":
            scan.hit("AWS-LAMBDA-001", res, v.line("authorization_type"), "authorization_type = NONE")
    elif t == "aws_lambda_permission":
        if v.get("principal") == "*" and all(v.get(k) in (None, "") for k in
                                             ("source_arn", "source_account", "principal_org_id")):
            scan.hit("AWS-LAMBDA-002", res, v.line("principal"), "principal = * without a source condition")
    elif t == "aws_cloudtrail":
        off = [k for k in ("is_multi_region_trail", "enable_log_file_validation")
               if tf_bool(v.get(k)) in (False, None)]
        if off:
            scan.hit("AWS-CT-001", res, res.line, "not true: " + ", ".join(off))
    elif t == "aws_kms_key":
        spec = v.get("customer_master_key_spec") or v.get("key_spec")
        # Keys in a custom key store (CloudHSM or external) cannot rotate automatically.
        custom_store = v.get("custom_key_store_id") not in (None, "") or v.get("xks_key_id") not in (None, "")
        if spec in (None, "SYMMETRIC_DEFAULT") and not custom_store and \
                tf_bool(v.get("enable_key_rotation")) in (False, None):
            scan.hit("AWS-KMS-001", res, res.line, "enable_key_rotation not true")
    elif t == "aws_eks_cluster":
        for cfg in v.blocks("vpc_config"):
            public = tf_bool(cfg.get("endpoint_public_access"))
            cidrs = cfg.get("public_access_cidrs")
            open_from = world_cidrs(["0.0.0.0/0"] if cidrs is None else cidrs)
            if public in (True, None) and open_from:
                scan.hit("AWS-EKS-001", res, cfg.line(), f"public endpoint open to {open_from[0]}")
    elif t == "google_compute_firewall":
        allows = [(a.get("protocol"), a.get("ports")) for a in v.blocks("allow")]
        scan.firewall(res, res.line, v.get("direction"), tf_bool(v.get("disabled")),
                      v.get("source_ranges"), allows)
    elif GCP_IAM.match(t):
        members = [v.get("member")] if v.get("member") is not None else aslist(v.get("members"))
        scan.gcp_iam(res, v.get("role"), members, v.line("role"))
    elif GCP_IAM_POLICY.match(t):
        data = v.get("policy_data")
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except ValueError:
                data = None
        if isinstance(data, dict) and isinstance(data.get("bindings"), list):
            for b in data["bindings"]:
                if isinstance(b, dict):
                    scan.gcp_iam(res, b.get("role"), aslist(b.get("members")), v.line("policy_data"))
    elif t == "google_iam_policy":
        for b in v.blocks("binding"):
            scan.gcp_iam(res, b.get("role"), aslist(b.get("members")), b.line())
    elif t == "google_service_account_key":
        scan.hit("GCP-IAM-003", res, res.line, "google_service_account_key resource")
    elif t == "google_storage_bucket":
        gaps = []
        if tf_bool(v.get("uniform_bucket_level_access")) in (False, None):
            gaps.append("uniform_bucket_level_access not true")
        pap = v.get("public_access_prevention")
        if pap is None or (isinstance(pap, str) and pap != "enforced"):
            gaps.append("public_access_prevention not enforced")
        if gaps:
            scan.hit("GCP-GCS-001", res, res.line, "; ".join(gaps))
    elif t == "google_sql_database_instance":
        for settings in v.blocks("settings"):
            if not settings.blocks("ip_configuration"):
                # Omitted ip_configuration: a public IPv4 address without required TLS.
                scan.hit("GCP-SQL-001", res, settings.line(), "public IP without required TLS (defaults)", "Low")
            for ipc in settings.blocks("ip_configuration"):
                open_from = world_cidrs([n.get("value") for n in ipc.blocks("authorized_networks")])
                if open_from:
                    scan.hit("GCP-SQL-001", res, ipc.line(), f"authorized network {open_from[0]}")
                ipv4_enabled = tf_bool(ipc.get("ipv4_enabled"))
                require_ssl = tf_bool(ipc.get("require_ssl"))
                # The provider defaults an omitted/null ipv4_enabled to true;
                # UNKNOWN must still remain distinct from that default.
                if ipv4_enabled in (True, None) and require_ssl in (False, None) and \
                        (ipc.get("ssl_mode") is None or ipc.get("ssl_mode") not in (*SSL_MODES, UNKNOWN)):
                    scan.hit("GCP-SQL-001", res, ipc.line(), "public IP without required TLS", "Low")
    elif t in ("google_compute_instance", "google_compute_instance_template"):
        for sa in v.blocks("service_account"):
            email = sa.get("email")
            if email is None or email == "default" or (isinstance(email, str) and DEFAULT_SA.search(email)):
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
        if tf_bool(v.get("enable_legacy_abac")) is True:
            scan.hit("GCP-GKE-001", res, v.line("enable_legacy_abac"), "enable_legacy_abac = true", "High")
        private = v.blocks("private_cluster_config")
        private_endpoint = tf_bool(private[0].get("enable_private_endpoint")) if private else None
        authorized = v.blocks("master_authorized_networks_config")
        if not authorized and private_endpoint in (False, None):
            scan.hit("GCP-GKE-001", res, res.line, "no master authorized networks and no private endpoint")
        elif private_endpoint in (False, None):
            open_from = world_cidrs([c.get("cidr_block") for cfg in authorized for c in cfg.blocks("cidr_blocks")])
            if open_from:
                scan.hit("GCP-GKE-001", res, authorized[0].line(), f"authorized networks include {open_from[0]}")
        if not v.blocks("workload_identity_config"):
            # Autopilot always enables Workload Identity. The default mode is
            # Standard, but an unresolved mode does not establish a gap.
            autopilot = tf_bool(v.get("enable_autopilot"))
            if autopilot in (False, None):
                scan.hit("GCP-GKE-001", res, res.line, "no workload_identity_config", "Low")
            elif autopilot is UNKNOWN:
                line = v.line("enable_autopilot")
                scan.not_run.append("GCP-GKE-001: unknown Autopilot mode; workload identity check not run: "
                                    f"{getattr(line, 'file', res.file)}:{line} ({res.address})")
    elif t == "google_iam_workload_identity_pool_provider":
        if any(oidc.known_present for oidc in v.blocks("oidc")) and \
                v.get("attribute_condition") in (None, ""):
            scan.hit("GCP-WIF-001", res, res.line, "OIDC provider without attribute_condition")


# ---------------------------------------------------------------- file handlers

def find_line(text, pattern, default=1):
    m = re.search(pattern, text)
    return text.count("\n", 0, m.start()) + 1 if m else default


GIT_SOURCE = re.compile(r"^(git::|git@|github\.com/|bitbucket\.org/)|\.git(//|$|\?)")
REGISTRY_SOURCE = re.compile(r"^([A-Za-z0-9.-]+(?:\.[a-z]+|:[0-9]+)/)?[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+"
                             r"(//[^?]+)?$")
PINNED_REF = re.compile(r"[0-9a-f]{7,40}|v?[0-9]+(?:\.[0-9]+)*(?:[-+.][0-9A-Za-z.-]+)?")
PROD_DIR = re.compile(r"(^|/)(prod|production|prd)([-_.][^/]*)?(/|$)", re.IGNORECASE)


class _HclLine(int):
    """A source line that keeps its file when an override inherits an argument."""
    def __new__(cls, line, file):
        result = super().__new__(cls, line)
        result.file = file
        return result


def _hcl_source(block, rel):
    block.line, block.end = _HclLine(block.line, rel), _HclLine(block.end, rel)
    block.attrs = {key: (raw, _HclLine(line, rel)) for key, (raw, line) in block.attrs.items()}
    for child in block.blocks:
        _hcl_source(child, rel)
    return block


def _merge_hcl_block(base, override):
    """Terraform's shallow override merge; dynamic blocks retain their uncertainty."""
    # The resource stays declared where its base block is; each argument
    # keeps its own file and line for hits.
    result = Block(base.type, base.labels, base.line, base.end)
    result.attrs = {**base.attrs, **override.attrs}

    def block_type(block):
        return block.labels[0] if block.type == "dynamic" and block.labels else block.type

    replaced = {block_type(block) for block in override.blocks}
    if base.type == "terraform" and replaced & {"backend", "cloud"}:
        replaced.update(("backend", "cloud"))
    result.blocks = [block for block in base.blocks if block_type(block) not in replaced]
    for block in override.blocks:
        previous = next((old for old in base.blocks if old.type == block.type), None)
        if previous and ((base.type == "resource" and block.type == "lifecycle") or
                         (base.type == "terraform" and block.type == "required_providers")):
            # Lifecycle arguments and provider requirements are the documented
            # exceptions; ordinary nested resource blocks are replaced in full.
            block = _merge_hcl_block(previous, block)
        result.blocks.append(block)
    return result


def terraform_overrides(scan, parsed):
    """Apply native .tf overrides per module before policy resolution and checks."""
    def is_override(rel):
        name = Path(rel).name
        return name in ("override.tf", "override.tofu") or name.endswith(("_override.tf", "_override.tofu"))

    def header(rel, block):
        alias = HclView(block).get("alias") if block.type == "provider" else None
        # A provider alias must be a literal string; invalid aliases must not
        # accidentally match a different provider configuration.
        if alias is not None and not isinstance(alias, str):
            alias = (rel, block.line)
        return str(Path(rel).parent), block.type, tuple(block.labels), alias

    overrides = [(rel, blocks) for rel, blocks in sorted(parsed) if is_override(rel)]
    if not overrides:
        return parsed, set()
    entries, positions, uncertain = [], {}, set()
    for rel, blocks in parsed:
        if is_override(rel):
            continue
        for block in blocks:
            _hcl_source(block, rel)
            positions.setdefault(header(rel, block), []).append(len(entries))
            entries.append((rel, block))
    for rel, blocks in overrides:
        for block in blocks:
            # These are the declarations consumed by the baseline. Locals,
            # variables and expressions remain unevaluated as before.
            if block.type not in ("resource", "data", "module", "provider", "terraform"):
                continue
            _hcl_source(block, rel)
            key = header(rel, block)
            address = ".".join(block.labels if block.type == "resource" else
                               [block.type, *block.labels])
            matches = positions.get(key, [])
            if not matches:
                if block.type == "terraform" or (block.type == "provider" and key[-1] is None):
                    positions[key] = [len(entries)]
                    entries.append((rel, block))
                else:
                    scan.not_run.append(f"Terraform override has no base declaration; checks not run: "
                                        f"{rel}:{block.line} ({address})")
                continue
            index = matches[0]
            base = entries[index][1]
            if len(matches) > 1 and block.type != "terraform":
                uncertain.add(base)
                scan.not_run.append(f"Terraform override has ambiguous base declarations; checks not run: "
                                    f"{rel}:{block.line} ({address})")
                for other in matches[1:]:
                    entries[other] = None
                positions[key] = [index]
                continue
            if base in uncertain:
                continue
            if block.type == "terraform":
                # Normal files may spread distinct terraform settings over
                # several blocks; an override backend replaces all prior ones.
                for other in matches[1:]:
                    old = entries[other][1]
                    base.attrs.update(old.attrs)
                    base.blocks.extend(old.blocks)
                    entries[other] = None
                positions[key] = [index]
            entries[index] = (entries[index][0], _merge_hcl_block(base, block))
    return [(entry[0], [entry[1]]) for entry in entries if entry is not None], uncertain


def handle_terraform(scan, parsed):
    """parsed: [(rel, blocks)]. Policy documents first, then rules."""
    # OpenTofu reads x.tofu instead of x.tf when both exist in one directory.
    present = {rel for rel, _ in parsed}
    shadowed = {rel for rel in present if rel.endswith(".tf") and rel[:-3] + ".tofu" in present}
    for rel in sorted(shadowed):
        scan.not_run.append(f"OpenTofu reads {rel[:-3]}.tofu instead; not evaluated: {rel}")
    parsed = [(rel, blocks) for rel, blocks in parsed if rel not in shadowed]
    parsed, uncertain = terraform_overrides(scan, parsed)

    def view_of(block, rel):
        def unknown_key(line):
            note = ("Terraform object has an unresolved key; affected checks not run: "
                    f"{getattr(line, 'file', rel)}:{line}")
            if note not in scan.not_run:
                scan.not_run.append(note)
        return DictView(UNKNOWN, block.line) if block in uncertain else HclView(block, unknown_key)

    for rel, blocks in parsed:
        d = str(Path(rel).parent)
        pending = list(reversed(blocks))
        while pending:
            block = pending.pop()
            if block.type == "dynamic":
                scan.not_run.append(f"Terraform dynamic block not evaluated; affected checks not run: "
                                    f"{getattr(block.line, 'file', rel)}:{block.line}")
            pending.extend(reversed(block.blocks))
        for b in blocks:
            if b.type == "data" and len(b.labels) == 2 and b.labels[0] == "aws_iam_policy_document":
                statements = doc_statements(view_of(b, rel))
                scan.policy_docs[(d, b.labels[1])] = statements
                if statements is UNKNOWN:
                    scan.not_run.append("IAM policy composition not evaluated; final document unknown: "
                                        f"data.aws_iam_policy_document.{b.labels[1]} at {rel}:{b.line}")
    for rel, blocks in parsed:
        d = str(Path(rel).parent)
        info = scan.tf_dirs.setdefault(d, {"resources": False, "backend": False, "file": rel})
        for b in blocks:
            view = view_of(b, rel)
            if b.type == "resource" and len(b.labels) == 2:
                res = Res(b.labels[0], f"{b.labels[0]}.{b.labels[1]}", rel, b.line, view, d)
                scan.add_resource(res)
                info["resources"] = True
                if b not in uncertain and not never_created(view):
                    check_tf(scan, res)
            elif b.type == "data" and len(b.labels) == 2 and b.labels[0] == "google_iam_policy":
                check_tf(scan, Res(b.labels[0], f"data.{b.labels[0]}.{b.labels[1]}", rel, b.line, view, d))
            elif b.type == "module" and b.labels:
                info["resources"] = True  # a root that only calls modules still holds state
                handle_module(scan, rel, b, view)
            elif b.type == "provider" and b.labels and b not in uncertain:
                for key in ("access_key", "secret_key", "token", "credentials", "access_token",
                            "client_secret", "client_certificate_password"):
                    # AWS keys in a provider block are flagged in any form, as before.
                    # Other providers often take short-lived tokens from data sources
                    # (kubernetes token = data.aws_eks_cluster_auth.x.token); flag only
                    # a literal value or a key file read from the repository.
                    if key in b.attrs and key not in ("access_key", "secret_key") and not (
                            isinstance(view.get(key), str) or b.attrs[key][0].lstrip().startswith("file(")):
                        continue
                    if key in b.attrs:
                        scan.hit("PS-003", Res("provider", f"provider.{b.labels[0]}", rel, b.line),
                                 view.line(key), f"{key} set in provider block")
                        break
            elif b.type == "terraform":
                for inner in b.blocks:
                    if inner.type == "cloud" or (inner.type == "backend" and inner.labels):
                        info["backend"] = True
                    if inner.type == "backend" and inner.labels:
                        handle_backend(scan, getattr(inner.line, "file", rel), inner)


def never_created(view):
    """A literal count = 0 or an empty literal for_each creates no instance."""
    count, for_each = view.get("count"), view.get("for_each")
    return to_int(count) == 0 if count is not None else for_each in ({}, [])


def handle_module(scan, rel, b, view):
    source, version = view.get("source"), view.get("version")
    name = b.labels[0]
    safe_source = module_source(source) if isinstance(source, str) else "UNKNOWN"
    scan.modules.append({"name": name, "source": safe_source,
                         "version": version if isinstance(version, str) else None,
                         "file": rel, "line": b.line})
    if isinstance(source, str) and source.startswith(("./", "../")):
        scan.local_module_dirs.add(posixpath.normpath(posixpath.join(str(Path(rel).parent), source.split("//")[0])))
    if not isinstance(source, str) or source.startswith(("./", "../")):
        return
    scan.not_run.append(f"remote module not read: module.{name} ({safe_source}) at {rel}:{b.line}")
    res = Res("module", f"module.{name}", rel, b.line)
    if GIT_SOURCE.search(source):
        m = re.search(r"[?&]ref=([^&]+)", source)
        if not m:
            scan.hit("PS-001", res, view.line("source"), "git source without ?ref=")
        elif not PINNED_REF.fullmatch(m.group(1)):
            # Only a commit or a version tag pins the code; anything else may be a branch.
            scan.hit("PS-001", res, view.line("source"), f"ref={m.group(1)} is not a commit or version tag")
    elif REGISTRY_SOURCE.match(source) and version is None:
        scan.hit("PS-001", res, view.line("source"), "registry module without version")


def handle_backend(scan, rel, block):
    kind = block.labels[0]
    view = HclView(block)
    scan.backends.append({"type": kind, "file": rel, "line": block.line})
    res = Res("backend", f"terraform.backend.{kind}", rel, block.line)
    if kind == "s3":
        encrypt, kms = tf_bool(view.get("encrypt")), view.get("kms_key_id")
        if encrypt is None and not block.attrs:
            # Partial configuration: settings come from -backend-config.
            scan.not_run.append("PS-002: s3 backend configured at init (-backend-config); "
                                f"check the backend config file: {rel}:{block.line}")
        elif encrypt is None and kms in (None, "") and backend_config_encrypts(scan, rel):
            pass
        elif encrypt is False or (encrypt is None and kms in (None, "")):
            scan.hit("PS-002", res, block.line, "s3 backend without encrypt = true")
    elif kind == "local" and PROD_DIR.search(rel):
        scan.hit("PS-002", res, block.line, "local state for a production directory", "Low")


def backend_config_encrypts(scan, rel):
    """A sibling *.tfbackend or backend*.hcl file that sets encrypt = true."""
    directory = Path(scan.root) / Path(rel).parent
    try:
        candidates = sorted(p for p in directory.iterdir()
                            if p.is_file() and not p.is_symlink() and
                            (p.name.endswith(".tfbackend") or re.fullmatch(r"backend.*\.hcl", p.name)))
        for path in candidates:
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                m = re.match(r'\s*encrypt\s*=\s*"?(true|false)"?\s*(?:#.*)?$', line)
                if m:
                    return m.group(1) == "true"
    except (OSError, UnicodeError):
        return False
    return False


def finish_dirs(scan):
    for d, info in sorted(scan.tf_dirs.items()):
        # A directory another module calls is a child module, not a root.
        if d in scan.local_module_dirs:
            continue
        if info["resources"] and not info["backend"] and PROD_DIR.search(d + "/"):
            scan.hit("PS-002", Res("backend", "terraform.backend.local", info["file"], 1), 1,
                     "no backend in a production root module; state is local", "Low")


def with_plan_unknowns(value, mask):
    """Restore values omitted from planned_values using change.after_unknown."""
    if mask is True:
        return UNKNOWN
    if not mask:
        return value
    if isinstance(mask, dict):
        out = dict(value) if isinstance(value, dict) else {}
        for key, child in mask.items():
            out[key] = with_plan_unknowns(out.get(key), child)
        return out
    if isinstance(mask, list):
        values = value if isinstance(value, list) else []
        return [with_plan_unknowns(values[i] if i < len(values) else None,
                                   mask[i] if i < len(mask) else False)
                for i in range(max(len(values), len(mask)))]
    return value


def handle_plan(scan, rel, text, doc):
    unknowns = {}
    changes = doc.get("resource_changes")
    for resource in changes if isinstance(changes, list) else []:
        if not isinstance(resource, dict) or not isinstance(resource.get("address"), str) \
                or "deposed" in resource:
            continue
        change = resource.get("change")
        if isinstance(change, dict):
            unknowns[resource["address"]] = change.get("after_unknown")

    # Map decoded addresses to lines once: Terraform escapes <, > and & and
    # writes non-ASCII raw, so re-encoding an address would not find it.
    lines = {}
    for m in re.finditer(r'"address"\s*:\s*("(?:\\.|[^"\\])*")', text):
        lines.setdefault(json.loads(m.group(1)), text.count("\n", 0, m.start()) + 1)

    def walk(module):
        if not isinstance(module, dict):
            return
        for r in module.get("resources", []) or []:
            if not isinstance(r, dict) or r.get("mode") == "data":
                continue
            address, type_ = r.get("address", ""), r.get("type", "")
            if not isinstance(address, str) or not isinstance(type_, str) or \
                    not isinstance(r.get("values") or {}, dict):
                scan.not_run.append(f"plan resource with an unexpected shape skipped: {rel}")
                continue
            line = lines.get(address, 1)
            values = with_plan_unknowns(r.get("values") or {}, unknowns.get(address))
            res = Res(type_, address, rel, line, DictView(values, line), rel)
            scan.add_resource(res)
            if contains_unknown(values):
                scan.not_run.append(f"plan contains unknown values; affected checks not run: "
                                    f"{address} at {rel}:{line}")
            check_tf(scan, res)
        children = module.get("child_modules")
        for child in children if isinstance(children, list) else []:
            walk(child)
    planned = doc.get("planned_values")
    walk(planned.get("root_module") if isinstance(planned, dict) else None)


JSON_TOKEN = re.compile(r'"(?:\\.|[^"\\])*"|[{}\[\],\n]')


def json_key_lines(text):
    """Map (path to the enclosing object, key) to the key's line in valid JSON.

    A path is the keys and list indexes from the root. Searching the whole
    text for a key would also match the same spelling in a value or in a
    different object (a Ref to a logical ID, a referenced security group).
    """
    out, stack, line, expect_key = {}, [], 1, False
    for m in JSON_TOKEN.finditer(text):
        token = m.group()
        if token == "\n":
            line += 1
        elif token[0] == '"':
            if stack and stack[-1][0] == "{" and expect_key:
                key = json.loads(token)
                stack[-1][1] = key
                out.setdefault((tuple(entry[1] for entry in stack[:-1]), key), line)
                expect_key = False
        elif token == "{":
            stack.append(["{", None])
            expect_key = True
        elif token == "[":
            stack.append(["[", 0])
        elif token in "}]":
            stack.pop()
        elif token == "," and stack:
            if stack[-1][0] == "{":
                expect_key = True
            else:
                stack[-1][1] += 1
    return out


def handle_cfn(scan, rel, text, doc):
    keys = json_key_lines(text)
    for lid, r in (doc.get("Resources") or {}).items():
        if not isinstance(r, dict):
            continue
        type_ = r.get("Type", "")
        props = r.get("Properties") or {}
        if not isinstance(props, dict):
            props = {}
        line = keys.get((("Resources",), lid), 1)
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
                # Omitted flags default to false, as in Terraform.
                off = [k for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls",
                                   "RestrictPublicBuckets") if pab.get(k) in (False, "false", None)]
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
        elif type_ in ("AWS::RDS::DBInstance", "AWS::RDS::DBCluster"):
            if props.get("PubliclyAccessible") in (True, "true"):
                scan.hit("AWS-RDS-001", res, line, "PubliclyAccessible = true")
            # Aurora instances take encryption from their cluster; replicas,
            # restores and Serverless v1 clusters from their source or engine.
            inherited = {"SourceDBInstanceIdentifier", "DBClusterIdentifier", "DBSnapshotIdentifier",
                         "SnapshotIdentifier", "SourceDBClusterIdentifier", "ReplicationSourceIdentifier",
                         "SourceDBInstanceAutomatedBackupsArn"} & props.keys()
            if type_ == "AWS::RDS::DBCluster":
                inherited = (inherited - {"DBClusterIdentifier"}) or props.get("EngineMode") == "serverless"
            if props.get("StorageEncrypted") in (False, "false", None) and not inherited:
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


def is_gcp_firewall_snapshot(value):
    if not isinstance(value, dict):
        return False
    if "kind" in value:
        return value["kind"] == "compute#firewall"
    # Concise snapshots may omit kind. Require firewall-specific selectors and
    # protocol entries so an unrelated sourceRanges field is not sufficient.
    selectors = ("sourceRanges", "sourceTags", "sourceServiceAccounts", "destinationRanges")
    return any(isinstance(value.get(key), list) for key in selectors) and any(
        isinstance(rule, dict) and isinstance(rule.get("IPProtocol"), str)
        for key in ("allowed", "denied") for rule in aslist(value.get(key)))


def handle_snapshot(scan, rel, text, doc):
    keys = json_key_lines(text)
    if isinstance(doc, dict) and isinstance(doc.get("SecurityGroups"), list):
        for index, sg in enumerate(doc["SecurityGroups"]):
            if not isinstance(sg, dict):
                continue
            gid = str(sg.get("GroupId", ""))
            line = keys.get((("SecurityGroups", index), "GroupId"), 1)
            res = Res("aws_security_group", f"snapshot:{gid}", rel, line)
            scan.add_resource(res, "aws")
            for perm in aslist(sg.get("IpPermissions")):
                if not isinstance(perm, dict):
                    continue
                cidrs = [r.get("CidrIp") for r in aslist(perm.get("IpRanges")) if isinstance(r, dict)]
                cidrs += [r.get("CidrIpv6") for r in aslist(perm.get("Ipv6Ranges")) if isinstance(r, dict)]
                scan.ingress(res, line, cidrs, perm.get("IpProtocol"), perm.get("FromPort"), perm.get("ToPort"))
        return "snapshot"
    if isinstance(doc, dict) and isinstance(doc.get("Policy"), str):
        try:
            doc = json.loads(doc["Policy"])
        except ValueError:
            return False
    if isinstance(doc, dict) and "Statement" in doc:
        statements = norm_statements(doc) or []
        raw = doc["Statement"] if isinstance(doc["Statement"], list) else [doc["Statement"]]
        line = keys.get(((), "Statement"), find_line(text, r'"Statement"'))
        if not any(st["principals"] for st in statements):
            # An identity policy, an SCP or a permissions boundary: the file
            # alone cannot say which. Terraform IAM policy resources that
            # read it with file() apply the identity rules at their own line.
            scan.policy_files[rel] = [statements, False]
            return "policy"
        # Trust policies name no Resource and grant an sts: action. A
        # resource policy's "Action": "*" is not a trust relationship.
        trust = not any(isinstance(st, dict) and ("Resource" in st or "NotResource" in st) for st in raw) \
            and any(st["effect"] == "Allow" and st["principals"] and any(
                isinstance(a, str) and a.lower().startswith("sts:assumerole") for a in st["actions"])
                for st in statements)
        if trust:
            res = Res("iam_trust_policy", f"policy:{Path(rel).name}", rel, line)
            scan.add_resource(res, "aws")
            scan.trust_policy(res, statements, line)
        else:
            res = Res("resource_policy", f"snapshot:{Path(rel).name}", rel, line)
            scan.add_resource(res, "aws")
            scan.resource_policy(res, statements, line)
        return "policy"
    if isinstance(doc, dict) and isinstance(doc.get("bindings"), list):
        res = Res("google_project_iam_policy", f"snapshot:{Path(rel).name}", rel, 1)
        scan.add_resource(res, "gcp")
        for index, b in enumerate(doc["bindings"]):
            if isinstance(b, dict) and isinstance(b.get("role"), str):
                line = keys.get((("bindings", index), "role"), 1)
                scan.gcp_iam(res, b["role"], aslist(b.get("members")), line)
        return "snapshot"
    if isinstance(doc, list) and doc and all(is_gcp_firewall_snapshot(x) for x in doc):
        for index, fw in enumerate(doc):
            name = str(fw.get("name", ""))
            line = keys.get(((index,), "name"), 1)
            res = Res("google_compute_firewall", f"snapshot:{name}", rel, line)
            scan.add_resource(res, "gcp")
            allows = [(a.get("IPProtocol"), a.get("ports")) for a in aslist(fw.get("allowed"))
                      if isinstance(a, dict)]
            scan.firewall(res, line, fw.get("direction"), fw.get("disabled"), fw.get("sourceRanges"), allows)
        return "snapshot"
    return False


class _YamlMap(dict):
    def __init__(self, line):
        super().__init__()
        self.line, self.lines = line, {}

    def put(self, key, value, line):
        if not isinstance(key, str) or key == "<<" or key in self:
            raise ValueError("complex, merge or duplicate mapping key")
        self[key], self.lines[key] = value, line


def _yaml_marks(text):
    """Unquoted characters with their flow nesting depth."""
    quote, depth, previous, i = None, 0, "", 0
    while i < len(text):
        c = text[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                if quote == "'" and text[i:i + 2] == "''":
                    i += 2
                    continue
                quote = None
        elif c in "\"'" and previous in ("", ":", "[", "{", ",", "-"):
            quote = c
        else:
            yield i, c, depth
            depth += (c in "[{") - (c in "]}")
        if not c.isspace():
            previous = c
        i += 1


def _yaml_comment(text):
    for i, c, _ in _yaml_marks(text):
        if c == "#" and (i == 0 or text[i - 1].isspace()):
            return text[:i].rstrip()
    return text.rstrip()


def _yaml_pair(text):
    for i, c, depth in _yaml_marks(text):
        if c == ":" and depth == 0 and (i + 1 == len(text) or text[i + 1].isspace()):
            return text[:i].strip(), text[i + 1:].strip()
    return None


class _YamlFlow:
    """Single-line flow collections and scalars; no YAML tags or references."""
    def __init__(self, text, line):
        self.text, self.line, self.i = text, line, 0

    def ws(self):
        while self.i < len(self.text) and self.text[self.i].isspace():
            self.i += 1

    def take(self, char):
        self.ws()
        if self.text[self.i:self.i + 1] == char:
            self.i += 1
            return True
        return False

    def value(self, flow=False, key=False):
        self.ws()
        start = self.i
        if start >= len(self.text):
            raise ValueError("multiline or incomplete scalar")
        c = self.text[start]
        if c in "\"'":
            self.i += 1
            while self.i < len(self.text):
                char = self.text[self.i]
                self.i += 1
                if char == "\\" and c == '"':
                    self.i += 1
                elif char == c:
                    if c == "'" and self.text[self.i:self.i + 1] == "'":
                        self.i += 1
                        continue
                    raw = self.text[start:self.i]
                    return json.loads(raw) if c == '"' else raw[1:-1].replace("''", "'")
            raise ValueError("multiline or incomplete quoted scalar")
        if c in "[{":
            self.i += 1
            close = "]" if c == "[" else "}"
            result = [] if c == "[" else _YamlMap(self.line)
            while not self.take(close):
                if c == "[":
                    result.append(self.value(flow=True))
                else:
                    self.ws()
                    quoted_key = self.text[self.i:self.i + 1] in ("'", '"')
                    name = self.value(flow=True, key=True)
                    if not self.take(":"):
                        raise ValueError("unsupported flow mapping key")
                    if not quoted_key and self.text[self.i:self.i + 1] \
                            and not self.text[self.i].isspace():
                        raise ValueError("ambiguous unquoted flow mapping key")
                    result.put(name, self.value(flow=True), self.line)
                if self.take(close):
                    return result
                if not self.take(","):
                    raise ValueError("multiline or malformed flow collection")
            return result
        while self.i < len(self.text) and not (
                (flow and self.text[self.i] in ",]}") or (key and self.text[self.i] == ":")):
            self.i += 1
        word = self.text[start:self.i].strip()
        if not word or word[0] in "&*!%@?|>" + chr(96) or re.search(r":\s", word):
            raise ValueError("unsupported YAML scalar, tag or reference")
        if key:
            return word
        # Kubernetes uses YAML 1.1 boolean spellings, including single-letter y/n.
        if word in ("y", "Y", "yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON"):
            return True
        if word in ("n", "N", "no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF"):
            return False
        if word.lower() in ("null", "~"):
            return None
        return word

    def parse(self):
        result = self.value()
        self.ws()
        if self.i != len(self.text):
            raise ValueError("unsupported trailing scalar content")
        return result


class _YamlSubset:
    """Kubernetes block maps/lists, single-line flow values and opaque block strings.

    Indentless lists, comments and quoted strings are supported. Anchors, aliases,
    tags, directives, complex/duplicate keys and multiline flow/quoted/plain
    scalars are rejected, so the caller records the document in not_run.
    """
    def __init__(self, rows):
        self.rows, self.i = rows, 0
        self.line = rows[0][0] if rows else 1

    def peek(self):
        while self.i < len(self.rows):
            n, raw = self.rows[self.i]
            self.line = n
            text = _yaml_comment(raw.lstrip(" "))
            if text and not text.startswith("#"):
                if text.startswith("\t"):
                    raise ValueError("tab indentation")
                return len(raw) - len(raw.lstrip(" ")), text, n
            self.i += 1
        return None

    @staticmethod
    def is_list(text):
        return text == "-" or text.startswith("- ")

    def entry(self, text, indent, line, indentless=True):
        if re.fullmatch(r"[|>](?:[+-][1-9]?|[1-9][+-]?)?", text):
            # Never interpret embedded manifests, scripts or configuration as YAML.
            while self.i < len(self.rows):
                raw = self.rows[self.i][1]
                if raw.strip() and len(raw) - len(raw.lstrip(" ")) <= indent:
                    break
                self.i += 1
            return UNKNOWN
        if text:
            return _YamlFlow(text, line).parse()
        nxt = self.peek()
        if nxt and (nxt[0] > indent or
                    (indentless and nxt[0] == indent and self.is_list(nxt[1]))):
            return self.block(nxt[0])
        return None

    def pair(self, result, text, indent, line):
        pair = _yaml_pair(text)
        if not pair:
            raise ValueError("unsupported mapping or multiline plain scalar")
        key, value = pair
        # Keys stay strings: a label named y, on or null is not a boolean or
        # None. A plain key may contain ':' (Fn::Sub, example.com/a:b).
        if key.strip()[:1] in ("'", '"', "[", "{"):
            name = _YamlFlow(key, line).parse()
        else:
            name = key.strip()
            if not name or name[0] in "&*!%@?|>" + chr(96) or re.search(r":\s", name):
                raise ValueError("unsupported YAML scalar, tag or reference")
        result.put(name, self.entry(value, indent, line), line)

    def mapping(self, indent, result):
        while (row := self.peek()) and row[0] == indent and not self.is_list(row[1]):
            self.i += 1
            self.pair(result, row[1], indent, row[2])
        return result

    def block(self, indent):
        row = self.peek()
        if not self.is_list(row[1]):
            if row[1].startswith(("{", "[")):
                self.i += 1
                return _YamlFlow(row[1], row[2]).parse()
            return self.mapping(indent, _YamlMap(row[2]))
        result = []
        while (row := self.peek()) and row[0] == indent and self.is_list(row[1]):
            self.i += 1
            text = row[1][1:].lstrip(" ")
            item_indent = indent + len(row[1]) - len(text)
            if _yaml_pair(text):
                value = _YamlMap(row[2])
                self.pair(value, text, item_indent, row[2])
                self.mapping(item_indent, value)
            else:
                value = self.entry(text, indent, row[2], indentless=False)
            result.append(value)
        return result

    def parse(self):
        row = self.peek()
        result = self.block(row[0]) if row else None
        if self.peek():
            raise ValueError("unsupported indentation or multiline value")
        return result


def _k8s_map(value, *keys):
    for key in keys:
        value = value.get(key) if isinstance(value, dict) else None
    return value if isinstance(value, _YamlMap) else _YamlMap(1)


def _check_k8s(scan, rel, doc, fallback_kind=None):
    kind = doc.get("kind", fallback_kind)
    if not isinstance(kind, str):
        scan.not_run.append(f"kubernetes rules not applied (missing or opaque kind): {rel}:{doc.line}")
        return
    if kind.endswith("List") and isinstance(doc.get("items"), list):
        for item in doc["items"]:
            if isinstance(item, _YamlMap):
                _check_k8s(scan, rel, item, kind[:-4] if kind != "List" else None)
        return
    meta = _k8s_map(doc, "metadata")
    name = meta.get("name")
    identity = name if isinstance(name, str) else "?"
    namespace = meta.get("namespace")
    if isinstance(namespace, str) and namespace:
        identity = f"{namespace}/{identity}"
    elif namespace is UNKNOWN:
        identity = f"?/{identity}"
    # An omitted namespace depends on the apply context. Keep the legacy
    # kind/name address instead of assuming 'default'; cluster-scoped objects
    # also have no namespace and retain that address form.
    res = Res(kind, f"k8s:{kind}/{identity}",
              rel, doc.lines.get("kind", doc.line))
    scan.add_resource(res, "kubernetes")
    # An opaque string in a rule-relevant identity needs manual review.
    relevant = [meta]
    if kind in ("ClusterRoleBinding", "RoleBinding"):
        role = _k8s_map(doc, "roleRef")
        subjects = [s for s in aslist(doc.get("subjects")) if isinstance(s, _YamlMap)]
        relevant += [role, *subjects]
        if role.get("kind") == "ClusterRole" and role.get("name") == "cluster-admin":
            scan.hit("K8S-002", res, role.lines["name"], "binds cluster-admin")
        for subject in subjects:
            if (subject.get("kind") == "Group" and subject.get("name") in
                    ("system:authenticated", "system:unauthenticated")) or (
                    subject.get("kind") == "User" and subject.get("name") == "system:anonymous"):
                scan.hit("K8S-002", res, subject.lines["name"], f"binds {subject['name']}")
    if namespace is UNKNOWN or any(m.get(k) is UNKNOWN for m in relevant for k in ("kind", "name")):
        scan.not_run.append(f"kubernetes opaque identity needs manual review: {rel}:{res.line}")
    if kind == "Secret":
        for key in ("data", "stringData"):
            if isinstance(doc.get(key), dict) and doc[key]:
                scan.hit("K8S-003", res, doc.lines[key], "Secret manifest with data")
    paths = {
        "Pod": ("spec",), "PodTemplate": ("template", "spec"),
        "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
        **{k: ("spec", "template", "spec") for k in (
            "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job")},
    }
    pod = _k8s_map(doc, *paths[kind]) if kind in paths else _YamlMap(res.line)
    hits = [(pod, k, f"{k}: true") for k in ("hostNetwork", "hostPID", "hostIPC")
            if pod.get(k) is True]
    for key in ("containers", "initContainers", "ephemeralContainers"):
        for container in aslist(pod.get(key)):
            security = _k8s_map(container, "securityContext")
            if security.get("privileged") is True:
                hits.append((security, "privileged", "privileged: true"))
    for volume in aslist(pod.get("volumes")):
        if isinstance(volume, _YamlMap) and isinstance(volume.get("hostPath"), dict):
            hits.append((volume, "hostPath", "hostPath volume"))
    seen = set()
    for mapping, key, label in hits:
        if label not in seen:
            seen.add(label)
            scan.hit("K8S-001", res, mapping.lines[key], label)


def _cfn_yaml_resources(rows, doc=None):
    """Only Resources.<logical ID>.Type is a resource declaration.

    Prefer parsed structure. The fallback reads block mapping headers when an
    intrinsic tag such as !Ref makes the YAML subset unavailable, and treats
    non-mapping values and their continuation lines as opaque.
    """
    def resource(lid, value):
        if isinstance(value, _YamlMap):
            type_ = value.get("Type")
            if isinstance(type_, str) and type_.startswith("AWS::"):
                yield lid, type_, value.lines["Type"]

    def resources(value):
        if isinstance(value, _YamlMap):
            for lid, entry in value.items():
                yield from resource(lid, entry)

    if isinstance(doc, _YamlMap):
        yield from resources(doc.get("Resources"))
        return
    parents, opaque_indent = [], None
    for line, raw in rows:
        indent = len(raw) - len(raw.lstrip(" "))
        text = _yaml_comment(raw.lstrip(" "))
        if not text:
            continue
        if opaque_indent is not None:
            if indent > opaque_indent:
                continue
            opaque_indent = None
        while parents and indent <= parents[-1][0]:
            parents.pop()
        pair = _yaml_pair(text)
        if not pair:
            opaque_indent = indent
            continue
        try:
            key = _YamlFlow(pair[0], line).parse()
        except (ValueError, RecursionError):
            opaque_indent = indent
            continue
        if not isinstance(key, str):
            opaque_indent = indent
            continue
        path = [name for _, name in parents] + [key]
        value = pair[1]
        if not value:
            parents.append((indent, key))
            continue
        try:
            parsed = _YamlFlow(value, line).parse()
        except (ValueError, RecursionError):
            parsed = UNKNOWN
        if path == ["Resources"]:
            yield from resources(parsed)
        elif len(path) == 2 and path[0] == "Resources":
            yield from resource(key, parsed)
        elif len(path) == 3 and path[0] == "Resources" and key == "Type" \
                and isinstance(parsed, str) and parsed.startswith("AWS::"):
            yield path[1], parsed, line
        # This includes block strings, multiline scalars and tagged values.
        # Nested text in them cannot introduce mapping headers or resources.
        opaque_indent = indent


def _yaml_kind(rows, doc):
    """Classify a document by its root keys, never by opaque string contents."""
    if isinstance(doc, _YamlMap):
        keys = doc.keys()
        cfn_resources = classify_json(doc) == "cloudformation"
    else:
        # Unsupported syntax still needs routing to not_run. Read only mapping
        # headers at the outermost indentation; do not interpret their values.
        headers, content = [], []
        for n, raw in rows:
            text = _yaml_comment(raw.lstrip(" "))
            content.append(text)
            pair = _yaml_pair(text)
            if pair:
                try:
                    key = _YamlFlow(pair[0], n).parse()
                except (ValueError, RecursionError):
                    continue
                if isinstance(key, str):
                    headers.append((len(raw) - len(raw.lstrip(" ")), key))
        indent = min((i for i, _ in headers), default=0)
        keys = {key for i, key in headers if i == indent}
        text = "\n".join(content)
        if re.match(r"(?:---\s+)?(?:(?:!\S*|&\S+)\s+)*\{", text.lstrip()):
            # Multiline flow values and tagged/anchored roots need manual review.
            keys.update(re.findall(r'(?:^|[,{])\s*["\']?(apiVersion|kind|Resources|'
                                   r'AWSTemplateFormatVersion)["\']?\s*:', text, re.M))
        cfn_resources = "Resources" in keys and next(_cfn_yaml_resources(rows), None) is not None
    if {"apiVersion", "kind"} <= keys:
        return "kubernetes"
    if "AWSTemplateFormatVersion" in keys or cfn_resources:
        return "cloudformation-yaml"
    return None


def handle_yaml(scan, rel, lines):
    docs, current = [], []
    for n, line in enumerate(lines, 1):
        if not current:
            # YAML permits a BOM at each document start, not only the file start.
            line = line.removeprefix("\ufeff")
        if re.fullmatch(r"(?:---|\.\.\.)(?:\s+#.*)?\s*", line):
            docs.append(current)
            current = []
        else:
            current.append((n, line))
    docs.append(current)
    kinds = set()
    for rows in docs:
        parser = _YamlSubset(rows)
        doc, reason = None, None
        try:
            doc = parser.parse()
        except (ValueError, RecursionError) as exc:
            reason = "nesting too deep" if isinstance(exc, RecursionError) else str(exc)
        kind = _yaml_kind(rows, doc)
        if not kind:
            continue
        kinds.add(kind)
        if kind == "cloudformation-yaml":
            handle_cfn_yaml(scan, rel, [line for _, line in rows], rows[0][0], doc)
            continue
        if reason:
            scan.not_run.append(f"kubernetes YAML rules not applied ({reason}): {rel}:{parser.line}")
            continue
        if isinstance(doc, _YamlMap):
            _check_k8s(scan, rel, doc)
        elif doc is not None:
            scan.not_run.append(f"kubernetes YAML rules not applied (expected a mapping): {rel}:{rows[0][0]}")
    return "mixed-yaml" if len(kinds) > 1 else next(iter(kinds), None)


def _json_as_yaml(value, keys, path=(), line=1):
    """Give parsed JSON the line-aware mappings the Kubernetes rules read."""
    if isinstance(value, dict):
        lines = {key: keys.get((path, key), line) for key in value}
        result = _YamlMap(min(lines.values(), default=line))
        for key, item in value.items():
            result.put(key, _json_as_yaml(item, keys, (*path, key), lines[key]), lines[key])
        return result
    if isinstance(value, list):
        return [_json_as_yaml(item, keys, (*path, n), line) for n, item in enumerate(value)]
    return value


def handle_k8s_json(scan, rel, text, doc):
    """Kubernetes manifests and `kubectl get -o json` exports written as JSON."""
    if not (isinstance(doc, dict) and isinstance(doc.get("apiVersion"), str)
            and isinstance(doc.get("kind"), str)):
        return False
    _check_k8s(scan, rel, _json_as_yaml(doc, json_key_lines(text)))
    return True


def handle_cfn_yaml(scan, rel, lines, start_line=1, doc=None):
    for lid, type_, line in _cfn_yaml_resources(list(enumerate(lines, start_line)), doc):
        scan.add_resource(Res(type_, f"cfn:{lid}", rel, line), "aws")
    note = f"cloudformation yaml: rules not applied (no YAML parser): {rel}"
    if note not in scan.not_run:
        scan.not_run.append(note)


SECRET_PATTERNS = [
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private key", re.compile(r"-{4,5} ?BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)? ?-{4,5}")),
    ("access token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|"
                                r"glpat-[A-Za-z0-9_-]{20}|xox[abeoprs]-[0-9]{6,}-[A-Za-z0-9-]+|"
                                r"AIza[0-9A-Za-z_-]{35})")),
]
GENERIC_SECRET = re.compile(
    r'^\s*"?([A-Za-z0-9_-]*(?:password|passwd|secret|secret_key|secret_string|token|api_key|apikey|'
    r'access_key|private_key))"?\s*=\s*"([^"]*)"', re.IGNORECASE)
PLACEHOLDER = re.compile(r"^(|<.*>|[xX*._-]+|todo|tbd|replace[_-]?me|arn:.*|projects/.*)$", re.IGNORECASE)


def scan_secrets(scan, rel, text, kind):
    res = Res("file", rel, rel, 1)
    lines = split_lines(text)
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


def walk(root, scan, prefix=""):
    entries = []

    def unreadable(error):
        where = Path(error.filename) if error.filename else root
        try:
            rel = where.relative_to(root).as_posix()
        except ValueError:
            rel = str(where)
        scan.not_run.append(f"unreadable directory, skipped: {prefix}{rel} ({error.strerror or error})")

    for dirpath, dirnames, filenames in os.walk(root, onerror=unreadable):
        base = Path(dirpath)
        keep = []
        for d in sorted(dirnames):
            full = base / d
            if d in SKIP_DIRS:
                continue
            if full.is_symlink():
                scan.not_run.append(f"symlink skipped: {prefix}{full.relative_to(root).as_posix()}")
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            full = base / f
            rel = prefix + full.relative_to(root).as_posix()
            if full.is_symlink():
                scan.not_run.append(f"symlink skipped: {rel}")
            elif full.is_file():
                entries.append((full, rel))
    return entries


INPUT_SUFFIXES = (".tf", ".tofu", ".tfvars", ".json", ".yaml", ".yml")
BOMS = ((codecs.BOM_UTF32_LE, "utf-32"), (codecs.BOM_UTF32_BE, "utf-32"),
        (codecs.BOM_UTF16_LE, "utf-16"), (codecs.BOM_UTF16_BE, "utf-16"))


def decode(data):
    """UTF-8 (with or without BOM), or UTF-16/32 with a BOM, as Windows shells write.

    Returns None for binary or undecodable data.
    """
    for bom, codec in BOMS:
        if data.startswith(bom):
            try:
                return data.decode(codec)
            except UnicodeDecodeError:
                return None
    if b"\0" in data:
        return None
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        return None


SNAPSHOT_PREFIX = "@snapshots/"


def snapshot_prefixes(dirs):
    """Label each export directory so its paths never collide with the repository's."""
    # Locations are path:line without spaces or colons; keep the label in that form.
    names = [re.sub(r"[\s:]+", "_", Path(d).resolve().name) or "root" for d in dirs]
    return [f"{SNAPSHOT_PREFIX}{name}/" if names.count(name) == 1 else f"{SNAPSHOT_PREFIX}{n}-{name}/"
            for n, name in enumerate(names, 1)]


def run(root, snapshots=()):
    root = Path(root)
    scan = Scan(root)
    parsed = []
    entries = walk(root, scan)
    for directory, prefix in zip(snapshots, snapshot_prefixes(snapshots)):
        entries += walk(Path(directory), scan, prefix)
    for full, rel in entries:
        name = full.name
        if STATE_FILE.search(name):
            scan.files.append({"path": rel, "kind": "state"})
            scan.hit("SEC-002", Res("file", rel, rel, 1), 1, "state file in the repository", strong=True)
            continue
        try:
            if full.stat().st_size > MAX_BYTES:
                scan.not_run.append(f"file too large to scan: {rel}")
                continue
            data = full.read_bytes()
        except OSError as e:
            scan.not_run.append(f"unreadable, skipped: {rel} ({e.strerror or e})")
            continue
        text = decode(data)
        if text is None:
            # Binary files are expected; an input the scanner would read is not.
            if b"\0" not in data:
                scan.not_run.append(f"not UTF-8, skipped: {rel}")
            elif name.lower().endswith(INPUT_SUFFIXES):
                scan.not_run.append(f"binary or not UTF-8, skipped: {rel}")
            continue
        kind = None
        if name.endswith(".tf.json") or name.endswith(".tofu.json"):
            scan.not_run.append(f"Terraform JSON syntax not evaluated; review by hand: {rel}")
        if name.endswith((".tf", ".tofu")):
            kind = "terraform"
            parsed.append((rel, parse_hcl(text)))
        elif name.endswith(".tfvars"):
            kind = "tfvars"
        elif name.endswith(".json"):
            try:
                doc = json.loads(text)
            except RecursionError:
                doc = None
                scan.not_run.append(f"JSON nested too deeply, skipped: {rel}")
            except ValueError:
                doc = None
                if "planned_values" in text or "AWSTemplateFormatVersion" in text:
                    scan.not_run.append(f"invalid JSON skipped: {rel}")
            kind = classify_json(doc)
            try:
                if kind == "plan":
                    handle_plan(scan, rel, text, doc)
                elif kind == "cloudformation":
                    handle_cfn(scan, rel, text, doc)
                elif doc is not None and handle_k8s_json(scan, rel, text, doc):
                    kind = "kubernetes"
                elif doc is not None:
                    kind = handle_snapshot(scan, rel, text, doc) or None
            except RecursionError:
                # json.loads accepts deeper nesting than the recursive rules.
                scan.not_run.append(f"JSON nested too deeply for the rules, skipped: {rel}")
        elif name.endswith((".yaml", ".yml")):
            kind = handle_yaml(scan, rel, split_lines(text))
        if kind:
            scan.files.append({"path": rel, "kind": kind})
        scan_secrets(scan, rel, text, kind)
    handle_terraform(scan, parsed)
    for rel, (_, referenced) in sorted(scan.policy_files.items()):
        if not referenced:
            scan.not_run.append("policy JSON without Principal is not read by a Terraform IAM policy "
                                f"resource (identity policy, SCP or boundary?); review by hand: {rel}")
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


def report(scan, root, commit, findings, snapshots=()):
    hits = [{k: v for k, v in h.items() if k != "strong"} for h in scan.hits]
    return {"tool": "iac_scan", "version": 1, "repo": str(Path(root).resolve()), "commit": commit,
            "snapshots": {prefix.rstrip("/"): str(Path(d).resolve())
                          for d, prefix in zip(snapshots, snapshot_prefixes(snapshots))},
            "files": scan.files, "resources": scan.resources, "modules": scan.modules,
            "backends": scan.backends, "not_run": scan.not_run, "hits": hits, "findings": findings}


def atomic_write(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        mode = stat.S_IMODE(path.stat().st_mode)
    except FileNotFoundError:
        umask = os.umask(0)
        os.umask(umask)
        mode = 0o666 & ~umask  # mkstemp would leave 0600
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        os.chmod(tmp, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


EMPTY_RECORD = ("attack_paths", "findings", "perspectives", "checked_ok", "decisions",
                "limitations", "next_steps")
# Match references in prose and Markdown labels, excluding words and filenames.
# URL ranges are protected separately, including their queries and fragments.
BASELINE_REFERENCE = re.compile(r"(?<![A-Za-z0-9_./-])I-[0-9]{3,}(?![A-Za-z0-9_/-]|\.[A-Za-z0-9])")
EVIDENCE_URL = re.compile(r"\b[A-Za-z][A-Za-z0-9+.-]*://[^\s<>`\"']+")


def evidence_url_spans(evidence):
    """Keep URL contents intact while allowing references after Markdown links."""
    cursor = 0
    while match := EVIDENCE_URL.search(evidence, cursor):
        depth, end = 0, match.end()
        for offset, char in enumerate(match.group()):
            if char == "(":
                depth += 1
            elif char == ")":
                if depth == 0:
                    end = match.start() + offset
                    break
                depth -= 1
        yield match.start(), end
        cursor = end


def baseline_key(finding):
    """The same root-cause grouping used by build_findings, independent of ID/line."""
    rule, location = finding.get("rule"), finding.get("location")
    if not isinstance(rule, str) or not rule or not isinstance(location, str) or ":" not in location:
        return None
    return rule, location.rsplit(":", 1)[0]


def remap_baseline_references(data, old, new):
    """Rebind path and review-evidence references before an I-ID can be reused."""
    old_by_id = {f["id"]: f for f in old}
    if len(old_by_id) != len(old):
        raise ValueError("existing baseline findings have duplicate IDs")
    new_by_key = {baseline_key(f): f for f in new if baseline_key(f) is not None}
    replacements = {}
    for fid, finding in old_by_id.items():
        replacement = new_by_key.get(baseline_key(finding))
        resources = finding.get("resources")
        # The same rule/file may now refer only to another resource. If any
        # previously affected resource vanished, its paths need fresh review.
        if replacement is not None and isinstance(resources, list) and resources \
                and all(isinstance(r, str) for r in resources) \
                and set(resources) <= set(replacement.get("resources", [])):
            replacements[fid] = replacement["id"]

    def removed_label(fid, evidence=False):
        key = baseline_key(old_by_id[fid]) if fid in old_by_id else None
        if key:
            label = f"{key[0]} at {key[1]}"
            if key in new_by_key:
                label += " (affected resources changed)"
            return label
        # Do not leave a live-looking I-ID in rewritten evidence: it could be
        # assigned to an unrelated hit on the next scan.
        return (f"unmatched baseline number {fid[2:]}" if evidence
                else f"unmatched baseline reference {fid}")

    def rewrite_carried(evidence):
        """Renumber I-IDs in carried I-* evidence in one pass, as for F-* below."""
        spans = list(evidence_url_spans(evidence))

        def replace(match):
            fid = match.group()
            if any(start <= match.start() < end for start, end in spans):
                return fid
            if fid in replacements:
                return replacements[fid]
            return f"[removed baseline: {removed_label(fid, evidence=True)}]"
        return BASELINE_REFERENCE.sub(replace, evidence)

    carry_triage(data, old_by_id, replacements, new, rewrite_carried)

    invalidated = set()
    invalidated_paths = {}
    for finding in data.get("findings", []):
        if not isinstance(finding, dict) or not str(finding.get("id", "")).startswith("F-"):
            continue
        validation = finding.get("validation")
        if not isinstance(validation, dict) or not isinstance(validation.get("evidence"), str):
            continue
        removed = []
        url_spans = list(evidence_url_spans(validation["evidence"]))

        def replace_reference(match):
            fid = match.group()
            if any(start <= match.start() < end for start, end in url_spans):
                return fid
            if fid in replacements:
                return replacements[fid]
            label = removed_label(fid, evidence=True)
            if label not in removed:
                removed.append(label)
            return f"[removed baseline: {label}]"

        # One regex pass is essential when I-001 -> I-002 and I-002 -> I-003:
        # a sequence of string replacements would move both to I-003.
        validation["evidence"] = BASELINE_REFERENCE.sub(replace_reference, validation["evidence"])
        if removed:
            note = "Baseline references removed by rescan: " + "; ".join(removed) + ". Recheck this finding."
            validation["evidence"] = validation["evidence"].rstrip() + "\n" + note
            validation["verdict"] = "Unverified"
            finding["confidence"] = "Suspected"
            invalidated.add(finding["id"])
            links = finding.get("attack_paths", [])
            if not isinstance(links, list) or not all(isinstance(aid, str) for aid in links):
                raise ValueError("finding attack-path references must be a list of strings")
            for aid in links:
                reason = f"supporting evidence for {finding['id']}"
                if reason not in invalidated_paths.setdefault(aid, []):
                    invalidated_paths[aid].append(reason)
            limitation = f"{finding['id']}: {note}"
            if limitation not in data["limitations"]:
                data["limitations"].append(limitation)

    for ap in data["attack_paths"]:
        if not isinstance(ap, dict) or not isinstance(ap.get("findings", []), list):
            raise ValueError("attack_paths must contain objects with finding-reference lists")
        refs = []
        removed = list(invalidated_paths.get(ap.get("id"), []))
        for fid in ap.get("findings", []):
            if not isinstance(fid, str):
                raise ValueError("attack-path finding references must be strings")
            if not fid.startswith("I-"):
                refs.append(fid)
                if fid in invalidated and f"supporting evidence for {fid}" not in removed:
                    removed.append(f"supporting evidence for {fid}")
            elif replacements.get(fid) is not None:
                refs.append(replacements[fid])
            else:
                removed.append(removed_label(fid))
        if "findings" in ap:
            ap["findings"] = refs
        if removed:
            note = "Baseline references removed by rescan: " + "; ".join(removed) + ". Recheck this attack path."
            previous = ap.get("note", "")
            if not isinstance(previous, str):
                raise ValueError("attack-path note must be a string")
            ap["status"] = "unknown"
            ap["note"] = (previous.rstrip() + "\n" + note).lstrip()
            limitation = f"{ap.get('id', 'Attack path')}: {note}"
            if limitation not in data["limitations"]:
                data["limitations"].append(limitation)


def unique_keys(pairs):
    """Refuse duplicate keys, as findings.py and render.py do; never echo the key."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def carry_triage(data, old_by_id, replacements, new, rewrite):
    """Keep a reviewer's I-* verdict when the same rule, file and resources survive.

    Triage lives only in I-*.validation; dropping it on every rescan would
    silently undo the review. A changed resource set needs fresh triage.
    """
    new_by_id = {f["id"]: f for f in new}
    for fid, new_id in replacements.items():
        old, current = old_by_id[fid], new_by_id[new_id]
        validation = old.get("validation")
        if not isinstance(validation, dict) or validation.get("verdict") in (None, "Unverified"):
            continue
        if set(old.get("resources", [])) == set(current.get("resources", [])):
            current["validation"] = copy.deepcopy(validation)
            if isinstance(validation.get("evidence"), str):
                current["validation"]["evidence"] = rewrite(validation["evidence"])
        else:
            note = (f"{new_id} (was {fid}): {validation['verdict']} triage not carried over; "
                    "affected resources changed. Recheck this baseline finding.")
            if note not in data["limitations"]:
                data["limitations"].append(note)


def merge_into(path, findings, inventory, commit):
    path = Path(path)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_keys)
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
    for key in ("findings", "attack_paths", "limitations"):
        if not isinstance(data[key], list):
            raise ValueError(f"{key} must be a list")
    meta["commit"] = commit
    data["inventory"] = inventory
    old = [f for f in data["findings"] if isinstance(f, dict) and str(f.get("id", "")).startswith("I-")]
    kept = [f for f in data["findings"] if not (isinstance(f, dict) and str(f.get("id", "")).startswith("I-"))]
    remap_baseline_references(data, old, findings)
    data["findings"] = kept + findings
    atomic_write(path, data)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("repo")
    p.add_argument("--out", help="write the inventory here (default: stdout)")
    p.add_argument("--into", help="findings.json whose I-* findings are replaced")
    p.add_argument("--snapshots", action="append", default=[], metavar="DIR",
                   help="directory of read-only exports the requester ran, outside the repository; "
                        "its files are reported as @snapshots/<dir>/... (repeatable)")
    args = p.parse_args(argv)
    root = Path(args.repo)
    try:
        readable = root.is_dir() and os.access(root, os.R_OK | os.X_OK)
    except OSError:
        readable = False
    if not readable:
        print(f"iac_scan: {root} is not a readable directory", file=sys.stderr)
        return 2
    resolved = root.resolve()
    for directory in args.snapshots:
        if not Path(directory).is_dir():
            print(f"iac_scan: --snapshots {directory} is not a readable directory", file=sys.stderr)
            return 2
        snap = Path(directory).resolve()
        if snap == resolved or resolved in snap.parents or snap in resolved.parents:
            print(f"iac_scan: --snapshots {directory} overlaps the repository; keep exports outside it",
                  file=sys.stderr)
            return 2
    for option, target in (("--out", args.out), ("--into", args.into)):
        if target is None:
            continue
        target = Path(target)
        if target.is_symlink():
            print(f"iac_scan: {option} {target} is a symlink; refusing to write through it", file=sys.stderr)
            return 2
        # The assessment writes nothing inside the repository it reads, and
        # a previous iac.json there would be rescanned as input.
        if resolved in target.resolve().parents:
            print(f"iac_scan: {option} {target} is inside the scanned repository; write it elsewhere",
                  file=sys.stderr)
            return 2
    scan = run(root, args.snapshots)
    commit = git_commit(root)
    findings = build_findings(scan.hits)
    result = report(scan, root, commit, findings, args.snapshots)
    # Write the inventory first: a failed --out must not leave findings.json
    # describing a scan whose inventory was never saved.
    if args.out:
        try:
            atomic_write(args.out, result)
        except OSError as e:
            print(f"iac_scan: cannot write {args.out}: {e.strerror or e}", file=sys.stderr)
            return 2
    else:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    if args.into:
        try:
            merge_into(args.into, findings, inventory_of(scan), commit)
        except (OSError, ValueError, RecursionError) as e:
            print(f"iac_scan: cannot update {args.into}: {e}", file=sys.stderr)
            return 2
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEV_RANK}
    print(f"iac_scan: {len(scan.files)} files, {len(scan.resources)} resources, {len(findings)} findings "
          f"(High {counts['High']}, Medium {counts['Medium']}, Low {counts['Low']}); "
          f"{len(scan.not_run)} not run", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
