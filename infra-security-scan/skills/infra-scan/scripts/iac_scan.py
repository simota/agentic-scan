#!/usr/bin/env python3
"""Inventory infrastructure as code and apply deterministic baseline rules.

    python3 iac_scan.py REPO [--snapshots DIR ...] [--out iac.json] [--into findings.json]

Reads, never executes: Terraform/OpenTofu (`*.tf`, `*.tofu`, `*.tfvars[.json]`),
Terraform plan JSON (`terraform show -json` output the requester produced),
CloudFormation and SAM templates (JSON, YAML, `.template`), `terragrunt.hcl`,
Kubernetes manifests and read-only config snapshots (AWS
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
of the finding and its paths. Inputs read only in part or not at all (Terraform
JSON, Kustomize, Helm templates, Serverless, Pulumi, other HCL, export shapes
without rules) and unreadable, binary or deeply nested inputs are listed in
`not_run`.

Exit codes: 0 scanned (hits do not change it); 2 unreadable REPO, --snapshots
directory or findings.json, a --snapshots directory overlapping REPO, or an
--out/--into path inside REPO, through a symlink or not writable.
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
import subprocess
import sys
from urllib.parse import unquote as url_unquote

# Run with python -I (isolated mode), the script's own directory is not on the path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import (BASELINE_REFERENCE, CARRY_NOTE, MAX_JSON_DEPTH, RECORD_LISTS, SEV_RANK, STATE_FILE,
                    has_symlink_parent, inventory, json_depth, meta_prose, shape_problems, split_yaml_documents,
                    sub_references, unique_object, write_json_atomic)
from redaction import CREDENTIAL, CREDENTIAL_SHAPES, KEY_BEGIN, module_source, split_lines

# Tool caches hold copies of the configuration (downloaded modules, the
# Terragrunt and SAM build copies); scanning them would duplicate findings.
# Serverless Framework's .serverless/ is kept: its compiled CloudFormation is
# the only form of serverless.yml the rules can read.
SKIP_DIRS = {".git", ".terraform", "node_modules", ".venv", "__pycache__", ".terragrunt-cache", ".aws-sam"}
QUIET_SKIPS = {".git", "__pycache__", ".venv"}
MAX_BYTES = 2 * 1024 * 1024
# Plan JSON and cloud exports are machine-written and routinely larger.
MAX_JSON_BYTES = 64 * 1024 * 1024
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
    "AWS-RDS-001": ("Database or data service is publicly accessible", "High", "Network exposure", "aws",
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
    "AWS-SNAP-001": ("Machine image or database snapshot shared publicly", "High", "Data protection", "aws",
                     ["AWS Foundational Security Best Practices — RDS snapshots are private"], "CWE-200"),
    "AWS-CF-001": ("CloudFront serves viewers over plaintext HTTP or outdated TLS", "Medium",
                   "Network exposure", "aws",
                   ["AWS Foundational Security Best Practices — CloudFront requires encryption in transit"],
                   "CWE-319"),
    "GCP-GCS-002": ("Bucket, object or dataset ACL grants public access", "High", "Data protection", "gcp",
                    ["CIS GCP Foundation — Cloud Storage buckets are not publicly accessible"], "CWE-200"),
}
# Resource types whose policy argument is a resource policy (AWS-S3-003).
RESOURCE_POLICY_ATTRS = {
    "aws_sqs_queue_policy": "policy", "aws_sqs_queue": "policy", "aws_sns_topic_policy": "policy",
    "aws_sns_topic": "policy", "aws_ecr_repository_policy": "policy", "aws_secretsmanager_secret_policy": "policy",
    "aws_secretsmanager_secret": "policy", "aws_kms_key": "policy", "aws_kms_key_policy": "policy",
    "aws_opensearch_domain_policy": "access_policies",
    "aws_elasticsearch_domain_policy": "access_policies", "aws_opensearch_domain": "access_policies",
    "aws_elasticsearch_domain": "access_policies", "aws_glacier_vault": "access_policy",
}
CFN_RESOURCE_POLICIES = {
    "AWS::SQS::QueuePolicy": "PolicyDocument", "AWS::SNS::TopicPolicy": "PolicyDocument",
    "AWS::ECR::Repository": "RepositoryPolicyText", "AWS::SecretsManager::ResourcePolicy": "ResourcePolicy",
    "AWS::KMS::Key": "KeyPolicy", "AWS::OpenSearchService::Domain": "AccessPolicies",
    "AWS::Elasticsearch::Domain": "AccessPolicies",
}
PUBLIC_DATA_SERVICES = ("aws_redshift_cluster", "aws_redshiftserverless_workgroup",
                        "aws_dms_replication_instance", "aws_mq_broker")
CFN_PUBLIC_DATA = ("AWS::Redshift::Cluster", "AWS::DMS::ReplicationInstance", "AWS::AmazonMQ::Broker",
                   "AWS::RedshiftServerless::Workgroup")
OLD_TLS = ("SSLv3", "TLSv1", "TLSv1_2016", "TLSv1.1_2016")
PUBLIC_GCS_ACL = ("publicRead", "publicReadWrite", "authenticatedRead")


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


# Real configuration nests a few blocks deep; each level rescans its body, so
# deeper input would cost depth x size time.
MAX_HCL_DEPTH = 64


def parse_body(t, start, end, line_of, depth=0):
    if depth > MAX_HCL_DEPTH:
        raise RecursionError("HCL blocks nested deeper than %d" % MAX_HCL_DEPTH)
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
            block.attrs, block.blocks = parse_body(t, j + 1, close - 1, line_of, depth + 1)
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

    def value(self, multiline=False, depth=0):
        if depth > MAX_HCL_DEPTH:
            raise RecursionError("HCL expression nested deeper than %d" % MAX_HCL_DEPTH)
        self.ws()
        start = self.i
        v = self.primary(multiline, depth)
        self.ws(newlines=multiline)
        if self.i < len(self.s) and self.s[self.i] not in self.SEP:
            self.skip_term(multiline)
            return UNKNOWN
        if self.i == start:
            self.skip_term(multiline)
            return UNKNOWN
        return v

    def primary(self, multiline=False, depth=0):
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
            return self.seq(depth + 1)
        if c == "{":
            return self.obj(depth + 1)
        m = NUMBER.match(s, i)
        if m:
            self.i = m.end()
            text = m.group()
            try:
                return int(text) if re.fullmatch(r"-?\d+", text) else float(text)
            except (ValueError, OverflowError):
                return UNKNOWN
        m = IDENT.match(s, i)
        if m:
            word, after = m.group(), m.end()
            nxt = s[after:after + 1]
            if word in ("true", "false", "null") and nxt not in (".", "(", "["):
                self.i = after
                return {"true": True, "false": False, "null": None}[word]
            if word in ("jsonencode", "tolist", "toset") and nxt == "(":
                self.i = after + 1
                v = self.value(depth=depth + 1)
                self.ws()
                if self.i < len(s) and s[self.i] == ")":
                    self.i += 1
                    return v
                self.i = skip_balanced(s, after)
                return UNKNOWN
        self.skip_term(multiline)
        return UNKNOWN

    def seq(self, depth=0):
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
            if re.match(r"for\s", s[self.i:self.i + 4]):
                self.i = skip_balanced(s, start)
                return UNKNOWN
            before = self.i
            # Tuple elements end at commas, not newlines. An unsupported
            # multiline expression must stay one UNKNOWN, including its branches.
            # Object attributes retain their separate newline-delimited context.
            out.append(self.value(multiline=True, depth=depth))
            self.ws()
            if self.i < len(s) and s[self.i] == ",":
                self.i += 1
            elif self.i == before:
                self.i += 1

    def obj(self, depth=0):
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
            if re.match(r"for\s", s[self.i:self.i + 4]):
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
            v = self.value(depth=depth)
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
    """Decode an HCL quoted string; a template (${...} or %{...}) is UNKNOWN.

    Scan left to right: $${ and %%{ are escapes for a literal ${ / %{, so
    "100%${var.x}" is a literal % followed by an interpolation.
    """
    out, i = [], 0
    while i < len(raw):
        if raw.startswith(("$${", "%%{"), i):
            out.append(raw[i + 1:i + 3])
            i += 3
        elif raw.startswith(("${", "%{"), i):
            return UNKNOWN
        elif raw[i] == "\\" and i + 1 < len(raw):
            if raw[i + 1] == "U" and re.fullmatch(r"[0-9A-Fa-f]{8}", raw[i + 2:i + 10]):
                if int(raw[i + 2:i + 10], 16) > 0x10FFFF:
                    return UNKNOWN  # no such code point: Terraform rejects the string
                out.append(chr(int(raw[i + 2:i + 10], 16)))
                i += 10
                continue
            out.append(raw[i:i + 2])
            i += 2
        else:
            out.append(raw[i])
            i += 1
    text = "".join(out)
    try:
        # strict=False: a literal tab or CR inside the string is allowed in HCL.
        return json.loads('"' + text + '"', strict=False)
    except ValueError:
        return text


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
    def __init__(self, data, line, reads=None, prefix=""):
        self.data, self._line = data, line
        # An unknown block may be absent after apply; unknown attributes in
        # an existing dictionary do not make the block's presence unknown.
        self.known_present = data is not UNKNOWN
        # Plan values: the attributes a rule read while unknown, so not_run
        # names exactly the checks that could not run.
        self.reads, self.prefix = reads, prefix

    @staticmethod
    def wrap(value, line, reads=None, prefix=""):
        if value is UNKNOWN or isinstance(value, dict):
            return [DictView(value, line, reads, prefix)]
        if isinstance(value, list):
            return [DictView(v, line, reads, prefix) for v in value if v is UNKNOWN or isinstance(v, dict)]
        return []

    def get(self, name):
        value = UNKNOWN if self.data is UNKNOWN else self.data.get(name)
        # A block holding unknowns is not itself unread: its own reads are recorded.
        # A map attribute (metadata, labels) may hold unknowns at any depth.
        if self.reads is not None and (value is UNKNOWN or isinstance(value, list) and UNKNOWN in value
                                       or isinstance(value, dict) and holds_unknown(value)):
            self.reads.add(self.prefix + name)
        return value

    def raw(self, name):
        return None

    def blocks(self, name):
        return self.wrap(self.get(name), self._line, self.reads, f"{self.prefix}{name}.")

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


def holds_unknown(value):
    """An unknown anywhere inside a plan value."""
    stack = [value]
    while stack:
        item = stack.pop()
        if item is UNKNOWN:
            return True
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
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


def cfn_string(value):
    """The template text of {"Fn::Sub": "..."} or of a {"Fn::Join": ["", [...]]}
    whose parts are strings and Refs (CDK writes managed policy ARNs that way,
    with {"Ref": "AWS::Partition"}); other values unchanged."""
    if isinstance(value, dict) and len(value) == 1 and "Fn::Sub" in value:
        sub = value["Fn::Sub"]
        if isinstance(sub, list) and sub and isinstance(sub[0], str):
            return sub[0]
        return sub if isinstance(sub, str) else value
    if isinstance(value, dict) and len(value) == 1 and "Fn::Join" in value:
        join = value["Fn::Join"]
        if isinstance(join, list) and len(join) == 2 and isinstance(join[0], str) and isinstance(join[1], list):
            parts = []
            for part in join[1]:
                if isinstance(part, dict) and len(part) == 1 and isinstance(part.get("Ref"), str):
                    part = "${" + part["Ref"] + "}"
                if not isinstance(part, str):
                    return value
                parts.append(part)
            return join[0].join(parts)
    return value


ARN_WILDCARD_ROOT = re.compile(r"\Aarn:[^:]+:iam::\*:root\Z", re.IGNORECASE)
PASSROLE_WILDCARD_ARN = re.compile(r"\Aarn:[^:]+:iam::[^:]*:role/\*\Z", re.IGNORECASE)


def _norm_principal(kind, raw_val):
    val = cfn_string(raw_val)
    norm_kind = "AWS" if isinstance(kind, str) and kind.upper() == "AWS" else (
        "Federated" if isinstance(kind, str) and kind.lower() == "federated" else kind)
    if norm_kind in ("*", "AWS") and isinstance(val, str) and (val == "*" or ARN_WILDCARD_ROOT.match(val)):
        return (norm_kind, "*")
    return (norm_kind, val)


def github_federation(raw, providers=frozenset()):
    """Whether the source text of an unresolved Federated principal names GitHub's
    OIDC provider: the issuer in an interpolated ARN, or a reference to an
    aws_iam_openid_connect_provider whose url is GitHub's (providers) or whose
    name says so."""
    if ":oidc-provider/" + GITHUB_ISSUER in raw:
        return True
    refs = re.findall(r"(?:data\.)?aws_iam_openid_connect_provider\.[\w-]+", raw)
    return bool(refs) and ("github" in raw.lower() or GITHUB_ISSUER in raw or any(r in providers for r in refs))


def github_claim(key):
    """'sub' or 'aud' for a GitHub (or GitHub Enterprise issuer) token claim key, else None."""
    if not isinstance(key, str):
        return None
    issuer, _, claim = key.lower().removeprefix("https://").rpartition(":")
    if issuer == GITHUB_ISSUER or issuer.startswith(GITHUB_ISSUER + "/"):
        return claim
    return None


def norm_statements(doc, raw="", github_providers=frozenset()):
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
                for x in aslist(ids):
                    nk, nv = _norm_principal(kind, x)
                    if nk == "Federated" and nv is UNKNOWN and github_federation(raw, github_providers):
                        nv = "arn:aws:iam::*:oidc-provider/" + GITHUB_ISSUER
                    principals.append((nk, nv))
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
                    conds.extend((op, key, [cfn_string(v) for v in aslist(vals)]) for key, vals in pairs.items())
                else:
                    conds.append((op, UNKNOWN, [UNKNOWN]))
        elif cond is not None:
            conds.append((UNKNOWN, UNKNOWN, [UNKNOWN]))
        raw_effect = st.get("Effect")
        effect = "Allow" if isinstance(raw_effect, str) and raw_effect.lower() == "allow" else raw_effect
        out.append({"effect": effect,
                    "actions": [cfn_string(x) for x in aslist(st.get("Action"))],
                    "not_action": "NotAction" in st,
                    "not_actions": [cfn_string(x) for x in aslist(st.get("NotAction"))],
                    "resources": [cfn_string(x) for x in aslist(st.get("Resource"))],
                    "not_resource": "NotResource" in st,
                    "principals": principals, "conditions": conds})
    return out


def doc_statements(view, github_providers=frozenset()):
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
        raw_effect = st.get("effect")
        effect = "Allow" if raw_effect is None or (
            isinstance(raw_effect, str) and raw_effect.lower() == "allow") else raw_effect
        principals = []
        for p in st.blocks("principals"):
            raw_ids = p.raw("identifiers") or ""
            ptype = p.get("type")
            for x in aslist(p.get("identifiers")):
                nk, nv = _norm_principal(ptype, x)
                if nk == "Federated" and nv is UNKNOWN and github_federation(raw_ids, github_providers):
                    nv = "arn:aws:iam::*:oidc-provider/" + GITHUB_ISSUER
                principals.append((nk, nv))
        if st.blocks("not_principals"):
            principals.append(("*", "*"))  # everyone except the named principals
        conds = [(c.get("test"), c.get("variable"), aslist(c.get("values")))
                 for c in st.blocks("condition")]
        out.append({"effect": effect,
                    "actions": aslist(st.get("actions")),
                    "not_action": st.get("not_actions") is not None,
                    "not_actions": aslist(st.get("not_actions")),
                    "resources": aslist(st.get("resources")),
                    "not_resource": st.get("not_resources") is not None,
                    "principals": principals, "conditions": conds})
    return out


def each_values(for_each, raw):
    """What each.value (or each.key) takes: a set's items, or a map's values (keys)."""
    if isinstance(for_each, dict):
        return list(for_each.keys() if raw.strip() == "each.key" else for_each.values())
    return aslist(for_each)


def each_ports(view):
    """[(from_port, to_port)]: the rule's own pair, or one per for_each element
    when both ports are each.value (or each.key) over a literal collection."""
    lo, hi = view.get("from_port"), view.get("to_port")
    raw = (view.raw("from_port") or "").strip()
    for_each = view.get("for_each")
    if lo is UNKNOWN and raw in ("each.value", "each.key") and (view.raw("to_port") or "").strip() == raw \
            and isinstance(for_each, (list, dict)):
        return [(port, port) for port in each_values(for_each, raw)] or [(lo, hi)]
    return [(lo, hi)]


EACH_ELEMENT = re.compile(r"\beach\.(?:value|key)\b(?![.\[\w])")


def each_cidrs(view, *attrs, for_each=None):
    """A rule's CIDRs, with each.value (or each.key) over a literal collection of
    strings read as its elements, as each_ports does for ports. for_each is the
    enclosing resource's, for a nested ingress block."""
    for_each = view.get("for_each") if for_each is None else for_each
    out = []
    for attr in attrs:
        values = aslist(view.get(attr))
        refs = [m.group() for m in EACH_ELEMENT.finditer(view.raw(attr) or "")]
        elements = each_values(for_each, refs[0]) if refs and isinstance(for_each, (list, dict)) else []
        if elements and all(isinstance(c, str) for c in elements) and values.count(UNKNOWN) >= len(refs):
            for _ in refs:
                values.remove(UNKNOWN)
            values += elements
        out += values
    return out


def cidr_raw(view, *attrs, parent=None):
    """The expressions behind a rule's CIDRs. Through each., they come from
    for_each: an input there (var., local.) may be the world, a subnet is not."""
    raw = raw_of(view, *attrs)
    if "each." in raw:
        raw += " " + ((parent or view).raw("for_each") or "")
    return raw


def lower_strs(values):
    return {v.lower() for v in values if isinstance(v, str)}


ADMIN_SVC_WILDCARDS = {
    "iam", "sts", "organizations", "ec2", "s3", "lambda", "kms",
    "secretsmanager", "ssm", "rds", "dynamodb", "cloudformation", "ecs", "eks",
}


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
        # Account- or org-level settings that change what an omitted
        # argument means, per module directory (see collect_context).
        self.imds_required_dirs, self.ebs_default_dirs = set(), set()
        # {constraint: {"orgs": org IDs, "dirs": {(dir, project or None)}}} for
        # enforced storage org policies.
        self.gcs_org_policies = {}
        self.project_folders = {}  # project ID: folder number, from google_project in the inputs
        self.project_orgs = {}  # project ID: organization number, likewise
        self.launch_templates = set()  # (dir, name) checked under AWS-EC2-001 themselves
        self.s3_blocks = {}  # (dir, bucket key or ("*", provider) for the account): flags turned on
        # (dir, literal bucket name) <-> (dir, aws_s3_bucket address), so a block
        # and an ACL that name one bucket differently still meet.
        self.bucket_aliases = {}
        self.cfn_checked_templates = {}  # template file: logical IDs of its launch templates
        self.k8s_bindings, self.k8s_wildcard_roles = [], {}  # role key: directories defining it
        self.k8s_sa_automount, self.k8s_pod_sa_refs = {}, []
        # (dir, name) of data "google_iam_policy": [(role, members, line)] for the
        # project/folder/organization policy that applies it.
        self.gcp_policy_data = {}
        self.vpc_domains = set()  # (dir, address) of OpenSearch/Elasticsearch domains with vpc_options
        self.admin_policy_data = set()  # (dir, name) of data "aws_iam_policy" naming AdministratorAccess
        self.boundary_policies, self.attached_policies = set(), set()
        # (plan file, module prefix) whose configuration reads a local outside a
        # boundary: a plan does not resolve locals, so one may attach a policy.
        self.plan_local_refs = set()
        # Principal-less policy JSON files: {rel: [statements, referenced?]}
        self.policy_files = {}
        self.tf_dirs = {}
        # dir: addresses of aws_iam_openid_connect_provider resources and data sources for GitHub's issuer
        self.github_providers = {}

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
            if st["effect"] != "Allow":
                continue
            full_res = st.get("not_resource") or "*" in st["resources"]
            if st["not_action"]:
                not_acts = lower_strs(st.get("not_actions", []))
                if full_res and not_acts and not any(
                        a in ("*", "*:*", "iam:*") or a.startswith("iam:passrole") for a in not_acts):
                    self.hit("AWS-IAM-001", res, line, "Allow NotAction on Resource *")
                continue
            acts = lower_strs(st["actions"])
            svc_wildcards = {a.split(":", 1)[0] for a in acts
                             if a.endswith(":*") and a != "*:*" and ":" in a}
            if full_res and ((acts & {"*", "*:*"}) or len(svc_wildcards & ADMIN_SVC_WILDCARDS) >= 2):
                self.hit("AWS-IAM-001", res, line, "Allow Action * on Resource *")
            if not (full_res and (acts & {"*", "*:*"})) and (
                    full_res or any(isinstance(r, str) and PASSROLE_WILDCARD_ARN.match(r)
                                    for r in st["resources"])) and matches_action(st, "iam:PassRole") is True:
                self.hit("AWS-IAM-002", res, line, "Allow iam:PassRole on Resource *")

    def trust_policy(self, res, stmts, line):
        source = getattr(line, "file", res.file)
        for st in stmts or []:
            if st["effect"] != "Allow":
                continue
            # aws:SecureTransport or MFA presence do not narrow who may assume.
            if not narrowing(st["conditions"], caller_set_keys(stmts, st)) and \
                    any(k in ("*", "AWS") and x == "*" for k, x in st["principals"]):
                allows_assume = matches_action(st, "sts:AssumeRole")
                if allows_assume is UNKNOWN:
                    self.not_run.append("AWS-IAM-003: unknown or unsupported trust policy actions; "
                                        f"check not run: {source}:{line} ({res.address})")
                elif allows_assume:
                    self.hit("AWS-IAM-003", res, line, "Principal * without a narrowing condition")
            gap = github_trust_gap(st)
            if gap is UNKNOWN:
                self.not_run.append("AWS-IAM-004: unknown or unsupported GitHub OIDC actions or conditions "
                                    f"at {source}:{line} ({res.address})")
            elif gap:
                self.hit("AWS-IAM-004", res, line, gap)

    def resource_policy(self, res, stmts, line, neutralised=None):
        for st in stmts or []:
            if st["effect"] == "Allow" and not narrowing(st["conditions"]) and \
                    any(k in ("*", "AWS") and x == "*" for k, x in st["principals"]):
                detail = "Allow to Principal * without a narrowing condition"
                if neutralised:
                    self.hit("AWS-S3-003", res, line, f"{detail}; {neutralised}", "Low")
                else:
                    self.hit("AWS-S3-003", res, line, detail)

    def ingress(self, res, line, cidrs, proto, lo, hi, rule="AWS-NET-001", raw=""):
        open_from = world_cidrs(cidrs)
        if not open_from:
            # An input (var.ssh_cidr, !Ref SSHLocation) may be the world: say so,
            # as GCP-NET-001 does for source ranges. A VPC or subnet attribute
            # (aws_vpc.main.cidr_block, module.vpc.*, !GetAtt Vpc.CidrBlock) never is.
            supplied = (any(c is UNKNOWN for c in aslist(cidrs)) and re.search(r"\b(?:var|local)\.", raw)) or any(
                isinstance(c, dict) and "Fn::GetAtt" not in c for c in aslist(cidrs))
            if supplied and sensitive_ports(proto, lo, hi):
                self.not_run.append(f"{rule}: source CIDR unresolved; check not run: "
                                    f"{getattr(line, 'file', res.file)}:{line} ({res.address})")
            return
        ports = sensitive_ports(proto, lo, hi)
        if ports:
            self.hit(rule, res, line, f"ingress from {open_from[0]} to {', '.join(ports[:5])}")
        elif proto is UNKNOWN or (str(to_int(proto) if to_int(proto) is not None else proto).lower() in ("tcp", "6")
                                  and UNKNOWN in (lo, hi)):
            self.not_run.append(f"{rule}: ingress from {open_from[0]} with unresolved protocol or ports; check not "
                                f"run: {getattr(line, 'file', res.file)}:{line} ({res.address})")

    def statements(self, res, attr, view=None):
        view = view or res.view
        value = view.get(attr)
        raw = view.raw(attr) or ""
        if isinstance(value, str):
            try:
                value = json.loads(value, object_pairs_hook=unique_object)
            except ValueError:
                # A heredoc with ${jsonencode(...)} outside a JSON string, or a
                # malformed document: the statements were never read.
                if value.strip():
                    line = view.line(attr)
                    self.not_run.append(f"policy document is not JSON as written (template or syntax error); "
                                        f"{attr} checks not run: {getattr(line, 'file', res.file)}:{line} "
                                        f"({res.address})")
                return None
        providers = self.github_providers.get(res.dir, frozenset())
        if isinstance(value, dict):
            statements = norm_statements(value, raw=raw, github_providers=providers)
            listed = value.get("Statement")
            # Statement = concat(local.base, [...]) or [local.admin]: what was not read was not checked.
            if "Statement" in value and (statements is None or (
                    isinstance(listed, list) and not all(isinstance(st, dict) for st in listed))):
                line = view.line(attr)
                self.not_run.append(f"policy statements not resolved from the inputs; {attr} checks not run "
                                    f"on them: {getattr(line, 'file', res.file)}:{line} ({res.address})")
            return statements
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
                # Only when the document itself is written in raw (its Statement is there):
                # templatefile(), replace(local.tpl, ...) and the like keep their conditions elsewhere.
                if attr == "assume_role_policy" and github_federation(raw, providers) and \
                        "condition" not in raw.lower() and re.search(r"\bStatement\b", raw):
                    return [{"effect": "Allow", "actions": ["sts:AssumeRoleWithWebIdentity"],
                             "not_action": False, "resources": ["*"], "not_resource": False,
                             "principals": [("Federated", "arn:aws:iam::*:oidc-provider/" + GITHUB_ISSUER)],
                             "conditions": []}]
                line = view.line(attr)
                self.not_run.append(f"policy document not resolved from the inputs; {attr} checks not run: "
                                    f"{getattr(line, 'file', res.file)}:{line} ({res.address})")
        return None

    def gcp_iam(self, res, role, members, line, service_agent=None, raw=""):
        """service_agent: every member is a Google-managed agent (computed here when
        None); raw: the member's source text when it is templated."""
        if service_agent is None:
            service_agent = bool(members) and all(isinstance(m, str) and SERVICE_AGENT.search(m) for m in members)
        unresolved = role is UNKNOWN or UNKNOWN in members
        if unresolved and not service_agent:
            self.not_run.append(f"GCP-IAM: role or members unresolved; checks not run: {res.file}:{line} "
                                f"({res.address})")
        role_text = role if isinstance(role, str) else "a role"
        public = [m for m in members if m in ("allUsers", "allAuthenticatedUsers")]
        if public:
            self.hit("GCP-IAM-001", res, line, f"{role_text} granted to {public[0]}")
        # Google-managed service agents receive token-creator and, for the Google
        # APIs agent (@cloudservices), roles/editor by design; owner is never default.
        agent_default = service_agent and role == "roles/editor" and all(
            "@cloudservices." in (m if isinstance(m, str) else raw) for m in members)
        if role in ("roles/owner", "roles/editor") and not agent_default:
            self.hit("GCP-IAM-002", res, line, f"{role} granted")
        if role in ("roles/iam.serviceAccountTokenCreator", "roles/iam.serviceAccountUser") and not service_agent and \
                res.type.startswith(("google_project_iam_", "google_folder_iam_",
                                     "google_organization_iam_")):
            self.hit("GCP-IAM-004", res, line, f"{role} granted at {res.type.split('_')[1]} level")

    def firewall(self, res, line, direction, disabled, ranges, allows, other_sources=()):
        if disabled is UNKNOWN or disabled is True or str(disabled).lower() == "true":
            return
        # direction is computed in a plan (UNKNOWN); source ranges only apply
        # to ingress, so known source ranges settle it.
        if direction not in (None, "INGRESS") and not (direction is UNKNOWN and ranges not in (None, UNKNOWN)):
            return
        if ranges in (None, []) and all(src in (None, []) for src in other_sources):
            # GCP: an ingress rule with no source applies to every source; an
            # empty list is not sent to the API, so it means the same.
            ranges = ["0.0.0.0/0"]
        # A known world range is open whatever its unresolved siblings hold.
        if ranges is UNKNOWN or (isinstance(ranges, list) and UNKNOWN in ranges and not world_cidrs(ranges)):
            if any(proto is not None for proto, _ in allows):
                self.not_run.append(f"GCP-NET-001: source ranges unresolved; check not run: "
                                    f"{getattr(line, 'file', res.file)}:{line} ({res.address})")
            return
        open_from = world_cidrs(ranges)
        if not open_from:
            return
        unresolved = False
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
                ordered = sorted(set(found), key=lambda p: int(p.split("/")[0]) if p.split("/")[0].isdigit() else 0)
                self.hit("GCP-NET-001", res, line, f"ingress from {open_from[0]} to {', '.join(ordered[:5])}")
                return
            unresolved = unresolved or contains_unknown(ports)
        if unresolved or any(proto is UNKNOWN for proto, _ in allows):
            self.not_run.append(f"GCP-NET-001: ingress from {open_from[0]} with unresolved protocol or ports; check "
                                f"not run: {getattr(line, 'file', res.file)}:{line} ({res.address})")


# Condition keys that hold for any caller, so they do not narrow Principal "*".
# The caller's own principal tags and session name need no further grant
# (any account can tag its own role team=platform); request tags and a
# source identity are the caller's only where the trust policy grants
# sts:TagSession / sts:SetSourceIdentity to anyone (caller_set_keys). Unknown
# keys count as narrowing: precision over completeness.
OPEN_CONDITION_KEYS = {
    "aws:securetransport", "aws:currenttime", "aws:epochtime", "aws:requestedregion",
    "aws:referer", "aws:useragent", "aws:multifactorauthpresent", "s3:tlsversion",
    "s3:signatureversion", "s3:signatureage", "s3:authtype", "s3:x-amz-content-sha256",
    "s3:x-amz-server-side-encryption", "s3:x-amz-server-side-encryption-aws-kms-key-id",
    "s3:x-amz-acl", "s3:prefix", "s3:delimiter", "s3:max-keys",
    "aws:multifactorauthage", "sts:rolesessionname",
}
OPEN_CONDITION_PREFIXES = ("aws:principaltag/",)


def _condition_narrows(op, key, vals):
    if not isinstance(key, str):
        return True
    if key.lower() in OPEN_CONDITION_KEYS or key.lower().startswith(OPEN_CONDITION_PREFIXES):
        return False
    if not isinstance(op, str):
        return True
    op_base = op.lower()
    # ForAllValues is true when the request lacks the key (aws:PrincipalOrgID
    # for a caller outside any organization, or an anonymous one), like IfExists.
    if op_base.startswith("forallvalues:") or op_base.endswith("ifexists"):
        return False
    op_base = op_base.removeprefix("foranyvalue:")
    if not vals or all(v == "" or v == [] for v in vals):
        return False
    if op_base in ("stringnotequals", "stringnotequalsignorecase", "stringnotlike",
                   "arnnotequals", "arnnotlike", "notipaddress"):
        return False
    if op_base == "ipaddress" and bool(world_cidrs(vals)):
        return False
    if op_base == "null" and any(v is True or (isinstance(v, str) and v.lower() == "true") for v in vals):
        return False
    # ArnEquals expands * and ? per ARN component exactly as ArnLike does.
    if op_base in ("stringlike", "stringlikeignorecase", "arnlike", "arnequals") and vals and all(
            isinstance(v, str) and (v.strip("*") in ("", "arn:", "arn:aws:") or any_owner(key, v)) for v in vals):
        return False
    return True


# Keys naming the caller's or the source's account or organization, and their ARNs.
OWNER_KEYS = {"aws:principalorgid", "aws:principalaccount", "aws:sourceaccount", "aws:sourceowner",
              "aws:sourceorgid"}
OWNER_ARN_KEYS = {"aws:principalarn", "aws:sourcearn"}
# S3 resource types whose ARN names an account (arn:aws:s3:region:account:accesspoint/name).
S3_ACCOUNT_RESOURCES = {"accesspoint", "job", "storage-lens", "storage-lens-group", "access-grants"}


RESOURCE_ARN_REF = re.compile(r"\$\{(?:data\.)?(?:aws|google)_[\w-]+\.[\w-]+(?:\[[^\]]*\])?\.arn\}")


def any_owner(key, value):
    """A like-pattern any account or organization can satisfy: o-*, or an ARN
    whose account is a wildcard (anyone can create role/deployer in their own)."""
    key = key.lower()
    if key in OWNER_KEYS:
        return value.strip("*?") in ("", "o-")
    if key in OWNER_ARN_KEYS:
        parts = value.split(":", 5)
        if len(parts) < 6:
            # A resource's own ARN (${aws_sns_topic.t.arn}) names that resource;
            # a variable or local may hold any pattern.
            return RESOURCE_ARN_REF.fullmatch(value) is None
        account, wildcard = parts[4], (lambda text: any(c in text for c in "*?"))
        if parts[2] == "s3":
            if account and not wildcard(account):
                return False  # that account's access points and jobs
            # Buckets carry no account (arn:aws:s3:::bucket/key; a * account matches that empty
            # one) and their names are global: only a wildcard in the name lets another account
            # match. Access points and jobs take a wildcard account from anyone.
            bucket = parts[5].split("/", 1)[0]
            if account and bucket in S3_ACCOUNT_RESOURCES:
                return True
            return not bucket or wildcard(bucket)
        return wildcard(account)
    return False


def narrowing(conditions, caller_set=()):
    """Some condition limits who matches; keys starting with caller_set are the caller's to choose."""
    return any(_condition_narrows(op, key, vals) for op, key, vals in conditions
               if not (isinstance(key, str) and key.lower().startswith(caller_set)))


CALLER_GRANTS = (("sts:TagSession", ("aws:requesttag/", "aws:tagkeys")),
                 ("sts:SetSourceIdentity", ("sts:sourceidentity",)))


def caller_set_keys(stmts, assume):
    """Condition keys of the assume statement that any caller can set: session
    tags where some statement grants sts:TagSession to "*", a source identity
    where one grants sts:SetSourceIdentity (AWS's own example puts these in a
    statement of their own). The grant's conditions must all hold for the
    caller already: either they narrow nothing, or the assume statement makes
    the very same demand (aws:RequestTag/team = platform in both). A grant for
    other values (team = security) opens nothing; values are not compared.
    An explicit Deny of the action to "*" overrides any grant when it holds for
    every request the assume statement admits, by the same exact matching."""
    def to_anyone(st):
        return any(k in ("*", "AWS") and x == "*" for k, x in st["principals"])
    keys = ()
    for action, opened in CALLER_GRANTS:
        if any(st["effect"] == "Allow" and matches_action(st, action) is True and to_anyone(st)
               and not narrowing([c for c in st["conditions"] if c not in assume["conditions"]])
               for st in stmts or []) and not any(
                st["effect"] == "Deny" and matches_action(st, action) is not False and to_anyone(st)
                and not narrowing([c for c in st["conditions"] if c not in assume["conditions"]])
                for st in stmts or []):
            keys += opened
    return keys


def world_cidrs(values):
    """Canonical /0 ranges, and narrower ranges in the same list that together
    cover a whole address family (0.0.0.0/1 + 128.0.0.0/1); unknown, invalid
    and other narrower ranges are skipped."""
    out, parts = [], {4: [], 6: []}
    for value in aslist(values):
        if not isinstance(value, str):
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.prefixlen == 0:
            out.append(str(network))
        elif network not in parts[network.version]:
            parts[network.version].append(network)
    for version, nets in parts.items():
        world = ipaddress.ip_network("0.0.0.0/0" if version == 4 else "::/0")
        if str(world) in out or world not in ipaddress.collapse_addresses(nets):
            continue
        out.append(" + ".join(map(str, nets)) if len(nets) <= 3 else f"{world} split over {len(nets)} ranges")
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
GITHUB_EXACT_OPS = {
    "StringEquals", "StringEqualsIgnoreCase",
}
GITHUB_LIKE_OPS = {
    "StringLike", "StringLikeIgnoreCase",
}
GITHUB_WEAK_OPS = {
    "foranyvalue:stringequals", "foranyvalue:stringequalsignorecase",
    "foranyvalue:stringlike", "foranyvalue:stringlikeignorecase",
}


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
    # GitHub Enterprise Cloud issuers append the enterprise: <issuer>/<slug>.
    fed = any(k == "Federated" and isinstance(x, str) and (
              github_claim(x.removeprefix("https://").rstrip("/") + ":") == "" or
              github_claim(x.rstrip("/").rpartition(":oidc-provider/")[2] + ":") == "" or
              ("aws_iam_openid_connect_provider" in x and ("github" in x.lower() or GITHUB_ISSUER in x)))
              for k, x in st["principals"])
    keyed = any(github_claim(key) is not None for _, key, _ in st["conditions"])
    if not fed and keyed and any((k == "Federated" and not isinstance(x, str)) or k is UNKNOWN
                                 for k, x in st["principals"]):
        # Federated = aws_iam_openid_connect_provider.github.arn: the provider is
        # a reference, but only GitHub tokens carry these condition keys.
        fed = True
    if not fed:
        return None
    subs, weak_aud, unsupported = [], False, allows_assume is UNKNOWN or contains_unknown(st["conditions"])
    for op, key, vals in st["conditions"]:
        if not isinstance(key, str):
            unsupported = True
        elif github_claim(key) == "sub":
            subs.append((op, vals))
        elif github_claim(key) == "aud":
            if isinstance(op, str) and (op.lower() in GITHUB_WEAK_OPS or op.lower().endswith("ifexists")):
                weak_aud = True
        else:
            # Other claims can narrow an otherwise broad subject. Do not
            # pretend to evaluate their effect on the set of repositories.
            unsupported = True
    broad = 0
    pinned = False
    for op, vals in subs:
        if not vals or not all(isinstance(v, str) and "${" not in v for v in vals) or not isinstance(op, str):
            unsupported = True
        elif op in GITHUB_EXACT_OPS:
            # These operators do not expand '*' or '?'. Even a wildcard-
            # shaped value is an exact subject, not an all-repository grant.
            pinned = True
        elif op in GITHUB_LIKE_OPS:
            if all(not any(c in v for c in "*?") or GITHUB_REPO_SUB.match(v) for v in vals):
                pinned = True
            else:
                broad += 1
        elif op.lower() in GITHUB_WEAK_OPS or op.lower().endswith("ifexists"):
            broad += 1
        else:
            unsupported = True
    if pinned and not weak_aud:
        return None
    if unsupported or broad > 1:
        return UNKNOWN
    if weak_aud:
        return "GitHub OIDC :aud condition uses ForAnyValue or IfExists"
    if not subs:
        return "no :sub condition on the GitHub OIDC token"
    return "GitHub :sub pattern does not pin the organization and repository"


# ---------------------------------------------------------------- Terraform rules

# AWS-owned policies in every partition (aws, aws-us-gov, aws-cn, aws-iso...).
AWS_MANAGED_ARN = re.compile(r"arn:aws(?:-[a-z]+)*:iam::aws:policy/")
ADMIN_ARN = re.compile(r"\Aarn:(?:[a-z0-9-]+|\$\{[^}]+\}):iam::aws:policy/AdministratorAccess\Z")
# The same ARN in raw HCL, with the partition interpolated (terraform-aws-modules idiom).
ADMIN_ARN_RAW = re.compile(r'"arn:(?:[a-z0-9-]+|\$\{[^}"]+\}):iam::aws:policy/AdministratorAccess"')
PUBLIC_GROUP = re.compile(r"/global/(?:AllUsers|AuthenticatedUsers)$")
GCP_IAM = re.compile(r"^google_\w+_iam_(member|binding)$")
SERVICE_AGENT = re.compile(r"@(?:gcp-sa-[a-z0-9-]+\.iam|cloudservices|"
                           r"container-engine-robot\.iam|compute-system\.iam)\.gserviceaccount\.com")
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


def bucket_key(view, address=None):
    """What names a bucket across resources: aws_s3_bucket.x for a reference to
    it (.id, .bucket), with its literal instance key when counted
    (aws_s3_bucket.x[0], aws_s3_bucket.x["logs"]), else the literal bucket name."""
    raw = (view.raw("bucket") or "").strip() if hasattr(view, "raw") else ""
    ref = re.fullmatch(r'(aws_s3_bucket\.[\w-]+(?:\[(?:\d+|"[^"\\]*")\])?)\.(?:id|bucket)', raw)
    if ref:
        return ref.group(1)
    if address:
        return address
    value = view.get("bucket")
    return value if isinstance(value, str) else None


def raw_of(view, *attrs):
    """The expressions written for attrs, as one string ("" in plans and exports)."""
    return " ".join(view.raw(attr) or "" for attr in attrs)


def admin_arn_list(scan, res, attr):
    """A list of managed policy ARNs holding AdministratorAccess, written out or through data.aws_iam_policy."""
    v = res.view
    text = text_of(v, attr)
    return any(isinstance(a, str) and ADMIN_ARN.search(a) for a in aslist(v.get(attr))) or \
        ADMIN_ARN_RAW.search(text) is not None or any(
            (res.dir, name) in scan.admin_policy_data
            for name in re.findall(r"data\.aws_iam_policy\.([\w-]+)\.arn", text))


def s3_block(scan, res, flag):
    """A note when a public access block in the module turns flag on for this bucket."""
    keys = {bucket_key(res.view, res.address if res.type == "aws_s3_bucket" else None)}
    if res.type == "aws_s3_bucket" and isinstance(res.view.get("bucket"), str):
        keys.add(res.view.get("bucket"))
    keys |= {scan.bucket_aliases.get((res.dir, key)) for key in keys}
    for key in keys - {None}:
        if flag in scan.s3_blocks.get((res.dir, key), ()):
            where = "ownership controls" if flag == "BucketOwnerEnforced" else "public access block"
            return f"neutralised by {flag} in the bucket's {where}"
    if flag in scan.s3_blocks.get((res.dir, ("*", provider_key(res.view))), ()):
        return f"neutralised by {flag} in the account public access block"
    return None


def without_block(text, name):
    """text with every `name { ... }` block removed (braces counted)."""
    while (m := re.search(rf"\b{name}\s*\{{", text)):
        depth, i = 0, m.end() - 1
        while i < len(text):
            depth += {"{": 1, "}": -1}.get(text[i], 0)
            i += 1
            if depth == 0:
                break
        text = text[:m.start()] + text[i:]
    return text


def org_policy_enforced(scan, constraint, res):
    """An enforced org policy in the inputs covers this bucket."""
    policies = scan.gcs_org_policies.get(constraint)
    if not policies:
        return False
    # An organization or folder policy covers a bucket whose project a google_project
    # in the inputs places in that organization or folder.
    project = res.view.get("project") if res.view else None
    if isinstance(project, str) and (scan.project_folders.get(project) in policies["folders"] or
                                     scan.project_orgs.get(project) in policies["orgs"]):
        return True
    # A project policy covers a bucket of the same project: the same literal, both
    # omitted under one provider configuration, or the same unresolved expression.
    here = {p for d, p in policies["dirs"] if d == res.dir}
    scope = project_scope(res.view, "project") if res.view else ("provider", "default")
    return scope in here and scope != ("expr", None)


def project_scope(view, attr):
    """A project as written: its literal ID, ("provider", alias) when omitted, or
    ("expr", text) for an unresolved reference (var.project, "projects/${var.project}")."""
    value = view.get(attr)
    if value is None:
        # The provider's default project: one per provider configuration (google.other).
        return ("provider", provider_key(view))
    if isinstance(value, str):
        return value.removeprefix("projects/") if attr == "parent" else value
    raw = view.raw(attr)
    if not raw:
        return ("expr", None)
    raw = re.sub(r'^"(?:projects/)?\$\{(.*)\}"$', r"\1", raw.strip())
    return ("expr", raw.strip())


def default_service_account(email, raw=None):
    """An omitted, "default" or *-compute@developer email, written out or referenced."""
    if email is None or email == "default" or (isinstance(email, str) and DEFAULT_SA.search(email)):
        return True
    raw = raw or ""
    return email is UNKNOWN and (DEFAULT_SA.search(raw.replace('"', "")) is not None or
                                 "data.google_compute_default_service_account." in raw)


def gce_metadata(scan, res, meta, line):
    if not isinstance(meta, dict):
        return
    gaps = []
    if str(meta.get("serial-port-enable")).lower() in ("true", "1"):
        gaps.append("serial-port-enable = true")
    if str(meta.get("block-project-ssh-keys")).lower() == "false":
        gaps.append("block-project-ssh-keys = false")
    if gaps:
        scan.hit("GCP-GCE-002", res, line, "; ".join(gaps))


def gke_node_config(scan, res, configs):
    """Nodes run as the default compute service account unless node_config names
    another; GCE_METADATA exposes the node's metadata server to pods."""
    # A cluster without node_config often removes its default pool or is
    # managed by node pools elsewhere; only a node pool's omission is certain.
    if not configs and res.type == "google_container_node_pool":
        scan.hit("GCP-GCE-001", res, res.line, "GKE nodes as the default compute service account")
    for config in configs:
        if config.known_present is False:
            continue
        if default_service_account(config.get("service_account"), config.raw("service_account")):
            scopes = lower_strs(aslist(config.get("oauth_scopes")))
            full = any(s.endswith("cloud-platform") for s in scopes)
            scan.hit("GCP-GCE-001", res, config.line(), "GKE nodes as the default compute service account"
                     + (" with cloud-platform scope" if full else ""))
        for wmc in config.blocks("workload_metadata_config"):
            if wmc.get("mode") == "GCE_METADATA":
                scan.hit("GCP-GKE-001", res, wmc.line("mode"), "workload_metadata_config mode = GCE_METADATA "
                         "(pods reach the node's metadata server)", "Medium")


VPC_DOMAIN_TYPES = ("aws_opensearch_domain", "aws_elasticsearch_domain")


def add_vpc_domain_name(scan, directory, view):
    """A split domain policy may name its domain by value (always so in a plan)."""
    if isinstance(view.get("domain_name"), str):
        scan.vpc_domains.add((directory, "domain_name:" + view.get("domain_name")))


def check_tf_shared(scan, res):
    """Rules that apply across several resource types, ahead of the per-type chain."""
    t, v = res.type, res.view
    attr = RESOURCE_POLICY_ATTRS.get(t)
    # A VPC-only OpenSearch/Elasticsearch domain is reached through its security
    # groups; Principal * in its access policy is the documented pattern there.
    vpc_domain = t.endswith(("_domain", "_domain_policy")) and bool(v.blocks("vpc_options"))
    if t.endswith("_domain_policy") and hasattr(v, "raw"):
        # The split form: aws_opensearch_domain_policy names its domain by reference.
        domain = re.fullmatch(r"\s*(aws_(?:opensearch|elasticsearch)_domain\.[\w-]+)\.domain_name\s*",
                              v.raw("domain_name") or "")
        vpc_domain = vpc_domain or bool(domain and (res.dir, domain.group(1)) in scan.vpc_domains)
    if t.endswith("_domain_policy") and isinstance(v.get("domain_name"), str):
        vpc_domain = vpc_domain or (res.dir, "domain_name:" + v.get("domain_name")) in scan.vpc_domains
    if attr and v.get(attr) is not None and not vpc_domain:
        scan.resource_policy(res, scan.statements(res, attr), v.line(attr))
    if t in PUBLIC_DATA_SERVICES and tf_bool(v.get("publicly_accessible")) is True:
        scan.hit("AWS-RDS-001", res, v.line("publicly_accessible"), "publicly_accessible = true")
    if t in ("aws_instance", "aws_launch_template", "aws_launch_configuration"):
        devices = v.blocks("root_block_device") + v.blocks("ebs_block_device")
        devices += [ebs for mapping in v.blocks("block_device_mappings") for ebs in mapping.blocks("ebs")]
        for device in devices:
            if tf_bool(device.get("encrypted")) is False:
                scan.hit("AWS-EBS-001", res, device.line("encrypted"), "block device encrypted = false")
    if t == "aws_ami_launch_permission" and v.get("group") == "all":
        scan.hit("AWS-SNAP-001", res, v.line("group"), "launch permission group = all")
    if t in ("aws_db_snapshot", "aws_db_cluster_snapshot") and "all" in aslist(v.get("shared_accounts")):
        scan.hit("AWS-SNAP-001", res, v.line("shared_accounts"), "shared_accounts includes all")
    if t == "aws_cloudfront_distribution":
        behaviors = v.blocks("default_cache_behavior") + v.blocks("ordered_cache_behavior")
        for behavior in behaviors:
            if behavior.get("viewer_protocol_policy") == "allow-all":
                scan.hit("AWS-CF-001", res, behavior.line("viewer_protocol_policy"),
                         "viewer_protocol_policy = allow-all")
        for cert in v.blocks("viewer_certificate"):
            if cert.get("minimum_protocol_version") in OLD_TLS and \
                    tf_bool(cert.get("cloudfront_default_certificate")) is not True:
                scan.hit("AWS-CF-001", res, cert.line("minimum_protocol_version"),
                         f"minimum_protocol_version = {cert.get('minimum_protocol_version')}")
    if t in ("google_storage_bucket_acl", "google_storage_object_acl", "google_storage_default_object_acl",
             "google_storage_bucket_object"):
        if v.get("predefined_acl") in PUBLIC_GCS_ACL:
            scan.hit("GCP-GCS-002", res, v.line("predefined_acl"), f"predefined_acl = {v.get('predefined_acl')}")
        entities = [e for e in aslist(v.get("role_entity")) if isinstance(e, str)]
        public = [e for e in entities if e.endswith((":allUsers", ":allAuthenticatedUsers"))]
        if public:
            scan.hit("GCP-GCS-002", res, v.line("role_entity"), f"role_entity {public[0]}")
    if t in ("google_storage_bucket_access_control", "google_storage_default_object_access_control",
             "google_storage_object_access_control") and v.get("entity") in ("allUsers", "allAuthenticatedUsers"):
        scan.hit("GCP-GCS-002", res, v.line("entity"), f"{v.get('role')} granted to {v.get('entity')}")
    if t == "google_cloud_run_v2_service" and tf_bool(v.get("invoker_iam_disabled")) is True:
        scan.hit("GCP-IAM-001", res, v.line("invoker_iam_disabled"),
                 "invoker_iam_disabled = true: anyone can invoke the service")
    if t in ("google_bigquery_dataset", "google_bigquery_dataset_access"):
        grants = v.blocks("access") if t == "google_bigquery_dataset" else [v]
        for grant in grants:
            for key in ("special_group", "iam_member"):
                who = grant.get(key)
                if who in ("allUsers", "allAuthenticatedUsers"):
                    scan.hit("GCP-GCS-002", res, grant.line(), f"dataset access granted to {who}")
                    break


def check_tf(scan, res):
    t, v = res.type, res.view
    check_tf_shared(scan, res)
    if t in ("aws_security_group", "aws_default_security_group"):
        for rule in v.blocks("ingress"):
            scan.ingress(res, rule.line(), each_cidrs(rule, "cidr_blocks", "ipv6_cidr_blocks", for_each=v.get("for_each")),
                         rule.get("protocol"), rule.get("from_port"), rule.get("to_port"),
                         raw=cidr_raw(rule, "cidr_blocks", "ipv6_cidr_blocks", parent=v))
    elif t == "aws_security_group_rule":
        if v.get("type") == "ingress":
            # The open range's own line: an override may set it in another file.
            line = v.line("cidr_blocks") if world_cidrs(each_cidrs(v, "cidr_blocks")) else v.line("ipv6_cidr_blocks")
            for lo, hi in each_ports(v):
                scan.ingress(res, line, each_cidrs(v, "cidr_blocks", "ipv6_cidr_blocks"),
                             v.get("protocol"), lo, hi, raw=cidr_raw(v, "cidr_blocks", "ipv6_cidr_blocks"))
    elif t == "aws_vpc_security_group_ingress_rule":
        line = v.line("cidr_ipv4") if world_cidrs(each_cidrs(v, "cidr_ipv4")) else v.line("cidr_ipv6")
        for lo, hi in each_ports(v):
            scan.ingress(res, line, each_cidrs(v, "cidr_ipv4", "cidr_ipv6"), v.get("ip_protocol"), lo, hi,
                         raw=cidr_raw(v, "cidr_ipv4", "cidr_ipv6"))
    elif t in ("aws_s3_bucket", "aws_s3_bucket_acl", "aws_s3_object", "aws_s3_bucket_object"):
        # A public access block on the same bucket makes S3 ignore public ACLs:
        # still a misconfiguration, but defence in depth rather than exposure.
        blocked = s3_block(scan, res, "ignore_public_acls") or s3_block(scan, res, "BucketOwnerEnforced")
        def acl_hit(line, detail):
            if blocked:
                scan.hit("AWS-S3-001", res, line, f"{detail}; {blocked}", "Low")
            else:
                scan.hit("AWS-S3-001", res, line, detail)
        if v.get("acl") in ("public-read", "public-read-write", "authenticated-read"):
            acl_hit(v.line("acl"), f"{'object ' if 'object' in t else ''}acl = {v.get('acl')}")
        grants = v.blocks("grant") + [g for policy in v.blocks("access_control_policy") for g in policy.blocks("grant")]
        for grant in grants:
            uris = [grant.get("uri")] + [grantee.get("uri") for grantee in grant.blocks("grantee")]
            group = next((u for u in uris if isinstance(u, str) and PUBLIC_GROUP.search(u)), None)
            if group:
                acl_hit(grant.line(), f"grant to {group.rsplit('/', 1)[-1]}")
        if t == "aws_s3_bucket" and v.get("policy") is not None:
            scan.resource_policy(res, scan.statements(res, "policy"), v.line("policy"),
                                 s3_block(scan, res, "restrict_public_buckets"))
    elif t in ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block"):
        flags = ("block_public_acls", "block_public_policy", "ignore_public_acls",
                 "restrict_public_buckets")
        off = [f for f in flags if tf_bool(v.get(f)) in (False, None)]
        if off:
            scan.hit("AWS-S3-002", res, res.line, "off: " + ", ".join(off))
    elif t == "aws_s3_bucket_policy":
        scan.resource_policy(res, scan.statements(res, "policy"), v.line("policy"),
                             s3_block(scan, res, "restrict_public_buckets"))
    elif t in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
        key = (res.dir, re.sub(r"\[[^\]]*\]", "", res.address))  # module.app.aws_iam_policy.b[0] -> ...b
        if t == "aws_iam_policy" and key in scan.boundary_policies and key not in scan.attached_policies:
            # A permissions boundary caps permissions ("allow *, deny X" is the
            # usual shape); it grants nothing by itself.
            module = key[1][:key[1].rindex("aws_iam_policy.")]
            use = ("used as a permissions boundary, and a local the plan does not resolve may attach it"
                   if (res.dir, module) in scan.plan_local_refs else "used only as a permissions boundary")
            scan.not_run.append(f"IAM policy {use}; grant rules not applied: {res.file}:{res.line} ({res.address})")
            return
        scan.identity_policy(res, scan.statements(res, "policy"), v.line("policy"))
    elif t == "aws_iam_role":
        scan.trust_policy(res, scan.statements(res, "assume_role_policy"), v.line("assume_role_policy"))
        for inline in v.blocks("inline_policy"):
            scan.identity_policy(res, scan.statements(res, "policy", inline), inline.line())
        if admin_arn_list(scan, res, "managed_policy_arns"):
            scan.hit("AWS-IAM-001", res, v.line("managed_policy_arns"), "AdministratorAccess attached")
    elif t in ("aws_iam_role_policy_attachments_exclusive", "aws_iam_user_policy_attachments_exclusive",
               "aws_iam_group_policy_attachments_exclusive"):
        if admin_arn_list(scan, res, "policy_arns"):
            scan.hit("AWS-IAM-001", res, v.line("policy_arns"), "AdministratorAccess attached")
    elif t == "aws_ssoadmin_permission_set_inline_policy":
        # A permission set grants its policies in every account it is assigned to.
        scan.identity_policy(res, scan.statements(res, "inline_policy"), v.line("inline_policy"))
    elif t in ("aws_iam_role_policy_attachment", "aws_iam_user_policy_attachment",
               "aws_iam_group_policy_attachment", "aws_iam_policy_attachment",
               "aws_ssoadmin_managed_policy_attachment"):
        attr = "managed_policy_arn" if t == "aws_ssoadmin_managed_policy_attachment" else "policy_arn"
        arn = v.get(attr)
        raw = (v.raw(attr) or "").strip()
        data = re.fullmatch(r"data\.aws_iam_policy\.([\w-]+)\.arn", raw)
        # for_each = toset([".../AdministratorAccess", ...]) with policy_arn = each.value (or each.key).
        each = raw in ("each.value", "each.key") and any(
            isinstance(a, str) and ADMIN_ARN.search(a) for a in each_values(v.get("for_each"), raw))
        if (isinstance(arn, str) and ADMIN_ARN.search(arn)) or ADMIN_ARN_RAW.search(text_of(v, attr)) or \
                (data and (res.dir, data.group(1)) in scan.admin_policy_data) or each:
            scan.hit("AWS-IAM-001", res, v.line(attr), "AdministratorAccess attached")
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
            "replicate_source_db", "snapshot_identifier", "replication_source_identifier")) or bool(
            v.blocks("restore_to_point_in_time"))
        if t != "aws_rds_cluster_instance" and tf_bool(v.get("storage_encrypted")) in (False, None) \
                and not inherited and v.get("engine_mode") != "serverless":
            scan.hit("AWS-RDS-002", res, v.line("storage_encrypted"), "storage_encrypted not true")
    elif t in ("aws_instance", "aws_launch_template", "aws_launch_configuration"):
        opts = v.blocks("metadata_options")
        if not opts and t == "aws_instance" and v.blocks("launch_template"):
            template = v.blocks("launch_template")[0]
            ref = re.match(r"\s*aws_launch_template\.([\w-]+)\.(?:id|name)\s*$",
                           template.raw("id") or template.raw("name") or "")
            if not (ref and (res.dir, ref.group(1)) in scan.launch_templates):
                scan.not_run.append("AWS-EC2-001: metadata options come from a launch template; check the "
                                    f"template: {res.file}:{res.line} ({res.address})")
        elif not opts and (res.dir, provider_key(v)) in scan.imds_required_dirs:
            pass  # aws_ec2_instance_metadata_defaults requires IMDSv2 for omitted settings
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
            if tokens is None and (res.dir, provider_key(v)) in scan.imds_required_dirs:
                return  # an omitted http_tokens takes the account default
            if tokens is None or (isinstance(tokens, str) and tokens != "required"):
                scan.hit("AWS-EC2-001", res, opts[0].line("http_tokens"),
                         f"http_tokens = {tokens if tokens else 'unset'}")
    elif t == "aws_ebs_volume":
        encrypted = tf_bool(v.get("encrypted"))
        # aws_ebs_encryption_by_default encrypts volumes that omit the argument.
        if encrypted is False or (encrypted is None and (res.dir, provider_key(v)) not in scan.ebs_default_dirs
                                  and v.get("snapshot_id") in (None, "")):
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
            # The provider sends public_access_cidrs only when non-empty; the API default is 0.0.0.0/0.
            open_from = world_cidrs(["0.0.0.0/0"] if cidrs in (None, []) else cidrs)
            if public in (True, None) and open_from:
                scan.hit("AWS-EKS-001", res, cfg.line(), f"public endpoint open to {open_from[0]}")
    elif t == "google_compute_firewall":
        allows = []
        for a in v.blocks("allow"):
            # for_each = toset(["22", "3389"]) with ports = [each.value]: one rule per element.
            raw = (a.raw("ports") or "").replace(" ", "")
            if raw in ("[each.value]", "[each.key]") and isinstance(v.get("for_each"), (list, dict)):
                allows.append((a.get("protocol"), each_values(v.get("for_each"), raw.strip("[]"))))
            else:
                allows.append((a.get("protocol"), a.get("ports")))
        ranges = each_cidrs(v, "source_ranges") if "each." in (v.raw("source_ranges") or "") else v.get("source_ranges")
        scan.firewall(res, res.line, v.get("direction"), tf_bool(v.get("disabled")),
                      ranges, allows, (v.get("source_tags"), v.get("source_service_accounts")))
    elif t in ("google_compute_firewall_policy_rule", "google_compute_network_firewall_policy_rule",
               "google_compute_region_network_firewall_policy_rule"):
        # Hierarchical and network firewall policies: match { src_ip_ranges, layer4_configs }.
        if v.get("action") == "allow":
            for match in v.blocks("match"):
                allows = [(l4.get("ip_protocol"), l4.get("ports")) for l4 in match.blocks("layer4_configs")]
                others = (match.blocks("src_secure_tags") or None, *(match.get(k) for k in (
                    "src_address_groups", "src_fqdns", "src_region_codes", "src_threat_intelligences")))
                scan.firewall(res, match.line(), v.get("direction"), tf_bool(v.get("disabled")),
                              match.get("src_ip_ranges"), allows, others)
    elif GCP_IAM.match(t):
        members = [v.get("member")] if v.get("member") is not None else aslist(v.get("members"))
        # Every member must be a Google-managed agent; a templated single member
        # (service-${number}@gcp-sa-...) is judged on its raw text, unless the
        # raw expression branches or combines multiple values.
        raw = (v.raw("member") or "") if hasattr(v, "raw") and v.get("member") is not None else ""
        if not raw and hasattr(v, "raw"):
            # members = ["serviceAccount:service-${...}@gcp-sa-...."]: one templated member, read the same way.
            one = re.fullmatch(r'\s*\[\s*("[^"]*")\s*,?\s*\]\s*', v.raw("members") or "")
            raw = one.group(1) if one else ""
        if members == [UNKNOWN] and raw.strip() in ("each.value", "each.key"):
            fe = v.get("for_each")
            if isinstance(fe, (list, dict)):
                members = [m if isinstance(m, str) else UNKNOWN for m in each_values(fe, raw)] or members
        raw_single_template = (
            bool(raw) and not any(c in raw for c in "?,[") and " for " not in raw and raw.count('"') <= 2
            and bool(SERVICE_AGENT.search(raw))
        )
        agents = bool(members) and all(
            (isinstance(m, str) and SERVICE_AGENT.search(m)) or (m is UNKNOWN and raw_single_template)
            for m in members)
        role = v.get("role")
        role_raw = (v.raw("role") or "").strip()
        each = role is UNKNOWN and role_raw in ("each.value", "each.key")
        roles = [r for r in each_values(v.get("for_each"), role_raw) if isinstance(r, str)] if each else []
        # for_each = toset(["roles/owner", ...]) with role = each.value, as the iam modules write it.
        for role in roles or [role]:
            scan.gcp_iam(res, role, members, v.line("role"), service_agent=agents, raw=raw)
    elif GCP_IAM_POLICY.match(t):
        source = re.fullmatch(r"\s*data\.google_iam_policy\.([\w-]+)\.policy_data\s*", v.raw("policy_data") or "")
        # A data "google_iam_policy" only builds JSON; its bindings take effect,
        # and are checked, where a policy resource applies it.
        for role, members, line in scan.gcp_policy_data.get((res.dir, source.group(1)), []) if source else []:
            scan.gcp_iam(res, role, members, line)
        data = v.get("policy_data")
        if isinstance(data, str):
            try:
                data = json.loads(data, object_pairs_hook=unique_object)
            except ValueError:
                data = None
        if isinstance(data, dict) and isinstance(data.get("bindings"), list):
            for b in data["bindings"]:
                if isinstance(b, dict):
                    scan.gcp_iam(res, b.get("role"), aslist(b.get("members")), v.line("policy_data"))
    elif t == "google_service_account_key":
        scan.hit("GCP-IAM-003", res, res.line, "google_service_account_key resource")
    elif t == "google_storage_bucket":
        gaps = []
        if tf_bool(v.get("uniform_bucket_level_access")) in (False, None) and \
                not org_policy_enforced(scan, "storage.uniformBucketLevelAccess", res):
            gaps.append("uniform_bucket_level_access not true")
        pap = v.get("public_access_prevention")
        # "inherited" (the default) is enforced when the org policy in the inputs enforces it.
        inherited = pap in (None, "inherited") and org_policy_enforced(scan, "storage.publicAccessPrevention", res)
        if not inherited and (pap is None or (isinstance(pap, str) and pap != "enforced")):
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
    elif t in ("google_compute_instance", "google_compute_instance_template",
               "google_compute_region_instance_template", "google_compute_instance_from_template"):
        for sa in v.blocks("service_account"):
            if default_service_account(sa.get("email"), sa.raw("email")):
                scopes = lower_strs(aslist(sa.get("scopes")))
                full = any(s.endswith("cloud-platform") for s in scopes)
                scan.hit("GCP-GCE-001", res, sa.line(),
                         "default compute service account" + (" with cloud-platform scope" if full else ""))
        gce_metadata(scan, res, v.get("metadata"), v.line("metadata"))
    elif t == "google_compute_project_metadata":
        # Project metadata applies to every VM in the project.
        gce_metadata(scan, res, v.get("metadata"), v.line("metadata"))
    elif t == "google_compute_project_metadata_item":
        if isinstance(v.get("key"), str) and isinstance(v.get("value"), str):
            gce_metadata(scan, res, {v.get("key"): v.get("value")}, v.line("value"))
    elif t == "google_container_node_pool":
        gke_node_config(scan, res, v.blocks("node_config"))
    elif t == "google_container_cluster":
        if tf_bool(v.get("enable_legacy_abac")) is True:
            scan.hit("GCP-GKE-001", res, v.line("enable_legacy_abac"), "enable_legacy_abac = true", "High")
        # The cluster's node_config describes its default pool, deleted when removed.
        # The provider requires initial_node_count when no node_pool is inline,
        # so a set count with no node_config is a default pool on the default account.
        removed = tf_bool(v.get("remove_default_node_pool"))
        if tf_bool(v.get("enable_autopilot")) is not True and removed is not True:
            configs = v.blocks("node_config")
            if not configs and v.get("initial_node_count") is not None and not v.blocks("node_pool"):
                if removed is UNKNOWN:
                    line = v.line("remove_default_node_pool")
                    scan.not_run.append("GCP-GKE-001: unknown remove_default_node_pool; default pool check not run: "
                                        f"{getattr(line, 'file', res.file)}:{line} ({res.address})")
                else:
                    scan.hit("GCP-GCE-001", res, v.line("initial_node_count"),
                             "GKE default node pool as the default compute service account")
            gke_node_config(scan, res, configs)
        for pool in v.blocks("node_pool"):
            if not pool.blocks("node_config"):
                scan.hit("GCP-GCE-001", res, pool.line(), "GKE node pool as the default compute service account")
            gke_node_config(scan, res, pool.blocks("node_config"))
        for auth in v.blocks("master_auth"):
            for cert in auth.blocks("client_certificate_config"):
                if tf_bool(cert.get("issue_client_certificate")) is True:
                    scan.hit("GCP-GKE-001", res, cert.line("issue_client_certificate"),
                             "issue_client_certificate = true (static client certificate credential)")
        private = v.blocks("private_cluster_config")
        private_endpoint = tf_bool(private[0].get("enable_private_endpoint")) if private else None
        authorized = v.blocks("master_authorized_networks_config")
        ip_endpoints = [ip for cfg in v.blocks("control_plane_endpoints_config")
                        for ip in cfg.blocks("ip_endpoints_config")]
        ip_states = [tf_bool(ip.get("enabled")) for ip in ip_endpoints]
        if ip_endpoints and all(state is False for state in ip_states):
            pass  # DNS-based endpoint only: no IP endpoint to authorize networks for
        elif not authorized and ip_endpoints and all(state in (False, UNKNOWN) for state in ip_states):
            line = ip_endpoints[0].line("enabled")
            scan.not_run.append("GCP-GKE-001: unknown ip_endpoints_config.enabled and no authorized networks; "
                                f"check not run: {getattr(line, 'file', res.file)}:{line} ({res.address})")
        elif not authorized and private_endpoint is UNKNOWN and private[0].known_present:
            line = private[0].line("enable_private_endpoint")
            scan.not_run.append("GCP-GKE-001: unknown enable_private_endpoint and no authorized networks; check "
                                f"not run: {getattr(line, 'file', res.file)}:{line} ({res.address})")
        elif not authorized and private_endpoint in (False, None):
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
        cond = v.get("attribute_condition")
        vacuous = cond is None or (
            isinstance(cond, str) and re.sub(r"\s+", " ", cond.strip().lower()) in ("", "true", "1 == 1", "true == true"))
        if vacuous and any(p.known_present for p in v.blocks("oidc")):
            scan.hit("GCP-WIF-001", res, res.line, "OIDC provider without attribute_condition")
        elif vacuous and any(p.known_present for p in v.blocks("aws")):
            # Bound to one AWS account: reaching it needs a workload in that account.
            scan.hit("GCP-WIF-001", res, res.line,
                     "AWS provider without attribute_condition: every role in the account is accepted", "Medium")


# ---------------------------------------------------------------- file handlers

def find_line(text, pattern, default=1):
    m = re.search(pattern, text)
    return text.count("\n", 0, m.start()) + 1 if m else default


def line_numbers(text, positions):
    """1-based line of each ascending offset, counting newlines once."""
    line, last = 1, 0
    for pos in positions:
        line += text.count("\n", last, pos)
        last = pos
        yield line


GIT_SOURCE = re.compile(r"^(git::|git@|github\.com/|bitbucket\.org/)|\.git(//|$|\?)")
REGISTRY_SOURCE = re.compile(r"^([A-Za-z0-9.-]+(?:\.[a-z]+|:[0-9]+)/)?[A-Za-z0-9_-]+/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+"
                             r"(//[^?]+)?$")
PINNED_REF = re.compile(r"[0-9a-f]{7,40}|v?[0-9]+(?:\.[0-9]+){1,2}(?:[-+][0-9A-Za-z.-]+)?")
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
        try:
            alias = HclView(block).get("alias") if block.type == "provider" else None
        except RecursionError:
            alias = UNKNOWN
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


def block_text(block):
    """Every raw argument of a block and its nested blocks, for reference lookups."""
    parts = [f"{key} = {raw}" for key, (raw, _) in block.attrs.items()]
    parts += [f"{child.type} {{\n{block_text(child)}\n}}" for child in block.blocks]
    return "\n".join(parts)


def provider_key(view):
    """The provider configuration a resource uses: "default" or an alias such as
    "aws.west". provider = aws names the default configuration, as omitting it does."""
    raw = view.raw("provider") if hasattr(view, "raw") else None
    raw = raw.strip().strip('"') if raw else ""
    return raw if "." in raw else "default"


def collect_context(scan, d, type_, view, text, defaults=True):
    """Settings elsewhere in the inputs that change what an omitted argument means.

    Account defaults are per account and region, so they are keyed by module
    directory and provider configuration; defaults=False when that cannot be told.
    A resource that is never created (count = 0, empty for_each) sets nothing.
    """
    if never_created(view):
        return
    if type_ == "google_project" and isinstance(view.get("project_id"), str):
        if isinstance(view.get("folder_id"), str):
            scan.project_folders[view.get("project_id")] = view.get("folder_id").removeprefix("folders/")
        if isinstance(view.get("org_id"), (str, int)) and not isinstance(view.get("org_id"), bool):
            scan.project_orgs[view.get("project_id")] = str(view.get("org_id")).removeprefix("organizations/")
    if type_ in ("aws_s3_bucket_public_access_block", "aws_s3_account_public_access_block") and \
            surely_created(view):
        # The account block applies per account: keyed by provider, and not
        # at all when a plan cannot tie resources to providers. A block that
        # may not be created (unknown count or for_each) neutralises nothing.
        account = type_ == "aws_s3_account_public_access_block"
        key = ("*", provider_key(view)) if account else bucket_key(view)
        on = {f for f in ("ignore_public_acls", "restrict_public_buckets") if tf_bool(view.get(f)) is True}
        if key and on and (defaults or not account):
            scan.s3_blocks.setdefault((d, key), set()).update(on)
    if type_ == "aws_s3_bucket_ownership_controls" and surely_created(view) and any(
            rule.get("object_ownership") == "BucketOwnerEnforced" for rule in view.blocks("rule")):
        # ACLs are disabled: a public ACL is refused (AccessControlListNotSupported).
        key = bucket_key(view)
        if key:
            scan.s3_blocks.setdefault((d, key), set()).add("BucketOwnerEnforced")
    if type_ == "aws_ec2_instance_metadata_defaults" and surely_created(view) and \
            view.get("http_tokens") == "required" and defaults:
        scan.imds_required_dirs.add((d, provider_key(view)))
    elif type_ == "aws_ebs_encryption_by_default" and surely_created(view) and \
            tf_bool(view.get("enabled")) in (True, None) and defaults:
        scan.ebs_default_dirs.add((d, provider_key(view)))
    elif type_ in ("google_org_policy_policy", "google_organization_policy", "google_folder_organization_policy",
                   "google_project_organization_policy") and surely_created(view):
        # A dry-run spec is not enforced.
        enforced = without_block(text, "dry_run_spec")
        for constraint in ("storage.publicAccessPrevention", "storage.uniformBucketLevelAccess"):
            if constraint not in enforced or not re.search(r'\benforce(?:d)?"?\s*[:=]\s*"?(?:TRUE|true)"?', enforced) \
                    or re.search(r'\bcondition\s*\{|"condition"\s*:\s*\[\s*\{', enforced):
                continue
            # Only an unconditional rule enforces for every bucket. An organization or
            # folder policy covers the buckets of projects a google_project places
            # there; a project policy covers the buckets of that project in its module.
            org = re.search(r'(?:parent|org_id)"?\s*[:=]\s*"(?:organizations/)?([0-9]+)"', enforced)
            org_level = type_ == "google_organization_policy" or (
                type_ == "google_org_policy_policy" and re.search(r'parent"?\s*[:=]\s*"organizations/', enforced))
            folder = re.search(r'(?:\bfolder"?\s*[:=]\s*"|parent"?\s*[:=]\s*")folders/([0-9]+)"', enforced)
            policies = scan.gcs_org_policies.setdefault(constraint, {"orgs": set(), "dirs": set(), "folders": set()})
            if org_level and org:
                policies["orgs"].add(org.group(1))
            elif folder or type_ == "google_folder_organization_policy":
                # A folder policy covers only projects shown to be in that folder.
                if folder:
                    policies["folders"].add(folder.group(1))
            elif not org_level:
                policies["dirs"].add((d, project_scope(view, "parent" if type_ == "google_org_policy_policy"
                                                       else "project")))
    if type_ in ("aws_iam_role", "aws_iam_user"):
        for m in re.finditer(r"aws_iam_policy\.([\w-]+)", text_of(view, "permissions_boundary")):
            scan.boundary_policies.add((d, f"aws_iam_policy.{m.group(1)}"))


def collect_policy_references(scan, d, block):
    """Any reference to aws_iam_policy.X other than permissions_boundary may attach it
    (policy_arn, for_each maps, locals, module arguments, outputs a caller attaches)."""
    def walk(b):
        for key, (raw, _) in b.attrs.items():
            if key != "permissions_boundary":
                for m in re.finditer(r"aws_iam_policy\.([\w-]+)", raw):
                    scan.attached_policies.add((d, f"aws_iam_policy.{m.group(1)}"))
        for child in b.blocks:
            walk(child)
    walk(block)


def text_of(view, attr):
    raw = view.raw(attr) if hasattr(view, "raw") else None
    return raw or ""


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
        for b in blocks:
            if b.type in ("resource", "data") and len(b.labels) == 2 and \
                    b.labels[0] == "aws_iam_openid_connect_provider":
                try:
                    url = HclView(b).get("url")
                except RecursionError:
                    continue
                if isinstance(url, str) and github_claim(url.rstrip("/") + ":") == "":
                    address = ("data." if b.type == "data" else "") + ".".join(b.labels)
                    scan.github_providers.setdefault(str(Path(rel).parent), set()).add(address)
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
            if b.type == "data" and len(b.labels) == 2 and b.labels[0] == "google_iam_policy":
                try:
                    scan.gcp_policy_data[(d, b.labels[1])] = [
                        (binding.get("role"), aslist(binding.get("members")), _HclLine(binding.line(), rel))
                        for binding in HclView(b).blocks("binding")]
                except RecursionError:
                    scan.not_run.append(f"Terraform expression nested too deeply; checks not run: "
                                        f"{getattr(b.line, 'file', rel)}:{b.line}")
            if b.type == "data" and len(b.labels) == 2 and b.labels[0] == "aws_iam_policy":
                try:
                    view = HclView(b)
                    if view.get("name") == "AdministratorAccess" or (
                            isinstance(view.get("arn"), str) and ADMIN_ARN.search(view.get("arn"))):
                        scan.admin_policy_data.add((d, b.labels[1]))
                except RecursionError:
                    scan.not_run.append(f"Terraform expression nested too deeply; checks not run: "
                                        f"{getattr(b.line, 'file', rel)}:{b.line}")
            if b.type == "data" and len(b.labels) == 2 and b.labels[0] == "aws_iam_policy_document":
                try:
                    statements = doc_statements(view_of(b, rel), scan.github_providers.get(d, frozenset()))
                except RecursionError:
                    statements = UNKNOWN
                scan.policy_docs[(d, b.labels[1])] = statements
                if statements is UNKNOWN:
                    scan.not_run.append("IAM policy composition not evaluated; final document unknown: "
                                        f"data.aws_iam_policy_document.{b.labels[1]} at {rel}:{b.line}")
    for rel, blocks in parsed:
        for b in blocks:
            try:
                if b.type == "resource" and len(b.labels) == 2 and b not in uncertain:
                    b_view = HclView(b)
                    collect_context(scan, str(Path(rel).parent), b.labels[0], b_view, block_text(b))
                    if b.labels[0] == "aws_s3_bucket" and isinstance(b_view.get("bucket"), str):
                        d, address = str(Path(rel).parent), f"aws_s3_bucket.{b.labels[1]}"
                        scan.bucket_aliases[(d, b_view.get("bucket"))] = address
                        scan.bucket_aliases[(d, address)] = b_view.get("bucket")
                    if b.labels[0] == "aws_launch_template" and not never_created(b_view):
                        scan.launch_templates.add((str(Path(rel).parent), b.labels[1]))
                    if b.labels[0] in VPC_DOMAIN_TYPES and b_view.blocks("vpc_options"):
                        scan.vpc_domains.add((str(Path(rel).parent), ".".join(b.labels)))
                        add_vpc_domain_name(scan, str(Path(rel).parent), b_view)
                collect_policy_references(scan, str(Path(rel).parent), b)
            except RecursionError:
                pass  # reported once by the checks below
    declared = {}
    for rel, blocks in parsed:
        d = str(Path(rel).parent)
        info = scan.tf_dirs.setdefault(d, {"resources": False, "backend": False, "file": rel})
        for b in blocks:
            try:
                check_block(scan, rel, d, b, view_of(b, rel), info, declared, uncertain)
            except RecursionError:
                scan.not_run.append(f"Terraform expression nested too deeply; checks not run: "
                                    f"{getattr(b.line, 'file', rel)}:{b.line}")


def check_block(scan, rel, d, b, view, info, declared, uncertain):
    """Inventory and rules for one top-level block."""
    if b.type in ("resource", "data") and len(b.labels) == 2:
        # Terraform refuses a module that declares one address twice;
        # the scanner reads both, so say the module is not valid as given.
        key = (d, b.type, *b.labels)
        if key in declared:
            address = ".".join(b.labels if b.type == "resource" else ["data", *b.labels])
            scan.not_run.append(f"duplicate declaration of {address} in one module (Terraform would "
                                f"reject it): {declared[key]} and {rel}:{b.line}")
        else:
            declared[key] = f"{rel}:{b.line}"
    if b.type == "resource" and len(b.labels) == 2:
        res = Res(b.labels[0], f"{b.labels[0]}.{b.labels[1]}", rel, b.line, view, d)
        scan.add_resource(res)
        info["resources"] = True
        if b not in uncertain and not never_created(view):
            check_tf(scan, res)
    elif b.type == "module" and b.labels:
        info["resources"] = True  # a root that only calls modules still holds state
        handle_module(scan, rel, b, view)
    elif b.type == "provider" and b.labels and b not in uncertain and not local_emulator(b, view):
        for key in ("access_key", "secret_key", "token", "credentials", "access_token",
                    "client_secret", "client_certificate_password"):
            # AWS keys in a provider block are flagged in any form.
            # Other providers often take short-lived tokens from data sources
            # (kubernetes token = data.aws_eks_cluster_auth.x.token); flag only
            # a literal value or a key file read from the repository.
            if key in b.attrs and key not in ("access_key", "secret_key") and not (
                    isinstance(view.get(key), str) or re.search(r"\bfile\(", b.attrs[key][0])):
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


def local_emulator(block, view):
    """A provider pointed at LocalStack or another local emulator takes dummy keys."""
    return tf_bool(view.get("skip_credentials_validation")) is True and \
        re.search(r"localhost|127\.0\.0\.1|localstack", block_text(block)) is not None


def surely_created(view):
    """No count or for_each, a literal count of at least one, or a non-empty literal for_each."""
    count, for_each = view.get("count"), view.get("for_each")
    if count is not None:
        return (to_int(count) or 0) >= 1
    if for_each is not None:
        return isinstance(for_each, (dict, list)) and bool(for_each) and not holds_unknown(for_each)
    return True


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


def handle_terragrunt(scan, rel, text):
    """terraform { source = ... } pins the module the same way a module block does,
    and remote_state configures the state backend. Literal locals in the same
    file are substituted into source ("${local.base_source_url}?ref=v1.2.0")."""
    try:
        blocks = parse_hcl(text)
        locals_ = {}
        for b in blocks:
            if b.type == "locals":
                view = HclView(b)
                locals_.update({name: value for name in b.attrs if isinstance(value := view.get(name), str)})
        for b in blocks:
            view = HclView(b)
            if b.type == "remote_state" and view.get("backend") == "s3" and isinstance(view.get("config"), dict):
                config = view.get("config")
                encrypt = tf_bool(config.get("encrypt"))
                if encrypt is False or (encrypt is None and "encrypt" not in config and
                                        config.get("kms_key_id") in (None, "")):
                    scan.hit("PS-002", Res("backend", "terragrunt.remote_state.s3", rel, b.line), view.line("config"),
                             "Terragrunt s3 remote_state without encrypt = true; relies on bucket default encryption",
                             "Low")
            if b.type != "terraform":
                continue
            source = view.get("source")
            raw = view.raw("source")
            if source is UNKNOWN and raw and raw.startswith('"') and raw.endswith('"'):
                substituted = re.sub(r"\$\{\s*local\.(\w+)\s*\}",
                                     lambda m: locals_.get(m.group(1), m.group()), raw[1:-1])
                source = substituted if "${" not in substituted else UNKNOWN
            if not isinstance(source, str) or not GIT_SOURCE.search(source):
                continue
            res = Res("terragrunt", f"terragrunt:{rel}", rel, b.line)
            m = re.search(r"[?&]ref=([^&]+)", source)
            if not m:
                scan.hit("PS-001", res, view.line("source"), "git source without ?ref=")
            elif not PINNED_REF.fullmatch(m.group(1)):
                scan.hit("PS-001", res, view.line("source"), f"ref={m.group(1)} is not a commit or version tag")
    except RecursionError:
        scan.not_run.append(f"HCL nested too deeply, skipped: {rel}")


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
            # S3 encrypts new objects (SSE-S3) by default since 2023: without
            # encrypt the state relies on the bucket's settings, which are not here.
            scan.hit("PS-002", res, block.line, "s3 backend without encrypt = true; relies on bucket default "
                     "encryption", "Low")
    elif kind == "local" and PROD_DIR.search(rel):
        scan.hit("PS-002", res, block.line, "local state for a production directory", "Low")


def backend_config_encrypts(scan, rel):
    """A sibling *.tfbackend or backend*.hcl file that sets encrypt = true."""
    directory = Path(scan.root) / Path(rel).parent
    try:
        candidates = sorted(p for p in directory.iterdir()
                            if p.is_file() and not p.is_symlink() and p.stat().st_size <= MAX_BYTES and
                            (p.name.endswith(".tfbackend") or re.fullmatch(r"backend.*\.hcl", p.name)))
        # Every config that sets encrypt must enable it: prod.tfbackend may differ from dev.
        settings = []
        for path in candidates:
            for line in path.read_text(encoding="utf-8-sig").splitlines():
                m = re.match(r'\s*encrypt\s*=\s*"?(true|false)"?\s*(?:#.*)?$', line)
                if m:
                    settings.append(m.group(1) == "true")
    except (OSError, UnicodeError):
        return False
    return bool(settings) and all(settings)


def _safe_terragrunt_include(base_dir, rel_path, root):
    raw_cand = base_dir / rel_path
    cur = raw_cand
    while cur != base_dir and cur != root and cur != cur.parent:
        if cur.is_symlink():
            return None
        cur = cur.parent
    if raw_cand.is_symlink():
        return None
    resolved = raw_cand.resolve()
    if resolved == root or root in resolved.parents:
        return resolved
    return None


def terragrunt_remote_state(scan, d):
    """Terragrunt writes the backend at run time, from remote_state or generate
    "backend" in the unit's terragrunt.hcl (here or above, within the scanned
    tree) or in a file that unit includes: find_in_parent_folders("root.hcl"),
    find_in_parent_folders() or a literal include path. Other .hcl files are not
    loaded and establish nothing."""
    root = Path(scan.root).resolve()
    here = (root / d).resolve()
    chain = [p for p in (here, *here.parents) if p == root or root in p.parents]
    try:
        unit = next((p / "terragrunt.hcl" for p in chain if (p / "terragrunt.hcl").is_file()), None)
        if unit is None or unit.is_symlink() or unit.stat().st_size > MAX_BYTES:
            return False
        text = unit.read_text(encoding="utf-8-sig")
        if terragrunt_backend(text):
            return True
        # Only include blocks inherit configuration; read_terragrunt_config in locals does not.
        code = hcl_code(text)
        includes = "\n".join(m.group() for m in re.finditer(r'^\s*include\b[^{\n]*\{[^}]*\}', code, re.M))
        names = set(re.findall(r'find_in_parent_folders\(\s*"([^"/]+)"\s*\)', includes))
        if re.search(r"find_in_parent_folders\(\s*\)", includes):
            names.add("terragrunt.hcl")  # the no-argument form finds terragrunt.hcl only
        candidates = [p / name for p in unit.parent.parents if p == root or root in p.parents for name in names]
        for m in re.findall(r'\bpath\s*=\s*"([^"$]+\.hcl)"', includes):
            safe_cand = _safe_terragrunt_include(unit.parent, m, root)
            if safe_cand is not None:
                candidates.append(safe_cand)
        for candidate in candidates:
            if (candidate == root or root in candidate.parents) and candidate.is_file() and \
                    not candidate.is_symlink() and candidate.stat().st_size <= MAX_BYTES and \
                    terragrunt_backend(candidate.read_text(encoding="utf-8-sig")):
                return True
    except (OSError, UnicodeError):
        return False
    return False


HEREDOC_START = re.compile(r"<<-?([A-Za-z_]\w*)\s*$")


def hcl_code(text, heredocs=False, strings=True):
    """HCL text without comments (#, //, /* */) and, unless heredocs is set, without
    heredoc bodies; quoted strings are kept (or emptied to "" without strings), and
    so is the line count. One linear pass, so hostile input cannot make it slow."""
    out, tag, in_block = [], None, False
    for line in text.split("\n"):
        if tag is not None:
            if line.strip() == tag:
                tag = None
            out.append(line if heredocs else "")
            continue
        kept, i, n = [], 0, len(line)
        while i < n:
            if in_block:
                close = line.find("*/", i)
                if close == -1:
                    i = n
                    break
                in_block, i = False, close + 2
                continue
            c = line[i]
            if c == '"':
                j = i + 1
                while j < n and line[j] != '"':
                    j += 2 if line[j] == "\\" else 1
                kept.append(line[i:j + 1] if strings else '""')
                i = j + 1
            elif c == "#" or line.startswith("//", i):
                break
            elif line.startswith("/*", i):
                in_block, i = True, i + 2
            else:
                kept.append(c)
                i += 1
        code = "".join(kept)
        if (m := HEREDOC_START.search(code)):
            tag = m.group(1)
            if not heredocs:
                code = code[:m.start()] + '""'
        out.append(code)
    return "\n".join(out)


# A backend at the top level: remote_state { ... }, generate "backend" { ... }, or
# remote_state = local.common.remote_state (read_terragrunt_config).
TERRAGRUNT_BACKEND = re.compile(r'\s*(?:remote_state\s*\{|generate\s*"backend"\s*\{|remote_state\s*=(?!=))')


def terragrunt_backend(text):
    """A backend declared outside every block, not inside locals, a heredoc or a comment."""
    depth = 0
    for line, code in zip(hcl_code(text).split("\n"), hcl_code(text, strings=False).split("\n")):
        if depth == 0 and TERRAGRUNT_BACKEND.match(line):
            return True
        depth = max(0, depth + code.count("{") - code.count("}"))
    return False


def finish_dirs(scan):
    for d, info in sorted(scan.tf_dirs.items()):
        # A directory another module calls is a child module, not a root.
        if d in scan.local_module_dirs:
            continue
        if info["resources"] and not info["backend"] and PROD_DIR.search(d + "/") \
                and not terragrunt_remote_state(scan, d):
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
    matches = list(re.finditer(r'"address"\s*:\s*("(?:\\.|[^"\\])*")', text))
    for m, line in zip(matches, line_numbers(text, (m.start() for m in matches))):
        lines.setdefault(json.loads(m.group(1)), line)

    plan_config_refs(scan, rel, doc)
    # planned_values do not say which provider alias a resource uses; with an
    # aliased AWS provider, account defaults cannot be tied to resources.
    providers = (doc.get("configuration") or {}).get("provider_config") if isinstance(
        doc.get("configuration"), dict) else None
    aliased = isinstance(providers, dict) and any(
        isinstance(p, dict) and p.get("name") == "aws" and p.get("alias") for p in providers.values())

    def walk(module, check):
        if not isinstance(module, dict):
            return
        for r in aslist(module.get("resources")):
            if not isinstance(r, dict) or r.get("mode") == "data":
                continue
            address, type_ = r.get("address", ""), r.get("type", "")
            if not isinstance(address, str) or not isinstance(type_, str) or \
                    not isinstance(r.get("values") or {}, dict):
                scan.not_run.append(f"plan resource with an unexpected shape skipped: {rel}")
                continue
            line = lines.get(address, 1)
            mask = unknowns.get(address)
            expressions = configured.get(re.sub(r"\[[^\]]*\]", "", address))
            if isinstance(mask, dict) and isinstance(expressions, dict):
                # An argument the configuration omits is unknown in the plan only
                # because the provider computes its default: it is omitted. A
                # block present in planned values, even empty, may be dynamic
                # (expressions never list dynamic blocks) and keeps its unknowns.
                planned = r.get("values") or {}
                mask = {k: m for k, m in mask.items() if k in expressions or planned.get(k) is not None}
            values = with_plan_unknowns(r.get("values") or {}, mask)
            if not check:
                # First pass: account and org settings that change what omitted arguments mean.
                collect_context(scan, rel, type_, DictView(values, line), json.dumps(values, default=str),
                                defaults=not aliased)
                if type_ in VPC_DOMAIN_TYPES and DictView(values, line).blocks("vpc_options"):
                    add_vpc_domain_name(scan, rel, DictView(values, line))
                continue
            reads = set()
            res = Res(type_, address, rel, line, DictView(values, line, reads), rel)
            scan.add_resource(res)
            check_tf(scan, res)
            if reads:
                scan.not_run.append(f"plan value unknown until apply ({', '.join(sorted(reads))}); affected checks "
                                    f"not run: {address} at {rel}:{line}")
        children = module.get("child_modules")
        for child in children if isinstance(children, list) else []:
            walk(child, check)
    configured = plan_expressions(doc)
    planned = doc.get("planned_values")
    root = planned.get("root_module") if isinstance(planned, dict) else None
    walk(root, False)
    walk(root, True)


def plan_expressions(doc):
    """{address without instance keys: configured expressions} from the plan's configuration."""
    out = {}

    def walk(module, prefix):
        if not isinstance(module, dict):
            return
        for r in module.get("resources", []) if isinstance(module.get("resources"), list) else []:
            if isinstance(r, dict) and isinstance(r.get("address"), str) and isinstance(r.get("expressions"), dict):
                out[prefix + r["address"]] = r["expressions"]
        calls = module.get("module_calls")
        for name, call in calls.items() if isinstance(calls, dict) else ():
            if isinstance(call, dict):
                walk(call.get("module"), f"{prefix}module.{name}.")
    config = doc.get("configuration")
    walk(config.get("root_module") if isinstance(config, dict) else None, "")
    return out


def plan_config_refs(scan, rel, doc):
    """Policy references from the plan's configuration section (values are unknown at plan time).

    As collect_policy_references for HCL: a reference from anything but
    permissions_boundary may attach the policy (policy_arn, a for_each map,
    a module argument, an output a caller attaches)."""
    config = doc.get("configuration")

    def note(value, prefix, boundary=False):
        if isinstance(value, dict):
            refs = value.get("references")
            for ref in refs if isinstance(refs, list) else []:
                m = re.match(r"^(aws_iam_policy\.[\w-]+)", str(ref))
                if m:
                    target = scan.boundary_policies if boundary else scan.attached_policies
                    target.add((rel, prefix + m.group(1)))
                elif str(ref).startswith("local.") and not boundary:
                    scan.plan_local_refs.add((rel, prefix))
            for key, item in value.items():
                if key != "references":
                    note(item, prefix, boundary or key == "permissions_boundary")
        elif isinstance(value, list):
            for item in value:
                note(item, prefix, boundary)

    def walk(module, prefix):
        if not isinstance(module, dict):
            return
        for r in module.get("resources", []) if isinstance(module.get("resources"), list) else []:
            if isinstance(r, dict):
                for key in ("expressions", "for_each_expression", "count_expression"):
                    note(r.get(key), prefix)
        note(module.get("outputs"), prefix)
        calls = module.get("module_calls")
        for name, call in calls.items() if isinstance(calls, dict) else []:
            if isinstance(call, dict):
                # A module's arguments name the caller's resources.
                for key in ("expressions", "for_each_expression", "count_expression"):
                    note(call.get(key), prefix)
                walk(call.get("module"), f"{prefix}module.{name}.")
    walk(config.get("root_module") if isinstance(config, dict) else None, "")


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
                out.setdefault((stack[-1][2], key), line)
                expect_key = False
        elif token in "{[":
            # Each container's path is built once when it opens and shared by
            # its keys: time and memory stay linear in the document.
            path = stack[-1][2] + (stack[-1][1],) if stack else ()
            stack.append(["{", None, path] if token == "{" else ["[", 0, path])
            expect_key = token == "{"
        elif token in "}]":
            stack.pop()
        elif token == "," and stack:
            if stack[-1][0] == "{":
                expect_key = True
            else:
                stack[-1][1] += 1
    return out


def handle_cfn(scan, rel, text, doc, line_of=None):
    """CloudFormation rules; line_of(logical ID) locates a resource (JSON keys by default)."""
    if line_of is None:
        keys = json_key_lines(text)
        line_of = lambda lid: keys.get((("Resources",), lid), 1)  # noqa: E731
    if doc.get("Transform") is not None:
        scan.not_run.append(f"CloudFormation Transform (SAM or macro): rules read the template as written, not the "
                            f"expanded resources; review the transformed template by hand: {rel}")
    globals_ = doc.get("Globals", {}).get("Function") if isinstance(doc.get("Globals"), dict) else None
    scan.cfn_checked_templates[rel] = {
        lid for lid, r in (doc.get("Resources") or {}).items()
        if isinstance(r, dict) and r.get("Type") == "AWS::EC2::LaunchTemplate"
        and isinstance(r.get("Properties"), dict) and isinstance(r["Properties"].get("LaunchTemplateData"), dict)
    }
    cfn_parameter_defaults(scan, rel, text, doc)
    for lid, r in (doc.get("Resources") or {}).items():
        if not isinstance(r, dict):
            continue
        type_ = r.get("Type", "")
        if not isinstance(type_, str):
            scan.not_run.append(f"CloudFormation resource with a non-literal Type skipped: {rel} ({lid})")
            continue
        props = r.get("Properties") or {}
        if not isinstance(props, dict):
            props = {}
        if type_ == "AWS::Serverless::Function" and isinstance(globals_, dict):
            props = sam_merge(globals_, props)  # SAM Globals; a function's own value wins
        line = line_of(lid)
        res = Res(type_, f"cfn:{lid}", rel, line, DictView(props, line))
        scan.add_resource(res, "aws")
        cfn_shared(scan, res, type_, props, line)
        cfn_secrets(scan, res, props, line)
        if type_ == "AWS::EC2::SecurityGroup":
            for rule in aslist(props.get("SecurityGroupIngress")):
                if intrinsic_only(rule) or rule is UNKNOWN:
                    # - !If [IsDev, {...0.0.0.0/0...}, !Ref AWS::NoValue]: a rule in some deployments.
                    scan.not_run.append(f"AWS-NET-001: ingress rule is not a literal; check not run: "
                                        f"{res.file}:{line} ({res.address})")
                elif isinstance(rule, dict):
                    cfn_ingress(scan, res, rule)
        elif type_ == "AWS::EC2::SecurityGroupIngress":
            cfn_ingress(scan, res, props)
        elif type_ == "AWS::S3::Bucket":
            if props.get("AccessControl") in ("PublicRead", "PublicReadWrite", "AuthenticatedRead"):
                scan.hit("AWS-S3-001", res, line, f"AccessControl = {props['AccessControl']}")
            pab = props.get("PublicAccessBlockConfiguration")
            if is_intrinsic(pab):
                # The whole block comes from Fn::If or a Ref: its flags are not in the template.
                scan.not_run.append(f"AWS-S3-002: PublicAccessBlockConfiguration is not a literal; check not run: "
                                    f"{res.file}:{line} ({res.address})")
            elif isinstance(pab, dict):
                # Omitted flags default to false, as in Terraform.
                off = [k for k in ("BlockPublicAcls", "BlockPublicPolicy", "IgnorePublicAcls",
                                   "RestrictPublicBuckets") if pab.get(k) in (False, "false", None)]
                if off:
                    scan.hit("AWS-S3-002", res, line, "off: " + ", ".join(off))
        elif type_ == "AWS::S3::BucketPolicy":
            scan.resource_policy(res, cfn_statements(scan, res, props.get("PolicyDocument"), line), line)
        elif type_ in ("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy", "AWS::IAM::RolePolicy",
                       "AWS::IAM::UserPolicy", "AWS::IAM::GroupPolicy"):
            scan.identity_policy(res, cfn_statements(scan, res, props.get("PolicyDocument"), line), line)
        elif type_ == "AWS::IAM::Role":
            scan.trust_policy(res, cfn_statements(scan, res, props.get("AssumeRolePolicyDocument"), line), line)
            for p in aslist(props.get("Policies")):
                if isinstance(p, dict):
                    scan.identity_policy(res, cfn_statements(scan, res, p.get("PolicyDocument"), line), line)
            cfn_admin(scan, res, props, line)
        elif type_ in ("AWS::IAM::User", "AWS::IAM::Group"):
            for p in aslist(props.get("Policies")):
                if isinstance(p, dict):
                    scan.identity_policy(res, cfn_statements(scan, res, p.get("PolicyDocument"), line), line)
            cfn_admin(scan, res, props, line)
        elif type_ == "AWS::SSO::PermissionSet":
            if props.get("InlinePolicy") is not None:
                scan.identity_policy(res, cfn_statements(scan, res, props["InlinePolicy"], line), line)
            cfn_admin(scan, res, props, line, "ManagedPolicies")
        elif type_ == "AWS::IAM::AccessKey":
            scan.hit("AWS-IAM-005", res, line, "access key for an IAM user")
        elif type_ == "AWS::KMS::Key":
            spec = props.get("KeySpec")
            # Imported and custom-key-store material cannot rotate automatically.
            if spec in (None, "SYMMETRIC_DEFAULT") and props.get("Origin") in (None, "AWS_KMS") \
                    and props.get("EnableKeyRotation") in (False, "false", None):
                scan.hit("AWS-KMS-001", res, line, "EnableKeyRotation not true")
        elif type_ == "AWS::CloudTrail::Trail":
            off = [k for k in ("IsMultiRegionTrail", "EnableLogFileValidation")
                   if props.get(k) in (False, "false", None)]
            if off:
                scan.hit("AWS-CT-001", res, line, "not true: " + ", ".join(off))
        elif type_ == "AWS::EC2::Volume":
            if props.get("Encrypted") in (False, "false") or (
                    props.get("Encrypted") is None and "SnapshotId" not in props):
                scan.hit("AWS-EBS-001", res, line, "Encrypted not true")
        elif type_ == "AWS::EKS::Cluster":
            cfg = props.get("ResourcesVpcConfig") if isinstance(props.get("ResourcesVpcConfig"), dict) else {}
            if is_intrinsic(cfg):
                scan.not_run.append(f"AWS-EKS-001: ResourcesVpcConfig is not a literal; check not run: "
                                    f"{res.file}:{line} ({res.address})")
                cfg = {"EndpointPublicAccess": False}
            public = cfg.get("EndpointPublicAccess", True)
            cidrs = cfg.get("PublicAccessCidrs")
            open_from = world_cidrs(["0.0.0.0/0"] if cidrs is None else cidrs)
            if public in (True, "true") and open_from:
                scan.hit("AWS-EKS-001", res, line, f"public endpoint open to {open_from[0]}")
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
        elif type_ == "AWS::Serverless::Function":
            # SAM expands these into Lambda, IAM role and URL resources.
            url = props.get("FunctionUrlConfig")
            if isinstance(url, dict) and url.get("AuthType") == "NONE":
                scan.hit("AWS-LAMBDA-001", res, line, "FunctionUrlConfig.AuthType = NONE")
            if "Role" not in props:
                policies = aslist(props.get("Policies"))
                for p in policies:
                    if isinstance(p, dict) and "Statement" in p:
                        scan.identity_policy(res, cfn_statements(scan, res, p, line), line)
                # A bare name is a managed policy in the aws partition.
                if any(p == "AdministratorAccess" or (isinstance(cfn_string(p), str) and ADMIN_ARN.search(cfn_string(p)))
                       for p in policies):
                    scan.hit("AWS-IAM-001", res, line, "AdministratorAccess attached")
        elif type_ in ("AWS::EC2::LaunchTemplate", "AWS::EC2::Instance"):
            cfn_instance(scan, res, type_, props, line)
        elif type_ == "AWS::Lambda::Url":
            if props.get("AuthType") == "NONE":
                scan.hit("AWS-LAMBDA-001", res, line, "AuthType = NONE")
        elif type_ == "AWS::Lambda::Permission":
            if props.get("Principal") == "*" and not any(
                    props.get(k) not in (None, "", {}) for k in ("SourceArn", "SourceAccount", "PrincipalOrgID")):
                scan.hit("AWS-LAMBDA-002", res, line, "Principal = * without a source condition")


def cfn_shared(scan, res, type_, props, line):
    """CloudFormation counterparts of check_tf_shared."""
    key = CFN_RESOURCE_POLICIES.get(type_)
    if key and props.get(key) is not None and not (type_.endswith("::Domain") and props.get("VPCOptions")):
        scan.resource_policy(res, cfn_statements(scan, res, props[key], line), line)
    if type_ in CFN_PUBLIC_DATA and props.get("PubliclyAccessible") in (True, "true"):
        scan.hit("AWS-RDS-001", res, line, "PubliclyAccessible = true")
    if type_ == "AWS::CloudFront::Distribution":
        config = props.get("DistributionConfig") if isinstance(props.get("DistributionConfig"), dict) else {}
        behaviors = [config.get("DefaultCacheBehavior"), *aslist(config.get("CacheBehaviors"))]
        if any(isinstance(b, dict) and b.get("ViewerProtocolPolicy") == "allow-all" for b in behaviors):
            scan.hit("AWS-CF-001", res, line, "ViewerProtocolPolicy = allow-all")
        cert = config.get("ViewerCertificate") if isinstance(config.get("ViewerCertificate"), dict) else {}
        if cert.get("MinimumProtocolVersion") in OLD_TLS and cert.get("CloudFrontDefaultCertificate") not in (True, "true"):
            scan.hit("AWS-CF-001", res, line, f"MinimumProtocolVersion = {cert['MinimumProtocolVersion']}")


def intrinsic_only(value):
    """A value that is wholly an intrinsic call: a one-key object such as {"Fn::If": ...}.
    A policy statement's "Condition" key does not make the statement one."""
    return isinstance(value, dict) and len(value) == 1 and is_intrinsic(value)


def is_intrinsic(value):
    """A CloudFormation value computed by an intrinsic function ({"Fn::If": ...}, {"Ref": ...})."""
    return isinstance(value, dict) and any(isinstance(k, str) and (k.startswith("Fn::") or k in ("Ref", "Condition"))
                                           for k in value)


def sam_merge(inherited, own):
    """SAM's Globals merge: maps merge key by key (recursively), lists keep the
    global entries first, and otherwise the function's value wins."""
    out = dict(inherited)
    for key, value in own.items():
        if isinstance(out.get(key), dict) and isinstance(value, dict):
            out[key] = sam_merge(out[key], value)
        elif isinstance(out.get(key), list) and isinstance(value, list):
            out[key] = out[key] + value
        else:
            out[key] = value
    return out


def cfn_instance(scan, res, type_, props, line):
    """AWS-EC2-001 and AWS-EBS-001 for launch templates and instances."""
    data = props.get("LaunchTemplateData") if type_ == "AWS::EC2::LaunchTemplate" else props
    if not isinstance(data, dict):
        return
    if type_ == "AWS::EC2::LaunchTemplate" and is_intrinsic(data):
        scan.not_run.append(f"AWS-EC2-001, AWS-EBS-001: LaunchTemplateData is not a literal; checks not run: "
                            f"{res.file}:{line} ({res.address})")
        return
    for mapping in aslist(data.get("BlockDeviceMappings")):
        ebs = mapping.get("Ebs") if isinstance(mapping, dict) else None
        if isinstance(ebs, dict) and ebs.get("Encrypted") in (False, "false"):
            scan.hit("AWS-EBS-001", res, line, "BlockDeviceMappings Ebs.Encrypted = false")
    opts = props.get("MetadataOptions") if type_ == "AWS::EC2::Instance" else data.get("MetadataOptions")
    if is_intrinsic(opts):
        # The whole options map comes from an intrinsic (Fn::If ...): unresolved.
        scan.not_run.append(f"AWS-EC2-001: MetadataOptions is not a literal; check not run: {res.file}:{line} "
                            f"({res.address})")
        return
    if type_ == "AWS::EC2::Instance" and not isinstance(props.get("MetadataOptions"), dict):
        # Without its own MetadataOptions an instance takes them from a launch template.
        template = props.get("LaunchTemplate")
        ref = template.get("LaunchTemplateId") if isinstance(template, dict) else None
        if isinstance(ref, dict) and isinstance(ref.get("Ref"), str) and \
                ref["Ref"] in scan.cfn_checked_templates.get(res.file, ()):
            pass  # a launch template in this template, checked on its own
        elif "LaunchTemplate" in props:
            scan.not_run.append("AWS-EC2-001: metadata options come from a launch template; check the "
                                f"template: {res.file}:{line} ({res.address})")
        else:
            scan.hit("AWS-EC2-001", res, line, "IMDSv2 not enforced by the template (no launch template with "
                     "MetadataOptions; depends on the AMI's ImdsSupport or the account default)")
        return
    opts = data.get("MetadataOptions")
    if not isinstance(opts, dict):
        scan.hit("AWS-EC2-001", res, line, "no MetadataOptions; IMDSv1 allowed")
    elif opts.get("HttpEndpoint") != "disabled" and opts.get("HttpTokens") != "required":
        unresolved = [k for k in ("HttpEndpoint", "HttpTokens") if isinstance(opts.get(k), (dict, list))]
        if unresolved:
            scan.not_run.append(f"AWS-EC2-001: {' and '.join(unresolved)} not a literal; check not run: "
                                f"{res.file}:{line} ({res.address})")
        else:
            scan.hit("AWS-EC2-001", res, line, f"HttpTokens = {opts.get('HttpTokens') or 'unset'}")


SECRET_REFERENCE_TYPES = {"PARAMETER_STORE", "SECRETS_MANAGER"}
SECRET_REFERENCE = re.compile(r'(?i)\btype"?\s*[:=]\s*"(?:PARAMETER_STORE|SECRETS_MANAGER)"')
FLAG_VALUE = re.compile(r"(?i)(?:true|false|yes|no|on|off|enabled?|disabled?|[0-9]{1,5})")
# CloudFormation property names (CamelCase) that hold a credential.
CFN_SECRET_KEY = re.compile(
    r"(?i)[A-Za-z0-9_-]*(?:(?:password|passwd|secret|secret_?key|secret_?string|"
    r"secret_?data|secret_?binary|token|api_?key|access_?key|private_?key|client_?key|"
    r"ssh_?key|tls\.key|passphrase|bearer|auth_?token|credentials?|pre_?shared_?key)"
    r"(?:[_-]?(?:prod|dev|staging|test|base|val|value|str|string|data|binary|[0-9]+))?|"
    r"(?<![A-Za-z])(?:pass|pwd|pw)(?![A-Za-z]))")


def literal_secret(value):
    """A CloudFormation string holding a secret. ${...} is literal text outside
    Fn::Sub (an intrinsic, so a dict here), so it does not exempt the value."""
    return isinstance(value, str) and not value.startswith(("{{resolve:secretsmanager:", "{{resolve:ssm-secure:")) and \
        not PLACEHOLDER.match(value.strip()) and not FLAG_VALUE.fullmatch(value.strip())


def cfn_parameter_defaults(scan, rel, text, doc):
    """SEC-001 for a literal Default of a secret-named parameter: NoEcho
    hides the value in the console, not in the repository."""
    params = doc.get("Parameters")
    if not isinstance(params, dict):
        return
    for name, param in params.items():
        if isinstance(name, str) and isinstance(param, dict) and CFN_SECRET_KEY.fullmatch(name) \
                and literal_secret(param.get("Default")):
            if isinstance(getattr(params, "lines", None), dict):
                line = params.lines.get(name, 1)  # parsed YAML carries its lines; text is None
            else:
                # The key under Parameters, not the same name earlier in the text
                # (Metadata ParameterLabels) or the first line of minified JSON.
                line = json_key_lines(text or "").get((("Parameters",), name), 1)
            scan.hit("SEC-001", Res("file", rel, rel, 1), line, f"literal default for parameter {name}")


def cfn_secrets(scan, res, props, line):
    """SEC-001 for literal strings under secret-named properties or Name/Value pairs."""

    found = []
    stack = [props]
    while stack:
        item = stack.pop()
        if isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            keys = {k.lower(): k for k in item if isinstance(k, str)}
            # CodeBuild variables of type PARAMETER_STORE / SECRETS_MANAGER hold a reference.
            reference = str(item.get(keys.get("type", ""), "")).upper() in SECRET_REFERENCE_TYPES
            for nk, vk in (("name", "value"), ("parameterkey", "parametervalue")):
                name = item.get(keys.get(nk, ""))
                if vk in keys and isinstance(name, str) and CFN_SECRET_KEY.fullmatch(name) and not reference \
                        and literal_secret(item[keys[vk]]):
                    found.append(name)
            for key, value in item.items():
                if isinstance(key, str) and CFN_SECRET_KEY.fullmatch(key) and literal_secret(value):
                    found.append(key)
                elif isinstance(value, (dict, list)):
                    stack.append(value)
    for key in sorted(set(found)):
        scan.hit("SEC-001", Res("file", res.file, res.file, 1), line, f"literal value assigned to {key} ({res.address})")


def cfn_admin(scan, res, props, line, key="ManagedPolicyArns"):
    if any(isinstance(cfn_string(a), str) and ADMIN_ARN.search(cfn_string(a))
           for a in aslist(props.get(key))):
        scan.hit("AWS-IAM-001", res, line, "AdministratorAccess attached")


def cfn_statements(scan, res, document, line):
    """Statements of a CloudFormation policy document: an object, or a JSON string
    (Json-typed properties accept both). A document or statement computed by an
    intrinsic (Fn::If, Fn::Sub, a block scalar) is named in not_run, not skipped."""
    if isinstance(document, str):
        try:
            document = json.loads(document, object_pairs_hook=unique_object)
        except ValueError:
            document = UNKNOWN
    listed = document.get("Statement") if isinstance(document, dict) and not intrinsic_only(document) else UNKNOWN
    if isinstance(listed, dict):
        listed = [listed]
    if not isinstance(listed, list) or any(intrinsic_only(st) or not isinstance(st, dict) for st in listed):
        scan.not_run.append(f"policy document or statement is not a literal; policy checks not run on it: "
                            f"{res.file}:{line} ({res.address})")
    return norm_statements(document) if isinstance(document, dict) else None


def cfn_ingress(scan, res, rule):
    def value(key):  # FromPort: !Ref Port is unresolved, as a Terraform unknown is
        return UNKNOWN if is_intrinsic(rule.get(key)) else rule.get(key)
    scan.ingress(res, res.line, [rule.get("CidrIp"), rule.get("CidrIpv6")], value("IpProtocol"),
                 value("FromPort"), value("ToPort"))


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


AWS_EXPORT_KEYS = {
    "SecurityGroups", "Reservations", "Functions", "DBInstances", "DBClusters", "Buckets", "Trails",
    "UserDetailList", "RoleDetailList", "GroupDetailList", "Policies", "Vpcs", "Subnets", "Clusters",
    "Snapshots", "Volumes", "LoadBalancers", "FunctionUrlConfigs", "Distributions", "DistributionList",
    "Users", "Roles", "Groups", "AccessKeyMetadata", "KeyMetadata", "SecretList", "NetworkAcls", "RouteTables",
    # Every top-level shape aws_export reads (describe-trails, get-public-access-block).
    "trailList", "PublicAccessBlockConfiguration",
}


def is_export(doc):
    """Output of a cloud CLI rather than configuration written by hand.

    AWS CLI JSON is an object of CamelCase keys holding lists (SecurityGroups,
    Reservations, Functions); gcloud prints lists of resources with selfLink or a
    "compute#..." kind, and IAM policies with an etag; kubectl prints a List.
    """
    if isinstance(doc, list):
        return bool(doc) and all(isinstance(x, dict) and ("selfLink" in x or "#" in str(x.get("kind", "")))
                                 for x in doc)
    if not isinstance(doc, dict) or not doc:
        return False
    if "Resources" in doc or "AWSTemplateFormatVersion" in doc or "planned_values" in doc:
        return False
    if isinstance(doc.get("bindings"), list) and "etag" in doc:
        return True
    if "selfLink" in doc or "#" in str(doc.get("kind", "")):
        return True  # gcloud ... describe
    meta = doc.get("metadata")
    # kubectl output carries server-set metadata (resourceVersion, uid, managedFields).
    if isinstance(meta, dict) and any(k in meta for k in ("resourceVersion", "uid", "managedFields")):
        return True
    if isinstance(doc.get("Policy"), str):
        return True
    # AWS CLI responses: known collection keys, or a single object carrying an Arn.
    if AWS_EXPORT_KEYS & doc.keys():
        return True
    return len(doc) <= 2 and any(isinstance(v, dict) and "Arn" in v for v in doc.values()) and \
        all(isinstance(k, str) and k[:1].isupper() for k in doc)


def aws_export(scan, rel, doc, keys):
    """Rules for the AWS CLI exports reference/snapshots.md lists; True when one matched."""
    def at(path, key):
        return keys.get((path, key), 1)

    def items(name):
        value = doc.get(name)
        return [(i, x) for i, x in enumerate(value) if isinstance(x, dict)] if isinstance(value, list) else []

    def policy(document):
        if isinstance(document, str):  # get-account-authorization-details may URL-encode documents
            try:
                document = json.loads(url_unquote(document), object_pairs_hook=unique_object)
            except ValueError:
                return None
        return norm_statements(document) if isinstance(document, dict) else None

    matched = False
    # aws iam get-account-authorization-details
    for list_name, inline_key, type_ in (("RoleDetailList", "RolePolicyList", "aws_iam_role"),
                                         ("UserDetailList", "UserPolicyList", "aws_iam_user"),
                                         ("GroupDetailList", "GroupPolicyList", "aws_iam_group")):
        for i, entity in items(list_name):
            matched = True
            name = str(entity.get(type_.split("_")[-1].capitalize() + "Name", i))
            line = at((list_name, i), "Arn")
            res = Res(type_, f"snapshot:{type_}.{name}", rel, line)
            scan.add_resource(res, "aws")
            if "AssumeRolePolicyDocument" in entity:
                scan.trust_policy(res, policy(entity["AssumeRolePolicyDocument"]), line)
            for p in aslist(entity.get(inline_key)):
                if isinstance(p, dict):
                    scan.identity_policy(res, policy(p.get("PolicyDocument")), line)
            if any(isinstance(p, dict) and isinstance(p.get("PolicyArn"), str) and ADMIN_ARN.search(p["PolicyArn"])
                   for p in aslist(entity.get("AttachedManagedPolicies"))):
                scan.hit("AWS-IAM-001", res, line, "AdministratorAccess attached")
    for i, managed in items("Policies"):
        # AWS-managed policies are AWS's documents; attaching them is checked above.
        if not managed.get("AttachmentCount") or AWS_MANAGED_ARN.match(str(managed.get("Arn", ""))):
            continue
        matched = True
        line = at(("Policies", i), "Arn")
        res = Res("aws_iam_policy", f"snapshot:aws_iam_policy.{managed.get('PolicyName', i)}", rel, line)
        scan.add_resource(res, "aws")
        for version in aslist(managed.get("PolicyVersionList")):
            if isinstance(version, dict) and version.get("IsDefaultVersion"):
                scan.identity_policy(res, policy(version.get("Document")), line)
    # aws rds describe-db-instances
    for i, db in items("DBInstances"):
        matched = True
        line = at(("DBInstances", i), "DBInstanceIdentifier")
        res = Res("aws_db_instance", f"snapshot:aws_db_instance.{db.get('DBInstanceIdentifier', i)}", rel, line)
        scan.add_resource(res, "aws")
        if db.get("PubliclyAccessible") is True:
            scan.hit("AWS-RDS-001", res, at(("DBInstances", i), "PubliclyAccessible"), "PubliclyAccessible = true")
        if db.get("StorageEncrypted") is False:
            scan.hit("AWS-RDS-002", res, at(("DBInstances", i), "StorageEncrypted"), "StorageEncrypted = false")
    # aws ec2 describe-instances
    for r, reservation in items("Reservations"):
        for i, instance in enumerate(aslist(reservation.get("Instances"))):
            if not isinstance(instance, dict):
                continue
            matched = True
            line = keys.get((("Reservations", r, "Instances", i), "InstanceId"), 1)
            res = Res("aws_instance", f"snapshot:aws_instance.{instance.get('InstanceId', i)}", rel, line)
            scan.add_resource(res, "aws")
            opts = instance.get("MetadataOptions")
            if isinstance(opts, dict) and opts.get("HttpEndpoint") != "disabled" and opts.get("HttpTokens") == "optional":
                scan.hit("AWS-EC2-001", res, line, "HttpTokens = optional")
    # aws lambda list-functions / get-function-configuration
    for i, fn in items("Functions"):
        matched = True
        line = at(("Functions", i), "FunctionName")
        res = Res("aws_lambda_function", f"snapshot:aws_lambda_function.{fn.get('FunctionName', i)}", rel, line)
        scan.add_resource(res, "aws")
        cfn_secrets(scan, res, fn.get("Environment"), line)
    # aws lambda list-function-url-configs
    for i, url in items("FunctionUrlConfigs"):
        matched = True
        line = at(("FunctionUrlConfigs", i), "FunctionArn")
        res = Res("aws_lambda_function_url", f"snapshot:{url.get('FunctionArn', i)}", rel, line)
        scan.add_resource(res, "aws")
        if url.get("AuthType") == "NONE":
            scan.hit("AWS-LAMBDA-001", res, at(("FunctionUrlConfigs", i), "AuthType"), "AuthType = NONE")
    # aws cloudtrail describe-trails
    for i, trail in items("trailList"):
        matched = True
        line = at(("trailList", i), "Name")
        res = Res("aws_cloudtrail", f"snapshot:aws_cloudtrail.{trail.get('Name', i)}", rel, line)
        scan.add_resource(res, "aws")
        off = [k for k in ("IsMultiRegionTrail", "LogFileValidationEnabled") if trail.get(k) is False]
        if off:
            scan.hit("AWS-CT-001", res, line, "not true: " + ", ".join(off))
    # aws s3control get-public-access-block / aws s3api get-public-access-block
    pab = doc.get("PublicAccessBlockConfiguration")
    if isinstance(pab, dict):
        matched = True
        line = at((), "PublicAccessBlockConfiguration")
        res = Res("aws_s3_public_access_block", f"snapshot:{Path(rel).name}", rel, line)
        scan.add_resource(res, "aws")
        off = [k for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
               if pab.get(k) is False]
        if off:
            scan.hit("AWS-S3-002", res, line, "off: " + ", ".join(off))
    return matched


def handle_snapshot(scan, rel, text, doc):
    """The file kind ("snapshot" or "policy") when the document is recognised, else None."""
    keys = json_key_lines(text)
    if isinstance(doc, dict) and aws_export(scan, rel, doc, keys):
        return "snapshot"
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
            doc = json.loads(doc["Policy"], object_pairs_hook=unique_object)
        except ValueError:
            return None
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
            scan.firewall(res, line, fw.get("direction"), fw.get("disabled"), fw.get("sourceRanges"), allows,
                          (fw.get("sourceTags"), fw.get("sourceServiceAccounts")))
        return "snapshot"
    return None


class _YamlMap(dict):
    def __init__(self, line):
        super().__init__()
        self.line, self.lines = line, {}

    def put(self, key, value, line):
        if not isinstance(key, str) or key == "<<" or key in self:
            raise ValueError("complex, merge or duplicate mapping key")
        self[key], self.lines[key] = value, line


YAML_TAGGED = re.compile(r"(?:^|[ \t\[{,])![A-Za-z][A-Za-z0-9]*[ \t]+\Z")


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
        elif c in "\"'" and (i == 0 or text[i - 1] in " \t[{,") and (
                previous in ("", ":", "[", "{", ",", "-") or YAML_TAGGED.search(text, max(0, i - 64), i)):
            quote = c  # a quote opens only at a token start, or after a tag (!Sub "...")
        else:
            yield i, c, depth
            depth += (c in "[{") - (c in "]}")
        if c not in " \t":
            previous = c
        i += 1


def _yaml_comment(text):
    for i, c, _ in _yaml_marks(text):
        if c == "#" and (i == 0 or text[i - 1] in " \t"):
            return text[:i].rstrip(" \t")
    return text.rstrip(" \t")


def _yaml_pair(text):
    for i, c, depth in _yaml_marks(text):
        if c == ":" and depth == 0 and (i + 1 == len(text) or text[i + 1] in " \t"):
            return text[:i].strip(" \t"), text[i + 1:].strip(" \t")
    return None


YAML_BREAK = re.compile("[\r\x85\u2028\u2029]")


# CloudFormation's short-form intrinsic function tags and their long forms.
CFN_TAGS = {"Ref": "Ref", "Condition": "Condition", **{name: f"Fn::{name}" for name in (
    "And", "Base64", "Cidr", "Equals", "FindInMap", "GetAtt", "GetAZs", "If", "ImportValue", "Join",
    "Length", "Not", "Or", "Select", "Split", "Sub", "ToJsonString", "Transform")}}
CFN_TAG = re.compile(r"!([A-Za-z][A-Za-z0-9]*)(?=[ \t]|$|[,\]}])")


def cfn_intrinsic(tag, value, line):
    """{"Ref": x} or {"Fn::Name": x} for a short-form tag; !GetAtt A.B is ["A", "B"]."""
    if tag not in CFN_TAGS:
        raise ValueError("unsupported YAML tag")
    if tag == "GetAtt" and isinstance(value, str) and "." in value:
        value = value.split(".", 1)
    result = _YamlMap(line)
    result.put(CFN_TAGS[tag], value, line)
    return result


class _YamlFlow:
    """Single-line flow collections and scalars; no YAML tags or references,
    except CloudFormation's intrinsic tags when cfn is set."""
    def __init__(self, text, line, cfn=False):
        self.text, self.line, self.i, self.cfn = text, line, 0, cfn

    def ws(self):
        # YAML whitespace is space and tab; NBSP or a BOM is content.
        while self.i < len(self.text) and self.text[self.i] in " \t":
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
        if c == "!" and self.cfn and not key:
            m = CFN_TAG.match(self.text, start)
            if not m:
                raise ValueError("unsupported YAML scalar, tag or reference")
            self.i = m.end()
            return cfn_intrinsic(m.group(1), self.value(flow=flow), self.line)
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
        # A plain key ends at ": " (or ":" before a flow indicator); Fn::ImportValue is one key.
        while self.i < len(self.text) and not (
                (flow and self.text[self.i] in ",]}") or (key and self.text[self.i] == ":" and (
                    self.i + 1 == len(self.text) or self.text[self.i + 1] in " \t,]}"))):
            self.i += 1
        word = self.text[start:self.i].strip(" \t")
        if not word or word[0] in "&*!%@?|>" + chr(96) or re.search(r":\s", word) or (flow and word.endswith(":")):
            raise ValueError("unsupported YAML scalar, tag or reference")
        if key:
            return word
        # Kubernetes uses YAML 1.1 boolean spellings, including single-letter y/n.
        if word in ("y", "Y", "yes", "Yes", "YES", "true", "True", "TRUE", "on", "On", "ON"):
            return True
        if word in ("n", "N", "no", "No", "NO", "false", "False", "FALSE", "off", "Off", "OFF"):
            return False
        if word in ("null", "Null", "NULL", "~"):
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
    def __init__(self, rows, cfn=False):
        self.rows, self.i, self.cfn = list(rows), 0, cfn
        self.line = rows[0][0] if rows else 1

    def peek(self):
        while self.i < len(self.rows):
            n, raw = self.rows[self.i]
            self.line = n
            # YAML (and kubectl) also break lines at a lone CR, NEL and the
            # Unicode separators. Lines here split on LF only, so a comment
            # would swallow the "next line"; refuse rather than mis-read.
            if YAML_BREAK.search(raw):
                raise ValueError("unsupported line break (lone CR, NEL or U+2028/2029)")
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
        tag = re.fullmatch(r"!([A-Za-z][A-Za-z0-9]*)(?:[ \t]+([|>].*))?", text) if self.cfn else None
        if tag:
            # A short-form tag whose value is a block (!If, !Join) or a block string (!Sub |).
            return cfn_intrinsic(tag.group(1), self.entry(tag.group(2) or "", indent, line, indentless), line)
        if re.fullmatch(r"[|>](?:[+-][1-9]?|[1-9][+-]?)?", text):
            # Never interpret embedded manifests, scripts or configuration as YAML.
            while self.i < len(self.rows):
                raw = self.rows[self.i][1]
                if raw.strip() and len(raw) - len(raw.lstrip(" ")) <= indent:
                    break
                self.i += 1
            return UNKNOWN
        if text:
            return _YamlFlow(text, line, self.cfn).parse()
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
                return _YamlFlow(row[1], row[2], self.cfn).parse()
            return self.mapping(indent, _YamlMap(row[2]))
        result = []
        while (row := self.peek()) and row[0] == indent and self.is_list(row[1]):
            self.i += 1
            text = row[1][1:].lstrip(" ")
            item_indent = indent + len(row[1]) - len(text)
            if self.is_list(text):
                # "- - a" opens a sequence inside the item: re-read the rest of
                # the row as the first entry of a block at the item's column.
                self.i -= 1
                self.rows[self.i] = (row[2], " " * item_indent + text)
                result.append(self.block(item_indent))
                continue
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


# Capabilities that reach the node: kernel modules, raw devices, other
# processes, host files, eBPF and the network stack.
DANGEROUS_CAPABILITIES = {"ALL", "SYS_ADMIN", "SYS_MODULE", "SYS_RAWIO", "SYS_PTRACE", "DAC_READ_SEARCH",
                          "NET_ADMIN", "BPF", "PERFMON", "SYS_BOOT"}
PLATFORM_BINDINGS = {
    ("ClusterRoleBinding", "kubeadm:cluster-admins", "cluster-admin", (("Group", "kubeadm:cluster-admins"),)),
    ("ClusterRoleBinding", "eks:addon-cluster-admin", "cluster-admin", (("User", "eks:addon-manager"),)),
    ("RoleBinding", "kubeadm:bootstrap-signer-clusterinfo", "kubeadm:bootstrap-signer-clusterinfo",
     (("User", "system:anonymous"),)),
}


def contains_key(value, key, depth=8):
    if depth == 0:
        return False
    if isinstance(value, dict):
        return key in value or any(contains_key(v, key, depth - 1) for v in value.values())
    if isinstance(value, list):
        return any(contains_key(v, key, depth - 1) for v in value)
    return False


def same_tree(a, b):
    """Two directories on one path (one holds the other): the same set of manifests,
    unlike sibling trees such as dev/ and prod/ that may target different clusters."""
    return a == b or not a or not b or a.startswith(b + "/") or b.startswith(a + "/")


def finish_k8s(scan):
    """Bindings to roles that grant * on *, defined in the binding's directory tree.
    A role of that name only in a sibling tree (dev/ for a prod/ binding) may be
    another cluster's: recorded as unresolved instead."""
    for res, kind, namespace, role_kind, role_name, line in scan.k8s_bindings:
        # An omitted namespace (None) is the apply context's: it may be any
        # namespace, so it pairs with an explicit one in either direction.
        dirs = set()
        for (kind_, ns, name_), where in scan.k8s_wildcard_roles.items():
            if kind_ == role_kind and name_ == role_name and (
                    role_kind == "ClusterRole" or not namespace or ns is None or ns == namespace):
                dirs |= where
        here = posixpath.dirname(res.file)
        if any(same_tree(here, d) for d in dirs):
            severity = "Medium" if kind == "RoleBinding" else None
            scan.hit("K8S-002", res, line, f"binds {role_kind} {role_name}, which grants * on *", severity)
        elif dirs:
            scan.not_run.append(f"K8S-002: {role_kind} {role_name} grants * on * in {', '.join(sorted(dirs))}, "
                                f"another tree than the binding; check it is the same cluster: {res.file}:{line} "
                                f"({res.address})")
    for res, namespace, sa_name, line in scan.k8s_pod_sa_refs:
        if any(name == sa_name and (not namespace or ns is None or ns == namespace)
               and same_tree(posixpath.dirname(res.file), info[0])
               for (ns, name), info in scan.k8s_sa_automount.items()):
            scan.hit("K8S-001", res, line, f"serviceAccountName {sa_name} has automountServiceAccountToken: true", "Low")


def _check_k8s(scan, rel, doc, fallback_kind=None):
    kind = doc.get("kind") or fallback_kind
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
    if namespace is not None and not isinstance(namespace, str):
        namespace = UNKNOWN  # a list or map is no namespace: opaque, reviewed by hand
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
        labels = _k8s_map(meta, "labels")
        # Kubernetes' own bootstrap RBAC (exported with kubectl get -o json):
        # system:* bindings labelled rbac-defaults, and cluster-admin to system:masters.
        bootstrap = labels.get("kubernetes.io/bootstrapping") == "rbac-defaults" and \
            isinstance(name, str) and name.startswith("system:") and role.get("name") == name
        masters_only = bool(subjects) and all(s.get("kind") == "Group" and s.get("name") == "system:masters"
                                              for s in subjects)
        # kubeadm and EKS create these bindings themselves; matched on name, role and subjects.
        # Compared, not hashed: a schema-invalid subject may hold a list or map.
        binding = (kind, name, role.get("name"), tuple((s.get("kind"), s.get("name")) for s in subjects))
        platform = any(binding == known for known in PLATFORM_BINDINGS) and (
            kind == "ClusterRoleBinding" or namespace == "kube-public")
        if platform:
            scan.not_run.append(f"K8S-002: platform-managed binding {name} (kubeadm/EKS default); confirm it is "
                                f"unmodified: {rel}:{res.line}")
        elif role.get("kind") == "ClusterRole" and role.get("name") == "cluster-admin" and not masters_only:
            if kind == "RoleBinding":
                scan.hit("K8S-002", res, role.lines["name"], f"binds cluster-admin within namespace "
                         f"{namespace if isinstance(namespace, str) else '(apply context)'}", "Medium")
            else:
                scan.hit("K8S-002", res, role.lines["name"], "binds cluster-admin")
        elif role.get("kind") in ("ClusterRole", "Role") and isinstance(role.get("name"), str) and not masters_only:
            # A role granting * on * is cluster-admin under another name; roles may be in other files.
            scan.k8s_bindings.append((res, kind, namespace, role.get("kind"), role.get("name"), role.lines["name"]))
        for subject in subjects if not (bootstrap or platform) else []:
            skind, sname = subject.get("kind"), subject.get("name")
            if (skind == "Group" and isinstance(sname, str) and (
                    sname in ("system:authenticated", "system:unauthenticated", "system:serviceaccounts") or
                    sname.startswith("system:serviceaccounts:"))) or (
                    skind == "User" and sname in ("system:anonymous", "system:unauthenticated")):
                scan.hit("K8S-002", res, subject.lines["name"], f"binds {sname}")
    if kind in ("ClusterRole", "Role") and isinstance(name, str):
        for rule in aslist(doc.get("rules")):
            if not isinstance(rule, dict):
                continue
            # Schema-invalid items (a nested list) match nothing instead of aborting the scan.
            verbs = {v for v in aslist(rule.get("verbs")) if isinstance(v, str)}
            resources = {v for v in aslist(rule.get("resources")) if isinstance(v, str)}
            groups = {v for v in aslist(rule.get("apiGroups")) if isinstance(v, str)}
            if ("*" in resources and ("*" in groups or "" in groups) and "*" in verbs) or (
                    "*" in resources and "*" in groups and bool(verbs & {"*", "bind", "escalate", "impersonate"})):
                ns_key = (namespace or None) if kind == "Role" else None
                scan.k8s_wildcard_roles.setdefault((kind, ns_key, name), set()).add(posixpath.dirname(rel))
    if namespace is UNKNOWN or any(m.get(k) is UNKNOWN for m in relevant for k in ("kind", "name")):
        scan.not_run.append(f"kubernetes opaque identity needs manual review: {rel}:{res.line}")
    if kind == "ServiceAccount" and isinstance(name, str) and doc.get("automountServiceAccountToken") is True:
        scan.k8s_sa_automount[(namespace or None, name)] = (
            posixpath.dirname(rel), doc.lines.get("automountServiceAccountToken", res.line))
    if kind == "Secret":
        for key in ("data", "stringData"):
            # Charts ship placeholder Secrets with empty values.
            if isinstance(doc.get(key), dict) and any(value not in ("", None) for value in doc[key].values()):
                scan.hit("K8S-003", res, doc.lines[key], "Secret manifest with data")
    api = doc.get("apiVersion") if isinstance(doc.get("apiVersion"), str) else ""
    paths = {
        "Pod": ("spec",), "PodTemplate": ("template", "spec"),
        "CronJob": ("spec", "jobTemplate", "spec", "template", "spec"),
        "ScaledJob": ("spec", "jobTargetRef", "template", "spec"),  # KEDA
        **{k: ("spec", "template", "spec") for k in (
            "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "ReplicationController", "Job",
            "Rollout",  # Argo Rollouts keeps a Deployment-shaped template
            "DeploymentConfig")},  # OpenShift
    }
    if kind in ("Service", "Configuration") and api.startswith("serving.knative.dev/"):
        paths[kind] = ("spec", "template", "spec")
    pod = _k8s_map(doc, *paths[kind]) if kind in paths else _YamlMap(res.line)
    sa_name = pod.get("serviceAccountName") or pod.get("serviceAccount")
    if kind in paths and isinstance(sa_name, str) and pod.get("automountServiceAccountToken") is not False:
        sa_key = "serviceAccountName" if "serviceAccountName" in pod.lines else "serviceAccount"
        scan.k8s_pod_sa_refs.append((res, namespace or None, sa_name, pod.lines.get(sa_key, res.line)))
    containers = [c for key in ("containers", "initContainers", "ephemeralContainers") for c in aslist(pod.get(key))]
    if kind in ("Workflow", "WorkflowTemplate", "ClusterWorkflowTemplate", "CronWorkflow") and \
            api.startswith("argoproj.io/"):
        # Argo Workflows: each template runs a container, script, sidecars or init containers.
        pod = _k8s_map(doc, "spec", "workflowSpec") if kind == "CronWorkflow" else _k8s_map(doc, "spec")
        for template in aslist(pod.get("templates")):
            if isinstance(template, _YamlMap):
                containers += [template.get(k) for k in ("container", "script") if isinstance(template.get(k), _YamlMap)]
                containers += [c for k in ("initContainers", "sidecars") for c in aslist(template.get(k))]
    elif kind not in paths and contains_key(doc, "containers"):
        scan.not_run.append(f"K8S-001: workload kind {kind} not modelled; review its pod spec by hand: "
                            f"{rel}:{res.line}")
    hits = [(pod, k, f"{k}: true") for k in ("hostNetwork", "hostPID", "hostIPC")
            if pod.get(k) is True]
    for container in containers:
        security = _k8s_map(container, "securityContext")
        if security.get("privileged") is True:
            hits.append((security, "privileged", "privileged: true"))
        caps = _k8s_map(security, "capabilities")
        added = [c for c in aslist(caps.get("add")) if isinstance(c, str)]
        dangerous = [c for c in added if c.upper().removeprefix("CAP_") in DANGEROUS_CAPABILITIES]
        if dangerous:
            hits.append((caps, "add", f"capabilities add {dangerous[0]}"))
    for container in containers:
        for env in aslist(container.get("env") if isinstance(container, _YamlMap) else None):
            # $(OTHER_VAR) expands another entry; {{ }} is an unrendered chart template.
            if isinstance(env, _YamlMap) and isinstance(env.get("name"), str) and \
                    CFN_SECRET_KEY.fullmatch(env["name"]) and literal_secret(env.get("value")) and \
                    not re.search(r"\$\(|\{\{", env["value"]):
                scan.hit("SEC-001", Res("file", rel, rel, 1), env.lines.get("value", res.line),
                         f"literal value for {env['name']} ({res.address})")
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


KUSTOMIZE = re.compile(r"""apiVersion:\s*["']?kustomize\.config\.k8s\.io/""")
KUSTOMIZATION_FILES = {"kustomization.yaml", "kustomization.yml", "Kustomization"}


def handle_yaml(scan, rel, lines):
    kinds = set()
    for rows in split_yaml_documents(lines):
        parser = _YamlSubset(rows)
        doc, reason = None, None
        try:
            doc = parser.parse()
        except (ValueError, RecursionError) as exc:
            reason = "nesting too deep" if isinstance(exc, RecursionError) else str(exc)
        if isinstance(doc, list) and doc and all(isinstance(x, _YamlMap) and is_manifest(x) for x in doc):
            kinds.add("kubernetes")  # a root sequence of manifests
            for item in doc:
                _check_k8s(scan, rel, item)
            continue
        kind = _yaml_kind(rows, doc)
        if not kind and any(YAML_BREAK.search(raw) for _, raw in rows):
            # A NEL or U+2028 can hide apiVersion/kind inside an LF-delimited
            # "comment" row. Classify on every YAML line break, then report the
            # document as unsupported rather than letting it vanish.
            pieces = [(n, piece) for n, raw in rows for piece in YAML_BREAK.split(raw)]
            kind = _yaml_kind(pieces, None)
            if not kind:
                scan.not_run.append(f"YAML with unsupported line breaks could not be classified; "
                                    f"review by hand: {rel}:{rows[0][0]}")
                continue
        if kind == "kubernetes" and any(KUSTOMIZE.match(raw) for _, raw in rows) or (
                not kind and Path(rel).name in KUSTOMIZATION_FILES):
            # A Kustomization is build input, not a cluster object.
            kind = "kustomize"
            scan.not_run.append(f"Kustomize overlay: patches, generators and remote bases not applied; "
                                f"review the `kustomize build` output by hand: {rel}")
        if not kind:
            continue
        kinds.add(kind)
        if kind == "kustomize":
            continue
        if kind == "cloudformation-yaml":
            if doc is None:
                try:  # short-form intrinsic tags (!Ref, !Sub, !GetAtt) as their long forms
                    doc = _YamlSubset(rows, cfn=True).parse()
                except (ValueError, RecursionError):
                    doc = None
            handle_cfn_yaml(scan, rel, [line for _, line in rows], rows[0][0], doc)
            continue
        if reason and any("{{" in raw for _, raw in rows):
            scan.not_run.append(f"kubernetes YAML rules not applied (template such as a Helm chart; review the "
                                f"rendered output, e.g. `helm template`): {rel}:{rows[0][0]}")
            k8s_header_resource(scan, rel, rows)
            continue
        if reason:
            scan.not_run.append(f"kubernetes YAML rules not applied ({reason}): {rel}:{parser.line}")
            k8s_header_resource(scan, rel, rows)
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


def is_manifest(doc):
    return isinstance(doc, dict) and isinstance(doc.get("apiVersion"), str) and isinstance(doc.get("kind"), str)


def handle_k8s_json(scan, rel, text, doc):
    """Kubernetes manifests and `kubectl get -o json` exports written as JSON,
    also a bare array of objects (`kubectl get -o json | jq .items`)."""
    if not (is_manifest(doc) or (isinstance(doc, list) and doc and all(is_manifest(x) for x in doc))):
        return False
    converted = _json_as_yaml(doc, json_key_lines(text))
    for item in converted if isinstance(converted, list) else [converted]:
        _check_k8s(scan, rel, item)
    return True


K8S_KIND = re.compile(r"""^kind:[ \t]*["']?([A-Za-z][\w.-]*)""")
K8S_META = re.compile(r"""^[ \t]+(name|namespace):[ \t]*["']?([\w.:-]+)""")


def k8s_header_resource(scan, rel, rows):
    """Inventory an object whose document is outside the YAML subset, from its headers."""
    kind = name = namespace = None
    line, in_meta = rows[0][0] if rows else 1, False
    for n, raw in rows:
        if (m := K8S_KIND.match(raw)) and kind is None:
            kind, line = m.group(1), n
        if raw.startswith(("metadata:", "metadata :")):
            in_meta = True
            flow = re.search(r"\{.*?\bname:[ \t]*[\"']?([\w.:-]+)", raw)
            name = name or (flow.group(1) if flow else None)
        elif raw[:1] not in (" ", "\t", "", "#"):
            in_meta = False
        elif in_meta and (m := K8S_META.match(raw)) and len(raw) - len(raw.lstrip()) <= 4:
            if m.group(1) == "name" and name is None:
                name = m.group(2)
            elif m.group(1) == "namespace" and namespace is None:
                namespace = m.group(2)
    if kind:
        identity = f"{namespace}/{name or '?'}" if namespace else (name or "?")
        scan.add_resource(Res(kind, f"k8s:{kind}/{identity}", rel, line), "kubernetes")


def handle_cfn_yaml(scan, rel, lines, start_line=1, doc=None):
    resources = doc.get("Resources") if isinstance(doc, _YamlMap) else None
    if isinstance(resources, _YamlMap):
        # Parsed by the YAML subset, with short-form tags (!Ref) read as their
        # long forms ({"Ref": X}): the JSON rules apply unchanged.
        def line_of(lid):  # the Type line, as the tag-tolerant inventory reports it
            r = resources.get(lid)
            return r.lines.get("Type", resources.lines[lid]) if isinstance(r, _YamlMap) else resources.lines[lid]
        handle_cfn(scan, rel, None, doc, line_of=line_of)
        return
    for lid, type_, line in _cfn_yaml_resources(list(enumerate(lines, start_line)), doc):
        scan.add_resource(Res(type_, f"cfn:{lid}", rel, line), "aws")
    note = f"cloudformation yaml: rules not applied (tags or syntax outside the YAML subset): {rel}"
    if note not in scan.not_run:
        scan.not_run.append(note)


SECRET_PATTERNS = [(label, re.compile(rf"\b(?:{pattern})")) for label, pattern in CREDENTIAL_SHAPES]
SECRET_PATTERNS.append(("private key", KEY_BEGIN))
# The short spellings (db_pass, admin_pw) count only as a whole word, as in
# redaction's CREDENTIAL_WORD: bypass or compass name no secret.
SECRET_KEY_NAME = (
    r'"?([A-Za-z0-9_-]*(?:(?:password|passwd|secret|secret_key|secret_string|secret_data|secret_binary|'
    r'token|api_key|apikey|access_key|private_key|client_key|ssh_key|tls\.key|passphrase|bearer|auth_token|'
    r'credentials?|connection_string|preshared_key|plaintext)(?:[_-]?(?:prod|dev|staging|test|base|val|value|str|string|data|binary|[0-9]+))?|'
    r'(?<![A-Za-z])(?:pass|pwd|pw)(?![A-Za-z])))"?'
)
# A key file path or a connection string without a password is no secret.
NOT_A_SECRET = {("credential", "credentials"): re.compile(r"^[\w./~-]+\.(?:json|pem|p12|key)$"),
                # Neither Password=... nor URI userinfo (postgres://user:pass@host).
                ("connection_string",): re.compile(r"^(?!.*\b(?:password|pwd)\s*=)(?!.*://[^/@\s]*:[^/@\s]*@)",
                                                   re.IGNORECASE)}
# AWS API output fields named *Token that are idempotency or pagination
# cursors (describe-instances ClientToken, --max-items NextToken), not secrets.
API_CURSOR_FIELDS = {"clienttoken", "nexttoken", "continuationtoken", "nextcontinuationtoken", "paginationtoken",
                     "idempotencytoken", "startingtoken"}
GENERIC_SECRET = re.compile(rf'^\s*{SECRET_KEY_NAME}\s*=\s*"([^"]*)"', re.IGNORECASE)
# The same inside a one-line object: variables = { LOG = "x", DB_PASSWORD = "..." }.
INLINE_SECRET = re.compile(rf'[{{,]\s*{SECRET_KEY_NAME}\s*=\s*"([^"]*)"', re.IGNORECASE)
GENERIC_SECRET_JSON = re.compile(rf'(?:^|[{{,])\s*{SECRET_KEY_NAME}\s*:\s*"([^"]*)"', re.IGNORECASE)  # .tfvars.json
# Values that are not secrets even under a secret-looking key: placeholders,
# references and time units (Cognito token_validity_units).
PLACEHOLDER = re.compile(r"^(|<.*>|[xX*._-]+|todo|tbd|replace[_-]?me|arn:.*|projects/.*|"
                         r"seconds|minutes|hours|days)$", re.IGNORECASE)
# A Secret Manager secret *name* (Cloud Run secret_key_ref, Cloud Functions
# secret_environment_variables): lowercase words joined by - or _.
SECRET_REF_BLOCK = re.compile(r"\b(?:secret_key_ref|secret_environment_variables|secret_volumes|value_source)\b")
SECRET_NAME_VALUE = re.compile(r"^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)+$")


# Container environment entries: { name = "DB_PASSWORD", value = "..." }, also
# split over two lines and in jsonencode()d container definitions.
NAME_VALUE = re.compile(r'(?i)"?\bname"?\s*[:=]\s*"([^"]+)"\s*,?\s*"?value"?\s*[:=]\s*"([^"]*)"')
NAME_ONLY = re.compile(r'(?i)^\s*"?name"?\s*[:=]\s*"([^"]+)"\s*,?\s*(?:(?:#|//).*)?$')
VALUE_ONLY = re.compile(r'(?i)^\s*"?value"?\s*[:=]\s*"([^"]*)"')


VALUE_NAME = re.compile(r'(?i)"?\bvalue"?\s*[:=]\s*"([^"]*)"\s*,?\s*"?name"?\s*[:=]\s*"([^"]+)"')


def innermost_objects(line):
    """The { ... } spans on a line that hold no other object, with braces inside
    quoted strings ignored ("pfx{x}" is a value, not an object)."""
    found, stack, i, n = [], [], 0, len(line)
    while i < n:
        c = line[i]
        if c == '"':
            i += 1
            while i < n and line[i] != '"':
                i += 2 if line[i] == "\\" else 1
        elif c == "{":
            stack.append([i, False])
        elif c == "}" and stack:
            start, nested = stack.pop()
            if not nested:
                found.append(line[start:i + 1])
            if stack:
                stack[-1][1] = True
        i += 1
    return found


def env_pairs(lines, i):
    """[(name, value, entry text)] of the environment entries whose name is on line i: on
    one line in either order, or as attributes of one block in any order (HCL order
    is free). The entry text is that line, or the block's attribute lines between
    its braces, so a sibling entry's attributes never count."""
    line = lines[i]
    # One-line objects: every field of { name = ..., type = ..., value = ... }, in any order.
    objects = []
    for obj in innermost_objects(line):
        fields = {k.lower(): v for k, v in re.findall(r'"?(\w+)"?\s*[:=]\s*"((?:\\.|[^"\\])*)"', obj)}
        if "name" in fields and "value" in fields:
            objects.append((fields["name"], fields["value"], obj))
    if objects:
        return objects
    if (m := NAME_VALUE.search(line)):
        return [(m.group(1), m.group(2), line)]
    if (m := VALUE_NAME.search(line)):
        return [(m.group(2), m.group(1), line)]
    name = NAME_ONLY.match(line)
    if not name:
        return []
    lo = hi = i
    while lo > 0 and i - lo < 6 and not re.search(r"[{}\[\]]", lines[lo - 1]):
        lo -= 1
    while hi + 1 < len(lines) and hi - i < 6 and not re.search(r"[{}\[\]]", lines[hi + 1]):
        hi += 1
    entry = lines[lo:hi + 1]
    value = next((m for raw in entry if (m := VALUE_ONLY.match(raw))), None)
    return [(name.group(1), value.group(1), "\n".join(entry))] if value else []


def mock_lines(lines):
    """Line numbers inside Terragrunt mock_outputs blocks: stand-ins for plan, not secrets."""
    inside, depth = set(), 0
    for n, line in enumerate(lines, 1):
        if depth == 0 and not re.match(r"\s*mock_outputs\s*=\s*\{", line):
            continue
        inside.add(n)
        depth += line.count("{") - line.count("}")
        depth = max(depth, 0)
    return inside


HCL_KINDS = ("terraform", "tfvars", "terragrunt")


HEREDOC_SECRET = re.compile(rf'^\s*{SECRET_KEY_NAME}\s*=\s*<<-?([A-Za-z_]\w*)\s*$', re.IGNORECASE)
SECRET_VARIABLE = re.compile(rf'^\s*variable\s+"?({SECRET_KEY_NAME[3:-3]})"?\s*\{{', re.IGNORECASE)
SECRET_OUTPUT = re.compile(rf'^\s*output\s+"?({SECRET_KEY_NAME[3:-3]})"?\s*\{{', re.IGNORECASE)
LOCALS_BLOCK = re.compile(r'^\s*locals\s*\{')
INLINE_LOCALS_SECRET = re.compile(rf'(?:^|[{{\s]){SECRET_KEY_NAME}\s*=\s*"((?:\\.|[^"\\])*)"', re.IGNORECASE)


def hcl_literal_secrets(scan, res, lines, mocks):
    """SEC-001 for what the one-line patterns cannot see: a heredoc assigned to a
    secret-named argument, and the literal default of a secret-named variable
    (variable "db_password" { default = "..." } or default = <<EOT), the literal
    value of a secret-named output, or a secret-named local inside a locals block.
    One pass: a heredoc's body is read once and then skipped, as it is text, not
    configuration."""
    def literal(value):
        value = value.strip()
        return value and "${" not in value and not PLACEHOLDER.match(value) and not FLAG_VALUE.fullmatch(value)

    skeleton = hcl_code("\n".join(lines), strings=False).split("\n")  # braces outside strings, heredocs
    variable, output, in_locals, depth, i = None, None, False, 0, 0
    while i < len(lines):
        line = lines[i]
        after = i + 1
        body = None
        if (opener := re.search(r"<<-?([A-Za-z_]\w*)\s*$", line)):
            after = next((j for j in range(i + 1, len(lines)) if lines[j].strip() == opener.group(1)), len(lines))
            body = "\n".join(lines[i + 1:after])
            after += 1
        if depth == 0:
            if (m := SECRET_VARIABLE.match(line)):
                variable = m.group(1)
            elif (m := SECRET_OUTPUT.match(line)):
                output = m.group(1)
            elif LOCALS_BLOCK.match(line):
                in_locals = True
        eff_depth = 1 if depth == 0 and (variable or output or in_locals) else depth
        label = None
        if (m := HEREDOC_SECRET.match(line)):
            label = f"literal value assigned to {m.group(1)}"
        elif variable and eff_depth == 1 and (m := re.search(r'(?:^|[\s{])default\s*=\s*("((?:\\.|[^"\\])*)"|<<-?[A-Za-z_]\w*)', line)):
            label = f"literal default for variable {variable}"
            if m.group(2) is not None:
                body = m.group(2)
            elif not opener:
                body = None
        elif output and eff_depth == 1 and (m := re.search(r'(?:^|[\s{])value\s*=\s*("((?:\\.|[^"\\])*)"|<<-?[A-Za-z_]\w*)', line)):
            label = f"literal value for output {output}"
            if m.group(2) is not None:
                body = m.group(2)
            elif not opener:
                body = None
        elif in_locals and eff_depth == 1 and not GENERIC_SECRET.match(line) and not INLINE_SECRET.search(line) \
                and (m := INLINE_LOCALS_SECRET.search(line)):
            label = f"literal value assigned to {m.group(1)}"
            body = m.group(2)
        if label and body is not None and i + 1 not in mocks and literal(body):
            scan.hit("SEC-001", res, i + 1, label)
        depth = max(0, depth + skeleton[i].count("{") - skeleton[i].count("}"))
        if depth == 0:
            variable = output = None
            in_locals = False
        i = after


def scan_secrets(scan, rel, text, kind):
    res = Res("file", rel, rel, 1)
    lines = split_lines(text)
    generic = GENERIC_SECRET_JSON.finditer if rel.endswith(".json") else (
        lambda line: [*filter(None, [GENERIC_SECRET.match(line)]), *INLINE_SECRET.finditer(line)])
    mocks = mock_lines(lines) if kind == "terragrunt" else set()
    # Environment entries are read without comments, which may sit beside a name or
    # mention a reference type; a heredoc's body (container definitions) is kept.
    code_lines = hcl_code("\n".join(lines), heredocs=True).split("\n") if kind in HCL_KINDS else lines
    for n, line in enumerate(lines, 1):
        for label, pattern in SECRET_PATTERNS:
            # AWS documentation keys end in EXAMPLE (AKIAIOSFODNN7EXAMPLE).
            if any(not m.group().endswith("EXAMPLE") for m in pattern.finditer(line)):
                scan.hit("SEC-001", res, n, label, strong=True)
        if kind not in (*HCL_KINDS, "snapshot") or n in mocks:
            continue
        for name, value, entry in env_pairs(code_lines, n - 1):
            # The entry's own type: CodeBuild writes type = "PARAMETER_STORE" after the value.
            if CFN_SECRET_KEY.fullmatch(name) and "${" not in value and not PLACEHOLDER.match(value.strip()) \
                    and not FLAG_VALUE.fullmatch(value.strip()) \
                    and not SECRET_REFERENCE.search(entry):
                scan.hit("SEC-001", res, n, f"literal value for {name}")
        for m in generic(line):
            if SECRET_NAME_VALUE.match(m.group(2)) and (
                    m.group(1).lower() in ("secret_id", "secret_name") or (
                        m.group(1).lower() == "secret" and SECRET_REF_BLOCK.search("\n".join(lines[max(0, n - 6):n])))):
                continue
            if kind == "snapshot" and m.group(1).lower() in API_CURSOR_FIELDS:
                continue
            exempt = next((p for keys, p in NOT_A_SECRET.items() if m.group(1).lower().endswith(keys)), None)
            if exempt and exempt.search(m.group(2)):
                continue
            if "${" not in m.group(2) and not PLACEHOLDER.match(m.group(2).strip()) \
                    and not FLAG_VALUE.fullmatch(m.group(2).strip()):
                scan.hit("SEC-001", res, n, f"literal value assigned to {m.group(1)}")
    if kind in HCL_KINDS:
        hcl_literal_secrets(scan, res, code_lines, mocks)
    if re.search(r'"type"\s*:\s*"service_account"', text) and re.search(r'"private_key"\s*:', text):
        scan.hit("SEC-001", res, find_line(text, r'"private_key"\s*:'), "GCP service account key JSON",
                 strong=True)


# ---------------------------------------------------------------- walking

def is_json(text):
    try:
        json.loads(text)
    except (ValueError, RecursionError):
        return False
    return True


def classify_json(doc):
    if isinstance(doc, dict) and "planned_values" in doc:
        return "plan"
    # Terraform state under another name (terraform state pull > prod.json), or
    # its terraform show -json rendering: the same secrets as a .tfstate file.
    # Version 4 keeps resources, version 3 (Terraform 0.11 and older) modules.
    if isinstance(doc, dict) and (
            type(doc.get("version")) is int and isinstance(doc.get("lineage"), str)
            and type(doc.get("serial")) is int and isinstance(doc.get("resources", doc.get("modules")), list)
            or "format_version" in doc and isinstance(doc.get("values"), dict) and "root_module" in doc["values"]):
        return "state"
    if isinstance(doc, dict) and isinstance(doc.get("Resources"), dict) and (
            "AWSTemplateFormatVersion" in doc or any(
                isinstance(r, dict) and str(r.get("Type", "")).startswith("AWS::")
                for r in doc["Resources"].values())):
        return "cloudformation"
    return None


def walk(root, scan, prefix=""):
    entries, skipped = [], []

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
                if d not in QUIET_SKIPS:
                    skipped.append(prefix + full.relative_to(root).as_posix())
                continue
            if full.is_symlink():
                shown = full.relative_to(root).as_posix().encode("utf-8", "surrogateescape").decode(
                    "utf-8", "backslashreplace")
                scan.not_run.append(f"symlink skipped: {prefix}{shown}")
                continue
            keep.append(d)
        dirnames[:] = keep
        for f in sorted(filenames):
            full = base / f
            rel = prefix + full.relative_to(root).as_posix()
            try:
                rel.encode("utf-8")
            except UnicodeEncodeError:
                # Locations and the record are UTF-8; such a path cannot be cited.
                shown = rel.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
                scan.not_run.append(f"file name is not UTF-8, skipped: {shown}")
                continue
            if full.is_symlink():
                scan.not_run.append(f"symlink skipped: {rel}")
            elif full.is_file():
                entries.append((full, rel))
    if skipped:
        examples = ", ".join(skipped[:3]) + (", ..." if len(skipped) > 3 else "")
        scan.not_run.append(f"{len(skipped)} tool cache or vendored directories skipped as copies: {examples}")
    return entries


INPUT_SUFFIXES = (".tf", ".tofu", ".tfvars", ".json", ".yaml", ".yml", ".template")


TERRAGRUNT_BLOCKS = {"locals", "terraform", "inputs", "include", "dependency", "dependencies", "remote_state",
                     "generate", "download_dir", "prevent_destroy", "skip", "iam_role", "terraform_version_constraint",
                     "terragrunt_version_constraint", "retryable_errors"}
TOP_LEVEL = re.compile(r'^([A-Za-z_][\w-]*)\s*(?:"[^"]*"\s*)*[{=]', re.M)
# Top-level Terragrunt blocks, as shared include files hold them.
TERRAGRUNT = re.compile(r'^(?:inputs\s*=|include\s*(?:"[^"]*"\s*)?\{|dependency\s*"|dependencies\s*\{|'
                        r'remote_state\s*\{|generate\s*")', re.M)


TERRAGRUNT_NOTE = ("Terragrunt configuration read only for module sources, s3 remote_state encryption and "
                   "literal secrets; inputs, dependencies and generate blocks not evaluated")


def input_note(name):
    """Why a recognised infrastructure input is read only in part, or not at all."""
    lower = name.lower()
    if lower.endswith((".tf.json", ".tofu.json")):
        if re.search(r"(?:^|_)override\.(?:tf|tofu)\.json$", lower):
            return ("Terraform JSON override not applied: the module's final configuration is unknown "
                    "and its checks read the configuration before the override")
        return "Terraform JSON syntax not evaluated"
    if lower == "terragrunt.hcl":
        return TERRAGRUNT_NOTE
    if lower.endswith(".tftest.hcl") or lower.endswith(".tftest.json"):
        return None  # test assertions, not deployed configuration
    if lower.endswith(".hcl") and lower != ".terraform.lock.hcl":
        return "HCL configuration (Packer, Nomad, Vault policy or other) not evaluated"
    if re.fullmatch(r"serverless\.(?:ya?ml|json|ts|js)", lower):
        return ("Serverless Framework configuration not evaluated (its compiled template in .serverless/, "
                "from `serverless package`, is read when present)")
    if name == "Kustomization":
        return "Kustomize overlay: patches, generators and remote bases not applied; review the `kustomize build` output"
    if re.fullmatch(r"pulumi(?:\.[^.]+)?\.ya?ml", lower):
        return "Pulumi project or stack configuration not evaluated"
    return None
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


def state_file(scan, rel, detail):
    """A state holds every secret in plain text: no rule reads it. In the
    repository it is SEC-002; supplied as a snapshot it is the requester's export."""
    scan.files.append({"path": rel, "kind": "state"})
    if rel.startswith(SNAPSHOT_PREFIX):
        scan.not_run.append(f"Terraform state supplied as a snapshot; not read (it holds secrets in plain text), "
                            f"supply plan JSON instead: {rel}")
    else:
        scan.hit("SEC-002", Res("file", rel, rel, 1), 1, detail, strong=True)


def run(root, snapshots=()):
    root = Path(root)
    scan = Scan(root)
    parsed = []
    entries = walk(root, scan)
    for directory, prefix in zip(snapshots, snapshot_prefixes(snapshots)):
        entries += walk(Path(directory), scan, prefix)
    skipped = {"too large": [], "not UTF-8": []}
    terragrunt_files = []
    # In a Terragrunt tree, account.hcl, region.hcl and env.hcl hold its locals.
    terragrunt_tree = any(full.name in ("terragrunt.hcl", "root.hcl") for full, _ in entries)
    for full, rel in entries:
        name = full.name
        if STATE_FILE.search(name):
            state_file(scan, rel, "state file in the repository")
            continue
        snapshot = rel.startswith(SNAPSHOT_PREFIX)
        # Inputs the scanner would read are named; other skipped files (archives,
        # media, documents) only weaken the credential search, so they are counted.
        is_input = snapshot or name.lower().endswith(INPUT_SUFFIXES) or input_note(name) is not None
        try:
            limit = MAX_JSON_BYTES if snapshot or name.lower().endswith((".json", ".template")) else MAX_BYTES
            if full.stat().st_size > limit:
                if is_input:
                    scan.not_run.append(f"file too large to scan: {rel}")
                else:
                    skipped["too large"].append(rel)
                continue
            data = full.read_bytes()
        except OSError as e:
            scan.not_run.append(f"unreadable, skipped: {rel} ({e.strerror or e})")
            continue
        text = decode(data)
        if text is None:
            # Binary files are expected; an input the scanner would read is not.
            if is_input:
                scan.not_run.append(f"binary or not UTF-8, skipped: {rel}")
            elif b"\0" not in data:
                skipped["not UTF-8"].append(rel)
            continue
        kind = None
        note = input_note(name)
        terragrunt = name == "terragrunt.hcl" or (name.endswith(".hcl") and note and (
            TERRAGRUNT.search(text) or terragrunt_tree and set(TOP_LEVEL.findall(text)) and
            set(TOP_LEVEL.findall(text)) <= TERRAGRUNT_BLOCKS))
        if terragrunt:
            # Shared Terragrunt files (root.hcl, env.hcl, _envcommon/*.hcl), named once below.
            terragrunt_files.append(rel)
            note = None
        if note:
            scan.not_run.append(f"{note}; review by hand: {rel}")
        # kubectl -f and CloudFormation take any spelling (pod.YAML); Terraform
        # loads only lower-case .tf/.tofu, so a main.TF is named, not parsed.
        lname = name.lower()
        if lname.endswith((".tf", ".tofu")) and not name.endswith((".tf", ".tofu")):
            scan.not_run.append(f"Terraform ignores a file whose extension is not lower case; not parsed: {rel}")
        if name.endswith((".tf", ".tofu")):
            kind = "terraform"
            try:
                parsed.append((rel, parse_hcl(text)))
            except RecursionError:
                scan.not_run.append(f"HCL nested too deeply, skipped: {rel}")
        elif name.endswith(".tfvars"):
            kind = "tfvars"
        elif terragrunt:
            kind = "terragrunt"
            handle_terragrunt(scan, rel, text)
        elif lname.endswith(".json") or (lname.endswith(".template") and text.lstrip().startswith("{")) or (
                lname.endswith((".yaml", ".yml")) and text.lstrip().startswith("{") and is_json(text)):
            # JSON is YAML: a JSON template saved as .yaml is read as JSON.
            try:
                doc = json.loads(text, object_pairs_hook=unique_object)
            except RecursionError:
                doc = None
                scan.not_run.append(f"JSON nested too deeply, skipped: {rel}")
            except ValueError:
                doc = None
                if snapshot or "planned_values" in text or "AWSTemplateFormatVersion" in text or \
                        ('"apiVersion"' in text and '"kind"' in text):
                    scan.not_run.append(f"invalid JSON skipped: {rel}")
            kind = classify_json(doc)
            if kind == "state":
                state_file(scan, rel, "Terraform state (read from its content) in the repository")
                continue
            try:
                if lname.endswith(".tfvars.json"):
                    kind = "tfvars"
                elif kind == "plan":
                    handle_plan(scan, rel, text, doc)
                elif kind == "cloudformation":
                    handle_cfn(scan, rel, text, doc)
                elif doc is not None and handle_k8s_json(scan, rel, text, doc):
                    kind = "kubernetes"
                elif doc is not None:
                    kind = handle_snapshot(scan, rel, text, doc)
                    if kind is None and snapshot:
                        scan.not_run.append(f"cloud export shape has no baseline rules; review by hand: {rel}")
            except RecursionError:
                # json.loads accepts deeper nesting than the recursive rules.
                scan.not_run.append(f"JSON nested too deeply for the rules, skipped: {rel}")
        elif lname.endswith((".yaml", ".yml", ".template")):
            kind = handle_yaml(scan, rel, split_lines(text))
        if kind:
            scan.files.append({"path": rel, "kind": kind})
        elif snapshot and not lname.endswith(".json") and not note:
            scan.not_run.append(f"export not read (rules cover JSON exports); review by hand: {rel}")
        scan_secrets(scan, rel, text, kind)
    if terragrunt_files:
        examples = ", ".join(terragrunt_files[:3]) + (", ..." if len(terragrunt_files) > 3 else "")
        scan.not_run.append(f"{TERRAGRUNT_NOTE} ({len(terragrunt_files)} file(s)); review by hand: {examples}")
    for reason, rels in skipped.items():
        if rels:
            examples = ", ".join(rels[:3]) + (", ..." if len(rels) > 3 else "")
            scan.not_run.append(f"{len(rels)} other file(s) {reason}, not searched for credentials: {examples}")
    handle_terraform(scan, parsed)
    for rel, (_, referenced) in sorted(scan.policy_files.items()):
        if not referenced:
            scan.not_run.append("policy JSON without Principal is not read by a Terraform IAM policy "
                                f"resource (identity policy, SCP or boundary?); review by hand: {rel}")
    finish_dirs(scan)
    finish_k8s(scan)
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
    """HEAD of the repository holding root. A bare-repository layout committed
    inside the assessed tree is not a repository (safe.bareRepository=explicit),
    and neither the caller's GIT_* environment nor repository hooks apply."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        out = subprocess.run(["git", "-c", "safe.bareRepository=explicit", "-c", "core.fsmonitor=",
                              "-C", str(root), "rev-parse", "--verify", "HEAD"], capture_output=True,
                             text=True, timeout=30, env=env)
    except (OSError, subprocess.SubprocessError):
        return ""
    return out.stdout.strip() if out.returncode == 0 else ""


def inventory_of(scan):
    return inventory(scan.resources, scan.files, scan.not_run)


def report(scan, root, commit, findings, snapshots=()):
    hits = [{k: v for k, v in h.items() if k != "strong"} for h in scan.hits]
    return {"tool": "iac_scan", "version": 1, "repo": str(Path(root).resolve()), "commit": commit,
            "snapshots": {prefix.rstrip("/"): str(Path(d).resolve())
                          for d, prefix in zip(snapshots, snapshot_prefixes(snapshots))},
            "files": scan.files, "resources": scan.resources, "modules": scan.modules,
            "backends": scan.backends, "not_run": scan.not_run, "hits": hits, "findings": findings}


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

    def removed_label(fid):
        key = baseline_key(old_by_id[fid]) if fid in old_by_id else None
        if key:
            label = f"{key[0]} at {key[1]}"
            if key in new_by_key:
                label += " (affected resources changed)"
            return label
        # Do not leave a live-looking I-ID in rewritten text: it could be
        # assigned to an unrelated hit on the next scan.
        return f"unmatched baseline number {fid[2:]}"

    def rewrite_carried(text):
        """Renumber I-IDs in one pass; a vanished one becomes a removal label."""
        return sub_references(BASELINE_REFERENCE, text, lambda m: replacements.get(m.group()) or
                              f"[removed baseline: {removed_label(m.group())}]")

    carry_triage(data, old_by_id, replacements, new, rewrite_carried)

    def rewrite_prose(value, removed=None):
        """Renumber every string in value; a vanished ID's label is added to removed."""
        if isinstance(value, str):
            def replace_reference(match):
                fid = match.group()
                if fid in replacements:
                    return replacements[fid]
                label = removed_label(fid)
                if removed is not None and label not in removed:
                    removed.append(label)
                return f"[removed baseline: {label}]"
            # One regex pass is essential when I-001 -> I-002 and I-002 -> I-003:
            # a sequence of string replacements would move both to I-003.
            return sub_references(BASELINE_REFERENCE, value, replace_reference)
        if isinstance(value, list):
            return [rewrite_prose(x, removed) for x in value]
        if isinstance(value, dict):
            return {k: v if k in ("id", "references", "findings") else rewrite_prose(v, removed)
                    for k, v in value.items()}
        return value

    # Every other mention of a baseline ID follows it too. A lost one in a
    # finding or an attack path reopens it below, as lost evidence does; the
    # carry-over notes iac_scan.py writes name earlier IDs on purpose.
    lost_in_prose = {}
    for finding in data.get("findings", []):
        if isinstance(finding, dict) and str(finding.get("id", "")).startswith("F-"):
            lost = lost_in_prose.setdefault(finding["id"], [])
            for key, value in list(finding.items()):
                if key not in ("id", "references", "validation", "attack_paths"):
                    finding[key] = rewrite_prose(value, lost)
    invalidated_paths = {}
    for i, ap in enumerate(data["attack_paths"]):
        lost = []
        data["attack_paths"][i] = rewrite_prose(ap, lost)
        if lost and isinstance(ap, dict):
            invalidated_paths[ap.get("id")] = lost
    for key in ("perspectives", "checked_ok", "decisions", "next_steps"):
        if isinstance(data.get(key), list):
            data[key] = rewrite_prose(data[key])
    if isinstance(data.get("limitations"), list):
        data["limitations"] = [line if isinstance(line, str) and CARRY_NOTE.fullmatch(line) else rewrite_prose(line)
                               for line in data["limitations"]]
    if isinstance(data.get("meta"), dict):
        prose = rewrite_prose(meta_prose(data["meta"]))
        data["meta"].update({k: v for k, v in prose.items() if k != "inputs"})
        for item, note in zip(data["meta"].get("inputs", []), prose.get("inputs", [])):
            if "note" in note:
                item["note"] = note["note"]

    invalidated = set()
    for finding in data.get("findings", []):
        if not isinstance(finding, dict) or not str(finding.get("id", "")).startswith("F-"):
            continue
        validation = finding.get("validation")
        removed = list(lost_in_prose.get(finding["id"], []))
        if isinstance(validation, dict) and isinstance(validation.get("evidence"), str):
            validation["evidence"] = rewrite_prose(validation["evidence"], removed)
        if removed:
            if not isinstance(validation, dict):
                validation = finding["validation"] = {}
            evidence = validation.get("evidence") if isinstance(validation.get("evidence"), str) else ""
            note = "Baseline references removed by rescan: " + "; ".join(removed) + ". Recheck this finding."
            validation["evidence"] = (evidence.rstrip() + "\n" + note).lstrip()
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
            elif removed_label(fid) not in removed:
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


def carry_triage(data, old_by_id, replacements, new, rewrite):
    """Keep a reviewer's I-* verdict when the same rule, file and resources survive.

    Triage is I-*.validation with the confidence, condition and severity set
    beside it; dropping it on every rescan would silently undo the review. A
    changed resource set or a changed hit (detail) needs fresh triage.
    """
    new_by_id = {f["id"]: f for f in new}
    for fid, new_id in replacements.items():
        old, current = old_by_id[fid], new_by_id[new_id]
        validation = old.get("validation")
        if not isinstance(validation, dict) or validation.get("verdict") in (None, "Unverified"):
            continue
        same_resources = set(old.get("resources", [])) == set(current.get("resources", []))
        if same_resources and old.get("detail") == current.get("detail"):
            current["validation"] = copy.deepcopy(validation)
            if isinstance(validation.get("evidence"), str):
                current["validation"]["evidence"] = rewrite(validation["evidence"])
            for key in ("confidence", "severity"):
                if isinstance(old.get(key), str):
                    current[key] = old[key]
            if isinstance(old.get("condition"), str):
                current["condition"] = rewrite(old["condition"])
        else:
            changed = "affected resources changed" if not same_resources else "the hit changed"
            note = (f"{new_id} (was {fid}): {validation['verdict']} triage not carried over; "
                    f"{changed}. Recheck this baseline finding.")
            if note not in data["limitations"]:
                data["limitations"].append(note)


def merge_into(path, findings, inventory, commit):
    path = Path(path)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
        if json_depth(data) > MAX_JSON_DEPTH:
            raise ValueError(f"JSON nesting exceeds maximum depth ({MAX_JSON_DEPTH})")
        problems = shape_problems(data)
        if problems:
            raise ValueError("; ".join(problems))
    else:
        data = {"schema_version": 1, "meta": {}}
    data.setdefault("schema_version", 1)
    meta = data.setdefault("meta", {})
    if not isinstance(meta, dict):
        raise ValueError("meta must be an object")
    for key in RECORD_LISTS:
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
    write_json_atomic(path, data, mkdir=True)


def printable(value):
    """Output text: lone surrogates (a "\\ud800" escape in an input) spelled out,
    since the output is UTF-8, and credential shapes in repository-derived names
    (a resource or directory named like a key) redacted."""
    if isinstance(value, str):
        return CREDENTIAL.sub("[redacted]", value.encode("utf-8", "backslashreplace").decode("utf-8"))
    if isinstance(value, list):
        return [printable(x) for x in value]
    if isinstance(value, dict):
        return {printable(k): printable(v) for k, v in value.items()}
    return value


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
        if target.is_symlink() or has_symlink_parent(target) or (target.exists() and not target.is_file()):
            print(f"iac_scan: {option} {target} is a symlink; refusing to write through it", file=sys.stderr)
            return 2
        # The assessment writes nothing inside the repository it reads, and
        # a previous iac.json there would be rescanned as input.
        target_resolved = target.resolve()
        if target_resolved == resolved or resolved in target_resolved.parents:
            print(f"iac_scan: {option} {target} is inside the scanned repository; write it elsewhere",
                  file=sys.stderr)
            return 2
        # The same holds for an export directory: the next run would read it as an export.
        if any(Path(d).resolve() in target_resolved.parents for d in args.snapshots):
            print(f"iac_scan: {option} {target} is inside a --snapshots directory; write it elsewhere",
                  file=sys.stderr)
            return 2
    scan = run(root, args.snapshots)
    commit = git_commit(root)
    findings = printable(build_findings(scan.hits))
    result = printable(report(scan, root, commit, findings, args.snapshots))
    # Write the inventory first: a failed --out must not leave findings.json
    # describing a scan whose inventory was never saved.
    if args.out:
        try:
            write_json_atomic(args.out, result, mkdir=True)
        except OSError as e:
            print(f"iac_scan: cannot write {args.out}: {e.strerror or e}", file=sys.stderr)
            return 2
    else:
        json.dump(result, sys.stdout, ensure_ascii=False, indent=2)
        sys.stdout.write("\n")
    if args.into:
        try:
            merge_into(args.into, findings, printable(inventory_of(scan)), commit)
        except (OSError, ValueError, RecursionError) as e:
            print(f"iac_scan: cannot update {args.into}: {e}", file=sys.stderr)
            return 2
    counts = {s: sum(f["severity"] == s for f in findings) for s in SEV_RANK}
    print(f"iac_scan: {len(scan.files)} files, {len(scan.resources)} resources, {len(findings)} findings "
          f"(High {counts['High']}, Medium {counts['Medium']}, Low {counts['Low']}, Info {counts['Info']}); "
          f"{len(scan.not_run)} not run", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
