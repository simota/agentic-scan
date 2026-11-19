# agentic-scan

Twelve read-only review skills for agents, kept in one repository. Each skill
maps one aspect of an application, checks it, and delivers the findings as a
dashboard and a report. None of them edits the code under review.

## The skills

| Skill | Looks at |
|---|---|
| [`architecture-scan`](architecture-scan/) | Modules, dependencies and data ownership; layering, coupling, failure handling, operability |
| [`bug-scan`](bug-scan/) | How bugs entered, from git history; the same entry points still present in code; a defect register |
| [`data-integrity-scan`](data-integrity-scan/) | Write paths, schema and migrations; missing constraints, transaction gaps, lost updates |
| [`infra-security-scan`](infra-security-scan/) | Terraform/OpenTofu, CloudFormation and Kubernetes config; exposure, identity, attack paths |
| [`logic-scan`](logic-scan/) | Business rules; wrong results on realistic input, each with a counterexample |
| [`performance-scan`](performance-scan/) | Hot paths; N+1 and unbounded queries, indexes, blocking I/O, caching, bundles |
| [`privacy-scan`](privacy-scan/) | Personal data and where it flows; minimisation, consent, retention, third-party sharing |
| [`prompt-scan`](prompt-scan/) | LLM prompts, templates and agent definitions; broken variables, contradictions, injection boundaries |
| [`prune-scan`](prune-scan/) | What does not earn its place: dead code, unused features, flags, dependencies, config |
| [`security-scan`](security-scan/) | Application source; authn/authz, cross-tenant access, injection, secrets, dependencies |
| [`test-gap-scan`](test-gap-scan/) | The test suite; where a defect would slip through, and what to assert |
| [`ux-scan`](ux-scan/) | Screens and flows; layout, states, forms, accessibility, microcopy |

Each skill's own README describes its workflow and outputs.

## Diff mode

Every skill can review a change instead of the whole repository: a branch
against its base, a pull request, a commit range, or uncommitted work. Ask for
it in the request:

```text
/security-scan review only this branch against main
/logic-scan the diff of PR 123
/test-gap-scan my uncommitted changes
```

Each skill's `scripts/diffscope.py` takes the diff from the merge base, as a
pull request shows it, and the review covers the changed files and the code
they reach. A finding is kept only when the change causes, exposes or worsens
it; defects that were already there are mentioned in the chat summary, not
recorded. The report names the range and says it is not a full assessment, so
do not compare it with a full run. The procedure is in each skill's
`reference/diff-mode.md`.

## Language

The documentation is in English. Reports follow the user's language, chosen
in this order:

1. A language named when invoking the skill, as an argument or in the
   request: `lang=ja`, `lang=en`, "in English", "日本語で".
2. Otherwise, the language the user has set for the agent: a host setting
   such as Claude Code's `language`, or a standing instruction such as
   "always respond in Japanese".
3. Otherwise, the language of the request.

```text
/security-scan lang=en          # English report, whatever the agent's language
/ux-scan lang=ja                # Japanese report
```

The dashboards and reports are rendered in Japanese (`ja`) or English (`en`).
For any other language the report is rendered in English and the agent's
summary in chat uses the user's language. Each renderer also takes the
language directly: `scripts/render.py ... --lang ja|en`.

## Layout

```
agentic-scan/
├── Makefile             fans a target out to every skill
└── <name>/
    ├── Makefile         link, unlink, status, test, check, demo (+ skill-specific targets)
    ├── README.md
    ├── skills/<name>/   the installable skill: SKILL.md, reference/, scripts/
    ├── examples/        sample findings used by check and demo
    └── tests/           offline tests
```

Each `<name>/` directory was imported from its former standalone repository
(`simota/<name>`) with its full git history.

## Usage

From the repository root:

```sh
make link                       # symlink every skill into claude / codex / agy skills dirs
make status                     # what is linked, per skill and host
make check                      # tests + self-containment checks for every skill
make test ONLY="bug-scan ux-scan"
make link AGENT=claude          # AGENT, SKILLS_DIR, PYTHON pass through to each skill
```

A failing skill does not stop the others; the run exits non-zero at the end
and names the skills that failed.

To work on one skill, run its own Makefile: `make -C ux-scan demo`.
