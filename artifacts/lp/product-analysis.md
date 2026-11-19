# Product analysis

## Overview

agentic-scan is a collection of 12 skills that AI coding agents (Claude Code, Codex, Antigravity) use to read and diagnose a target repository. Each skill is independent per review focus, records findings with a common procedure (RECON → CHECKLIST → REVIEW → VERIFY → REPORT; some include PLAN), and returns them as a chat summary, an HTML dashboard, and a report.

Sources: the root `README.md`, and the opening and "What it does" / "Install" sections of each `<skill>/README.md`.

## Confirmed facts (used in the LP's messaging)

| Fact | Source |
|---|---|
| 12 skills (security, infra-security, privacy, logic, data-integrity, bug, test-gap, architecture, performance, prune, ux, prompt) | Table in the root `README.md` |
| Read-only by default. Does not edit code and does not contact deployed systems | Note at the top of each README |
| Exceptions: logic-scan's REPRO, test-gap-scan's and data-integrity-scan's GUARD, and performance-scan's benchmarks run only when requested and permitted | `logic-scan/README.md`, `test-gap-scan/README.md`, `data-integrity-scan/README.md`, `performance-scan/README.md` |
| infra-security-scan does not call cloud APIs and does not run `terraform plan/apply` | `infra-security-scan/README.md` |
| privacy-scan is not legal advice | `privacy-scan/README.md` |
| ux-scan judges by criteria, not taste (the `padding: 13px` example) | `ux-scan/README.md` |
| High / Medium are re-verified (VERIFY) before reporting | The "What it does" diagram in each README |
| Outputs: chat summary, dashboard.html, report.md / report.html / PDF (varies by skill), findings.json | The diagram in each README |
| SARIF export, comparison with a re-scan, Japanese and English output | Stated in all 12 READMEs (confirmed with grep) |
| Python 3.9+ (some 3.10+), standard library only, Chrome / Chromium for PDF | Requirements in each README |
| `make link` links to every installed host (claude / codex / agy) | Each skill's `Makefile`, the root `Makefile` |
| `make demo` generates a dashboard from the bundled sample | Each README; confirmed by running it |
| Sample finding titles (the right column of the LP's 12 rows) | Extracted from each `examples/findings.sample*.json` |

## Target

- Primary: developers and tech leads writing their own app's code with AI agents. People who want to hand review to the agent too, but feel that findings which merely sound plausible are useless.
- Problems: findings lack a location, evidence, and a done condition. Worry that the agent will change code on its own. Separate tools for each review focus (security, UX, data integrity…).
- Alternatives: generic code-review requests, individual static analysis tools, human review.
- Reasons to hesitate: worry about code being rewritten, contact with production or the cloud, setup effort, reliability of results.
- Deciding factors: read-only by default, verified verdicts, findings with file and line, no dependencies and only `make link`.

## Assumptions (no basis in the repository)

- The persona and psychological barriers above are assumptions. User data, adoption record, satisfaction, and the like do not exist in the repository, so they are not on the LP.
- No pricing or license statement was found, so the LP does not mention them.

## Differentiation (within what can be confirmed)

1. 12 dedicated skills, one per review focus, share the same procedure and report format.
2. A verdict (Confirmed / Valid, etc.) reached through verification (falsification) is recorded for each finding.
3. Read-only by default. Procedures that write run only when requested and permitted.
4. No external packages needed.
