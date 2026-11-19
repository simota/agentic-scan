# Creative strategy (terminal / agent version)

On 2026-11-19 the brand and design were rebuilt from scratch. The previous version was an editorial style of ink black, off-white, Mincho serif type, and thin rules. That is a common pattern in AI-generated LPs, and the owner also pointed out 「AI 生成感が強い」 ("it feels strongly AI-generated"). The direction the owner chose was "terminal / agent".

## Concept

**Show the real product, where the product actually runs.**

agentic-scan is a set of skills that are invoked inside an agent session and leave a `findings.json` and a dashboard. So the LP's lead is that output itself: specifically, the result of running commands against the bundled samples. No copy is written just to create an impression. Every terminal output on screen is the unedited result of a command that was actually run.

## Core message

- Headline: 「コードに触れずに、裏の取れた指摘を。」 ("Findings that are backed up, without touching your code.")
  - 「コードに触れずに」 ("without touching your code") refers to read-only. Confirmed in each skill's README and SKILL.md.
  - 「裏の取れた」 ("backed up") refers to the verdict. The security-scan README says "every finding gets a verdict … with evidence".
- Supporting line: 「どの指摘にもファイルと行と検証の判定がつく」 ("every finding comes with a file, a line, and a verification verdict").
- Signature (the one thing only this product has): the `F-004  High  FalsePositive` row in the hero ledger.
  - A finding judged a false positive is kept, with its evidence, instead of being deleted.
  - This is based on the security-scan rule "Never: delete a finding judged false; mark it FalsePositive …". The bug / infra / logic / data-integrity / test-gap SKILL.md files have the same rule.
  - It is not a marketing line from another review tool; the product's own data shows that it "checks before handing over".

## Copy guidelines

- Write what the visitor gets rather than feature names (their code is not rewritten; findings arrive with verdicts).
- Write skill names, commands, and verdict values in English, in monospace, so they match the strings visitors actually type.
- Expressions in the previous version that did not match the facts were corrected. "All 12 skills follow the same procedure" was wrong, so each skill's procedure from its README is shown instead.
- No numbers, adoption record, or user testimonials, because the repository gives no basis for them.

## Conversion goal and flow

- Primary CTA: 「導入手順を見る」 ("See install steps") (`#install`). It leads to 3 steps — clone, `make link`, ask the agent — with working copy buttons.
- Secondary CTA: 「出力サンプルへ」 ("To output samples") (`#output`). It shows 4 real dashboards.
- Constraint: the repository is private. This is stated in the install section, and a GitHub link is also provided.

## Section structure

1. Hero: headline, lead, CTAs. On the right (below on mobile), a ledger of the real output of `jq … | column -t`.
2. skills: the real output of `make list` serves as the table of contents (each row links to a section). Each of the 12 skills gets its review focus, its README procedure, and one finding from its bundled sample.
3. verify (inverted band): 4 rules — read-only / verify / keep / decide.
4. output: 4 real dashboards in tabs. Also the real output of `make demo` and a list of output formats.
5. install: 3 steps, requirements, and the private-repository notice.
6. FAQ and footer.

## Design intent

- A monospace typeface carries the brand. It is used for the wordmark, nav, commands, verdicts, and skill names.
- Japanese body text uses Gothic (sans-serif) type for readability.
- The severity colors used by the skills' dashboards (High / Medium / Low / Info) are used directly as meaningful colors. The background is a cool gray, not paper.
- Avoided: green neon on black, glows or scanlines, fake typing effects, macOS window frames, gradient blobs.
