# Perspectives — reviewing a prompt from more than one angle

**Read when:** CHECKLIST, to choose which perspectives apply; REVIEW, as the
sweep over each review unit; REPORT, to fill the `perspectives` list in
`findings.json`. Reader: the agent running the skill.

Apply each perspective within every review unit (`SKILL.md`, *Run contract*)
and work through its hunt steps. A step is sound only when the text or code
that makes it sound can be cited as `path:line`. "The model will figure it
out" is not evidence.

| Perspective | The question it asks |
|---|---|
| Task and intent | Does the prompt state what to do, for whom, and what a good result looks like? |
| Instruction consistency | Do any two instructions contradict, or override each other in a way the author did not intend? |
| Structure and placement | Can the model tell instructions from data, and are the important constraints where they will be read? |
| Variables and assembly | Is every variable filled, escaped and placed as intended in the message actually sent? |
| Output contract | Does the format the prompt asks for match what the consumer parses, including when the model deviates? |
| Examples | Are the few-shot examples correct, representative, consistent with the instructions and free of leaks? |
| Tools and agents | Do tool and agent descriptions say when to use them, what arguments mean and what they must not do? |
| Untrusted input | Can text from users, documents, web pages or tool results override the instructions, and what can the model do while reading it? |
| Safety and refusal | Does the prompt prevent harmful output without refusing legitimate requests? |
| Context budget | Does everything important fit, and what is dropped first when it does not? |
| Model and parameters | Do the model ID, temperature, token limits and other parameters suit the task? |
| Language and tone | Is the output language, register and audience stated and consistent? |
| Evaluation | Is there an eval, test or golden set that would catch a regression in this prompt? |
| Maintainability | Is the prompt versioned, deduplicated and owned, so a change in one place does not silently diverge? |

## Hunt steps per perspective

### Task and intent (TI)

| Step | Hunt | Sound when |
|---|---|---|
| TI1 | The task is implied, not stated (a role line with no instruction, a list of rules with no goal) | One sentence says what to produce and for whom |
| TI2 | The success criterion is missing: no length, depth, audience or definition of done | The prompt says what a good answer contains, or the consumer constrains it |
| TI3 | Vague evaluative words with no anchor ("concise", "professional", "high quality", "appropriately") | Each is anchored by a number, an example or a contrast |
| TI4 | Context the model needs but does not have (who the user is, why the task exists, domain terms) | The prompt supplies it, or a variable does and is filled |
| TI5 | Negative-only instructions ("don't do X") with no statement of what to do instead | Each prohibition has a positive alternative |

### Instruction consistency (IC)

| Step | Hunt | Sound when |
|---|---|---|
| IC1 | Two instructions that cannot both hold ("be brief" / "explain every step"; "answer only in JSON" / "greet the user") | A priority or scope is stated for each |
| IC2 | A later layer contradicts an earlier one: system vs template vs appended per-request text vs tool description | The layers are read in send order and agree, or the precedence is stated |
| IC3 | Absolute words (always, never, must) on rules that have legitimate exceptions | The exception is written next to the rule |
| IC4 | A rule copied into several prompts with different wording or values | One source, or the copies agree |
| IC5 | Instructions that refer to sections, tools, fields or files that no longer exist | Every reference resolves in the prompt as sent (lint `missing-file-reference` checks cited files) |

### Structure and placement (ST)

| Step | Hunt | Sound when |
|---|---|---|
| ST1 | Data and instructions run together with no delimiter | Data sits inside named tags, fences or a separate message |
| ST2 | The key constraint is buried in the middle of a long block, or stated only once far from where it applies | It is near the task statement or repeated at the point of use |
| ST3 | Long documents placed after the question in a long-context prompt | Documents first, question and instructions last, or the reason for the other order is clear |
| ST4 | Inconsistent tag names or nesting (`<doc>` opened, `<document>` closed) | Tags are balanced and named consistently (lint `unclosed-tag` helps) |
| ST5 | Instructions placed in the user turn that belong in the system prompt, or the reverse | Stable behaviour lives in system; per-request data in user |

### Variables and assembly (VA)

| Step | Hunt | Sound when |
|---|---|---|
| VA1 | A template variable that no call site fills, or a call site that fills a name the template does not use | Every name matches between template and call site (`inventory.json` `bindings`; lint `unfilled-variable`, `unused-render-key` and `unreferenced-variable` help) |
| VA2 | Empty or missing values: the variable is optional in code but the prompt reads as if it is present | The template handles the empty case, or the code guarantees a value |
| VA3 | Escaping: literal braces in a format string, a value containing the delimiter, Jinja autoescape producing `&lt;` in the prompt | Values are escaped for the template engine and cannot close the surrounding tag |
| VA4 | Type and formatting: a list or object interpolated with its repr (`['a', 'b']`, `[object Object]`), dates without timezone, numbers without units | The value is formatted for a reader |
| VA5 | Message assembly: wrong role, two consecutive same-role messages where the API forbids them, system text placed in a user message, history order reversed | The message list as sent matches the intended conversation |
| VA6 | Retry and fallback paths that send a different, older or partial prompt | Every path sends the reviewed prompt |

### Output contract (OC)

| Step | Hunt | Sound when |
|---|---|---|
| OC1 | Field names, types or enum values in the prompt differ from the parser or schema | They match field by field (cite both `path:line`; lint `unrequested-output-key` helps, `call_sites[].params` gives the call's literal parameters) |
| OC2 | The prompt asks for JSON but allows prose around it, and the parser does not strip it | Structured output, a prefill, or a tolerant parser |
| OC3 | No instruction for the empty, unknown or refusal case, so the model invents a value | The prompt names the value for "none" or "cannot answer" and the consumer handles it |
| OC4 | The parser's failure path: crash, silent default, or retry loop without a limit | Failure is detected and handled visibly |
| OC5 | Length limits: the requested output can exceed `max_tokens`, truncating the structure | The limit leaves room for the largest valid output, or truncation is detected (`call_sites[].params` holds a literal `max_tokens`) |

### Examples (EX)

| Step | Hunt | Sound when |
|---|---|---|
| EX1 | An example that violates the prompt's own rules or format | Every example passes the output contract |
| EX2 | All examples share one surface pattern (same length, same label, same opening), so the model copies it | Examples vary along the dimensions that matter |
| EX3 | Examples contain real customer data, secrets or another tenant's content | Examples are synthetic |
| EX4 | Examples are not marked as examples and can be mistaken for the current input | They sit inside example tags or are clearly labelled |
| EX5 | A hard case the instructions mention has no example | The hardest stated case is illustrated, or the reason it is not is clear |

### Tools and agents (TA)

| Step | Hunt | Sound when |
|---|---|---|
| TA1 | A tool description that says what it is but not when to use it, or when not to | Both are stated |
| TA2 | Parameter descriptions missing units, formats, ranges or examples | Each parameter is unambiguous to a reader with no code access |
| TA3 | Overlapping tools with no rule for choosing between them | The descriptions distinguish them |
| TA4 | A side-effecting tool (send, delete, pay, write) with no confirmation or scope rule | The prompt or the code gates it |
| TA5 | Agent or skill frontmatter (name, description, allowed tools) that does not match the body, or a description too vague to trigger | Frontmatter and body agree; the description names when to use it |
| TA6 | Instructions that assume a tool exists that is not passed on this call path | The tool list as sent contains every tool the prompt mentions |

### Untrusted input (UI)

| Step | Hunt | Sound when |
|---|---|---|
| UI1 | Untrusted text interpolated into the system prompt or into instructions rather than delimited data | It is in a user turn or a tagged data block, never in instruction position |
| UI2 | No statement that instructions inside the data are to be treated as data | The prompt says so, and the data is delimited so it cannot close the tag |
| UI3 | The model can call side-effecting tools, reach other users' data or send messages while reading untrusted text | Capabilities are reduced while reading untrusted text, or each action is confirmed or checked in code |
| UI4 | Output rendered as HTML/Markdown or executed (links, images, code) without sanitising, so injected text can exfiltrate data | Output is escaped or the renderer is restricted |
| UI5 | Secrets, internal URLs or other users' data placed in the prompt where an injection could make the model repeat them | Only what this reader may see is in the prompt |

### Safety and refusal (SR)

| Step | Hunt | Sound when |
|---|---|---|
| SR1 | Blanket prohibitions that will refuse legitimate requests in this product's domain | Each restriction is scoped to the harm it prevents |
| SR2 | A harm the product can plausibly cause with no instruction about it (medical, legal, financial advice; minors; self-harm) | The relevant guidance exists, or the domain makes it irrelevant |
| SR3 | No instruction for what to do when declining, so the consumer receives an unparseable refusal | The refusal shape is defined and handled (see OC3) |
| SR4 | Persona or role-play instructions that could be used to talk the model out of its other rules | The persona is subordinate to the rules, stated explicitly |

### Context budget (CB)

| Step | Hunt | Sound when |
|---|---|---|
| CB1 | Estimated prompt size (`inventory.json` `est_tokens`) close to or over the model's context, at realistic variable sizes | There is headroom at the largest realistic input |
| CB2 | Truncation code that cuts from the start (dropping system or instructions) or mid-structure | It cuts low-priority content first and keeps instructions |
| CB3 | Conversation history growing without a summary or window | History is bounded |
| CB4 | Large static text resent on every call with no caching where the provider supports it | Caching is used, or the cost is accepted in `decisions` |
| CB5 | Redundant text: the same rule stated many times, boilerplate the model does not need | Each rule appears where it is needed |

### Model and parameters (MP)

| Step | Hunt | Sound when |
|---|---|---|
| MP1 | A hard-coded model ID that may be deprecated or retired (check the vendor's current list) | The ID is current, or configurable and documented |
| MP2 | Temperature or sampling unsuited to the task (high temperature for extraction or classification; zero for creative generation) | The setting matches the task, or the reason is recorded |
| MP3 | `max_tokens` too small for the expected output, or unset where the API requires it | It fits the largest valid output |
| MP4 | Prompt features the chosen model does not support (prefill, a tool-choice mode, a system role) | The feature exists for that model |
| MP5 | The same prompt used across models of different capability with no per-model adjustment | Differences are tested or handled |

### Language and tone (LT)

| Step | Hunt | Sound when |
|---|---|---|
| LT1 | Output language not stated, so it follows the input language unpredictably | The language rule is explicit |
| LT2 | Prompt written in one language with examples in another, or mixed terminology for the same thing | Terms are consistent |
| LT3 | Tone or register unspecified for an end-user-facing output | Audience and register are stated |
| LT4 | Locale formats (dates, currency, honorifics) left to the model | They are specified or formatted in code |

### Evaluation (EV)

| Step | Hunt | Sound when |
|---|---|---|
| EV1 | No eval, golden set or snapshot test covers this prompt | One exists (cite it) |
| EV2 | Tests mock the model and so cannot catch prompt regressions | At least one check exercises the real prompt text (snapshot) or the real model (eval) |
| EV3 | The eval covers only happy-path inputs | It includes the hard and adversarial cases the prompt mentions |
| EV4 | No record of which prompt version produced which results | Prompts are versioned and results reference the version |

### Maintainability (MT)

| Step | Hunt | Sound when |
|---|---|---|
| MT1 | The same prompt text copied into several files or languages | One source, rendered where needed |
| MT2 | Prompts built from string concatenation scattered across functions, so the full text is visible nowhere | The full template lives in one place |
| MT3 | Placeholder or TODO text left in a shipped prompt (lint `placeholder`) | None remain |
| MT4 | No owner or change history for a prompt that controls a production behaviour | The repository records it |

## Recording

Record every perspective in the report, including the ones that found nothing
and the ones not run:

- A perspective not applicable to these prompts is recorded as `N/A` with a
  reason, not silently skipped
- A perspective that could not be checked statically is recorded as
  `not checked` with what would be needed
- Every finding names the perspective that surfaced it in `category`, using the
  exact name from the first table
- The `note` lists the hunt step IDs applied and each one left out with its
  reason (e.g. `TI1–TI3; TI4 N/A: no end users`)
