# Performance Optimization Verification Record — 2026-11-04 (JST)

## A. Optimization Summary

The baseline commit is `ddaca26df47253abd12414282982f0aa87b792cf`. After confirming there were no uncommitted changes in the freshly checked-out working tree, work proceeded on a dedicated branch. We first performed a full audit, `make check`, and 3-scale measurements of the 8 existing workloads, then implemented and compared independent candidates. The execution environment was Python 3.12.14 / Linux x86_64. No new runtime dependencies were added.

Numbers in this record are empirical measurements on synthetic offline inputs and do not represent network audit speed or overall production performance. They are not treated as proof of non-regression across all metrics or inputs. Among synthetic fixtures, paths with adopted improvements are distinguished from unmodified control paths. Raw samples, conditions, output hashes, initial values, and re-measurements are saved in [measurement data](performance-2026-11-04.json).

### Areas Investigated

| Area | Scope & Assessment |
|---|---|
| Architecture & hot paths | Standard-library-centric Python CLI. Covered dependency scanning, findings updates, evidence capture/verification, HTML/PDF generation, contract checks, and run management. CI runs Python 3.9/3.12; part of Cargo workspace parsing uses `tomllib` from Python 3.11+. |
| Algorithms | Checked and measured ID duplicate detection, F/D classification, excluded-finding renumbering, Compose element selection, repeated workflow parsing, filename matching, and URL redaction. URL changes were ultimately reverted. |
| Memory & caching | Checked sorting temporaries, classification lists, report indexes, local LRU, string retention, and URL callback allocation. No persistent caches or cache-limit changes were introduced. |
| I/O & evidence | Preserved file type and symlink rejection, size/count/time limits, hashing, and before/after identity checks. Re-reads are not skipped. |
| Async, concurrency & recovery | Checked writer lock, inheritance by child processes, deadline termination, checkpoints, stage/rollback, and atomic publish. Product-side concurrency was not changed. |
| External audits & dependencies | Investigated external audit invocations, result parsing, and triage. Online network speed and load were not measured; parallelizing external audits and persistent result caching were deferred. |
| Database | No regular operational DB path exists. SQLite is used for count-limited reproduction fixtures. DB improvements are not counted as results. |
| HTML, JS/CSS & PDF | Investigated HTML generation, search/sort/lazy rendering, and printing. Verified existing JS search cache, debounce, lazy detail DOM construction, and shared Collator. JS/CSS/PDF implementations were not modified due to lack of browser and accessibility measurements. |
| Vendor & generated artifacts | `scan_report_kit` and its `MANIFEST` were not modified. Generated reports were not edited as product code. |
| CI & build | Checked Makefile, doc references, syntax, vendor integrity, sample rendering, self-scan, Python matrix, and mandatory Chrome/PDF gate. There is no conventional compile or frontend bundling step. |

### Implemented Optimizations

| Priority | Target | Problem & Change | Complexity & Compatibility Rationale |
|---|---|---|---|
| 1 | Contract check | Removed per-ID full `count` and finding-dict membership comparisons. Sort the ID list in place and diagnose adjacent duplicates once. Classify F/D in a single pass and release the no-longer-needed ID list. | Duplicate check O(N²)→O(N log N), classification O(N²)→O(N). Preserves lexicographical order of duplicates, uniqueness, diagnostic order, and relative F/D order. |
| 2 | Renumbering | Classify active/excluded in a single pass and sort with the same key as before. Release reference lists after classification. | Eliminated O(N×excluded) dict comparisons. Kept the initial ID scan to preserve exception precedence on malformed input. |
| 3 | Compose | Removed mutual membership checks between top-level elements and service-nested elements. | Source line ranges never overlap, so they never matched. Eliminated O(T×S) target selection while preserving inspected targets, order, and line numbers. |
| 4 | Workflow | Consolidated trigger extraction to once per text. Skip re-parsing for the local graph only when `./` (required for local references) is absent. | Preserves file reads, standard security checks, privilege/input propagation, ordering, limits, and incomplete-result detection. |
| 5 | Requirements detection | Moved prose-exclusion regex into the final `requirements/` branch where its result is needed. | Preserves short-circuit order, bool return value, and suffix iterable consumption count. Reduces redundant work for non-matching extensions and explicit requirements names. |

### Rejected Candidates

| Candidate | Decision & Reason |
|---|---|
| Early return on extension mismatch in requirements | Initial version increased CPU by ~6.2% when classifying inside `requirements` directories. Reverted and replaced with the deferred evaluation above. |
| Final candidate combining URL guard + shared callback | Improved CPU time and process RSS for OSV parsing and HTML generation, but repeatedly increased Python traced peak in normal-scale report runs. Because non-regression under normal conditions was not established, reverted the implementation and its 6 dedicated tests and re-ran all integrated comparisons. |
| URL syntax guard alone | Average CPU +2.240% (95% CI +0.428% to +3.960%) on non-URLs containing colons/percent signs. Rejected standalone. A combined variant removing callback creation was compared separately, then also reverted for the reason above. |
| Similar guard for `has_url_credentials` | Not retained due to insufficient evidence of non-regression. |
| Shared verification-catalog index in report | Improved time, but reverted because non-regression—including extra memory in standalone calls and internal API expansion—could not be established. |
| Skipping eager fallback for known labels | Changes LRU keys and eviction order. Tiny boundary peak differences flipped sign on reversal and were not judged a fixed regression, but reverted because non-regression including retained string size was not established. |
| Split header/body hashing for Git objects | Improved 16 MiB standalone, but added 32 B peak on 64 B input, shifted the [hashlib GIL release threshold](https://docs.python.org/3.12/library/hashlib.html), and failed to confirm clear gains on real Git; reverted. |
| Skipping evidence re-reads / sharing verification | Required to detect races, mutations, and stale results. Changes that weaken security boundaries are not adopted. |
| Global redaction cache, parallel external audits, reduced runner copies, narrower deepcopy scope, CI cache changes | Deferred due to insufficient verification of retention size, invalidation, error ordering, recovery, external load, and real CI impact. |

`render.py`, `url_redaction.py`, `evidence_integrity.py`, vendored assets, execution limits, dependencies, and mandatory CI checks remain identical to the baseline.

## B. Changed Files

| File | Change & Purpose | Compatibility & Verification |
|---|---|---|
| `skills/security-scan/scripts/contract_check.py` | Reduced repeated work in duplicate ID checks and finding classification; shortened temporary list lifetime | Diagnostic order/content and input immutability; randomized/invalid IDs and missing outputs; 6 regression tests |
| `skills/security-scan/scripts/findings.py` | Single-pass active/excluded classification and release of temporary lists | Numbering, dict insertion order, exception precedence, excluded ratios; 6 regression tests |
| `skills/security-scan/scripts/deps_scan.py` | Reduced redundant work in Compose, workflow, and filename detection | 2,861-case differential match, 8 regression tests, I/O counters |
| `scripts/ci/benchmark_performance.py` | Optional CPU, P95/P99, throughput, Python peak, and RSS measurement | Regression test preserving default JSON keys; separates timing from allocation measurement |
| `scripts/ci/benchmark_pipeline.py` | 3-scale scan/contract/renumber/HTML/URL/Git-control fixtures | Identical fixtures, full output hashes, benign offline inputs |
| `scripts/ci/compare_performance.py` | Alternating comparison in separate interpreters, output matching, raw samples, bootstrap intervals | Refuses overwriting fixed revisions, timeout & child termination, same-revision smoke test |
| `tests/test_contract_performance.py` | 6 regression tests | Executed as part of full suite |
| `tests/test_findings_renumber_performance.py` | 6 regression tests | Executed as part of full suite |
| `tests/test_scan_efficiency.py` | 8 regression tests | Executed as part of full suite |
| `tests/test_performance_harness.py` | 3 regression tests | Verifies default output format, reserved args, and completion of 2-worker comparison |
| `README.md` | Measurement instructions and new comparison command | Doc reference check |
| `docs/ci.md` | Conditions, limitations, RSS scope, and reproduction commands | Doc reference check |
| `docs/performance-2026-11-04.md` | This report | Performance tables generated from raw data |
| `docs/performance-2026-11-04.json` | Raw samples, hashes, execution conditions, and decision evidence | Does not impute unmeasured values |

## C. Performance Comparison

### Methodology

- Same Linux environment and Python, CPU affinity 1, `PYTHONHASHSEED=0`, no bytecode writing. Measured baseline worktree and candidate using the same latest harness.
- Separate interpreter per revision; after 3 warmups, 21 pairs alternated before→after and after→before. Timed operations never ran concurrently.
- Input generation, copying, IPC, and result hashing are outside the timed region. OS/filesystem cache is warm and distinct from cold-cache measurements.
- Wall/CPU timing was separated from 3 tracemalloc runs. Exact full-result hash match was required on every run. Dict insertion order for renumbering was also verified via a separate differential test.
- Intervals are 95% intervals for the mean time ratio from 3,000 paired bootstrap resamples. Results spanning 1 are not treated as proof of improvement or equivalence. Because these are unadjusted intervals across many cases and even same-revision controls show occasional bias, adoption was not decided by a single significance check alone; re-measurements and code structure were also inspected.
- P95/P99 use nearest-rank. P99 over 21 runs is the observed maximum and does not estimate production tail/SLO.
- Throughput is 1 batch / mean time, not product concurrent request capacity.
- Python peak is newly traced allocations during the operation, excluding prior inputs and imports. RSS is the worker process high-water mark, including prior workloads and tracing. Do not conflate the two.

### High-Load Workloads

| Workload | Before P50 ms | After P50 ms | P50 Change | Mean Time Ratio 95% CI | Output |
|---|---:|---:|---:|---|---|
| Compose (1,500 services / 1,000 extensions) | 53.335 | 33.619 | -36.97% | 0.606–0.640 | Match |
| Remote workflow (48 files × 160 steps) | 379.463 | 327.099 | -13.80% | 0.817–0.908 | Match |
| Workflow with local actions (48 files × 160 steps) | 403.498 | 405.701 | +0.55% | 0.942–1.056 | Match |
| Source tree (10,000 files) | 471.338 | 437.467 | -7.19% | 0.906–0.976 | Match |
| Contract check (1,800 findings) | 94.160 | 5.346 | -94.32% | 0.055–0.064 | Match |
| Renumbering (999 findings, half excluded) | 12.904 | 1.232 | -90.45% | 0.079–0.108 | Match |
| HTML 2 variants (400 findings, 500 evidence, 200 runs) | 938.391 | 952.789 | +1.53% | 0.994–1.039 | Match |
| 10,000 fields without URLs | 14.146 | 14.325 | +1.27% | 0.938–1.028 | Match |
| 500 URLs/line × 20 lines | 79.271 | 80.001 | +0.92% | 0.979–1.033 | Match |
| ~21 Ki chars, trailing delimiters × 100 lines | 167.094 | 166.131 | -0.58% | 0.973–1.093 | Match |
| Workspace discovery (600 members) | 617.295 | 576.435 | -6.62% | 0.945–1.047 | Match |
| Source excerpts (500 findings, 10,000 lines) | 40.760 | 41.205 | +1.09% | 0.905–1.034 | Match |
| Existing HTML fixture (400 findings) | 987.856 | 988.932 | +0.11% | 0.942–1.040 | Match |
| Triage without source model (100 findings) | 0.944 | 1.017 | +7.65% | 0.929–1.224 | Match |
| Live-integrity HTML (200 findings, 500 evidence) | 1674.410 | 1736.688 | +3.72% | 0.943–1.025 | Match |
| OSV distinct groups (2,000 records) | 393.577 | 388.323 | -1.33% | 0.919–1.002 | Match |
| OSV alias pairs (2,000 records) | 300.110 | 301.903 | +0.60% | 0.925–1.044 | Match |
| OSV ungrouped (2,000 records) | 416.208 | 415.009 | -0.29% | 0.952–1.019 | Match |

### By Metric: Contract Check (1,800 Findings)

| Metric | Before | After | Change | Verdict |
|---|---:|---:|---:|---|
| Mean runtime | 95.742 ms | 5.702 ms | -94.04% | Improved |
| P50 | 94.160 ms | 5.346 ms | -94.32% | Improved |
| P95 | 114.371 ms | 8.420 ms | -92.64% | Improved |
| P99 (observed max) | 125.639 ms | 9.424 ms | -92.50% | Improved |
| CPU time P50 | 94.157 ms | 5.349 ms | -94.32% | Improved |
| Serial throughput | 10.445 checks/s | 175.379 checks/s | +1579.11% | Improved |
| Python peak (median of 3) | 1,472,420 B | 1,456,252 B | -1.10% | Improved |
| File reads | 4 | 4 | 0% | Identical read volume (separate I/O measurement) |
| Physical disk I/O, online network, DB load | Unmeasured | Unmeasured | — | Unverified / no regular DB path |
| CPU utilization, GC pause, concurrent throughput | Unmeasured | Unmeasured | — | Unverified |

### P50 Change Across All Scales

Values are point estimates from each initial integrated comparison. Small-scale noise and re-measurement results are not omitted. Fluctuations on unmodified control paths such as URL and HTML are not counted as improvements. See the measurement data for raw samples and confidence intervals.

| Workload | small | normal | high |
|---|---:|---:|---:|
| compose | -0.82% | +0.88% | -36.97% |
| workflow_remote | -10.17% | -17.43% | -13.80% |
| workflow_local | -8.52% | +0.81% | +0.55% |
| source_tree | -7.71% | -3.26% | -7.19% |
| contract | +7.93% | -50.93% | -94.32% |
| renumber | -17.24% | -78.67% | -90.45% |
| verification_catalog | -3.03% | -0.23% | +1.53% |
| url_plain | +1.52% | -2.17% | +1.27% |
| url_dense | +0.11% | -6.28% | +0.92% |
| url_symbols | -0.11% | -0.32% | -0.58% |
| offline_workspaces | -1.06% | -2.09% | -6.62% |
| shared_source_excerpts | -9.55% | -2.15% | +1.09% |
| structured_verification_report | -2.41% | +3.22% | +0.11% |
| triage_without_source_model | -2.80% | -12.95% | +7.65% |
| live_integrity_report | -6.08% | -1.64% | +3.72% |
| osv_distinct_groups | -7.73% | +1.98% | -1.33% |
| osv_alias_pairs | +0.38% | -1.10% | +0.60% |
| osv_ungrouped | -4.87% | -5.20% | -0.29% |

### Additional Small-Scale, Memory, and Startup Verification

Small-scale contract check showed a P50 increase in the initial 21 pairs, so the same harness and input were re-measured with 501 pairs. The table below shows that re-measurement; initial values remain in the table above and in the raw data. Because the time-ratio interval spans 1, this is treated neither as an improvement nor as proof of equivalence.

| Metric | Before | After | Verdict |
|---|---:|---:|---|
| P50 | 0.333156 ms | 0.333386 ms | +0.069%, no clear difference confirmed |
| Mean time ratio 95% CI | — | 0.979–1.050 | Not proof of equivalence |
| Python peak | 207,802 B | 207,625 B | Decreased |

Initial scan comparisons used separate fixture directories. Because differences of 4 B appeared in Compose and 4 / 36 / 96 B in source tree, we re-ran each revision in a fresh interpreter with 3 warmups + 5 traces using the exact same real files, inodes, contents, and stable metadata. High-load Compose and all 3 scales of source tree matched identically across all 5 paired samples in both peak and retained data.

| Shared Input | Before Python Peak Median | After Python Peak Median | Result |
|---|---:|---:|---|
| high/compose | 1,336,553 B | 1,336,553 B | Output, order, retained size, and all peaks matched |
| small/source_tree | 48,892 B | 48,892 B | Output, order, retained size, and all peaks matched |
| normal/source_tree | 1,965,721 B | 1,965,721 B | Output, order, retained size, and all peaks matched |
| high/source_tree | 12,537,983 B | 12,537,983 B | Output, order, retained size, and all peaks matched |

In `small/local workflow`, a 59 B difference remained on the first trace, with an 8 B difference in the 5-run median. In a re-measurement reversing the revision execution order with the same real files and worker, all 5 paired samples matched identically (38,432 / 38,424 / 38,416 / 38,408 / 38,392 B). The initial difference is recorded without omission and is not judged a persistent increase.

Differences also remain in controls using unmodified rendering functions: normal catalog Python peak median was 5,123,424→5,123,706 B (+282 B), and high live-integrity was 10,579,175→10,585,144 B (+5,969 B). Static analysis confirmed that the timed bodies of both paths do not call any function modified in this work. Although fluctuations are also observed in same-revision controls, import state and prior workloads are involved, so the mechanism of these residuals was not definitively attributed to measurement noise. They are not counted as evidence of speedup or exact memory equivalence.

Startup was compared across 4 CLIs via `--help` in fresh interpreters for 31 pairs each. To eliminate differences from pre-existing bytecode, both revisions used the same empty bytecode prefix. To further eliminate script path differences, only the 3 product files were swapped into an identical working copy outside the timed region, verifying byte identity of all changed files before launch. Bytecode was neither read nor written. The OS file cache was warm, differing from cold-cache startup. The first 2 runs measured with different script paths are also retained in the preliminary section of the raw data.

| CLI | Before Startup P50 ms | After Startup P50 ms | Mean Time Ratio 95% CI | Before/After RSS Median B |
|---|---:|---:|---|---:|
| deps_scan.py | 361.791 | 353.288 | 0.954–1.028 | 27,172,864 / 27,164,672 |
| findings.py | 276.994 | 289.018 | 0.994–1.090 | 23,310,336 / 23,285,760 |
| contract_check.py | 196.392 | 195.057 | 0.970–1.050 | 17,354,752 / 17,354,752 |
| render.py | 330.760 | 318.112 | 0.955–1.034 | 22,204,416 / 22,204,416 |

The RSS figures above are whole-process high-water marks including the wrapper, imports, and source compilation. Improvement or non-regression is not concluded from small point-estimate differences in startup time or RSS alone. All samples and CPU intervals are saved in the raw data.

### Other Memory & I/O Verification

A 1,800-finding full contract check with randomized ID order was also compared with all output files missing. Under this condition where large JSON reads do not mask the peak, diagnostics matched across valid, invalid, and mixed cases, and peak dropped by ~16 KiB in all 3 cases. Renumbering reduced peak across all 9 combinations of 0/1/10/999 findings and none/half/all excluded.

In scan Python file API counters, call counts and input bytes read were identical for Compose, source tree, and local workflow. Remote workflow kept 40 `read_text` calls and 141,035 B, while `stat` changed 170→166 and `lstat` 426→394. These are Python API observations, not measurements of physical disk transfer or OS cache misses.

Integrated trials and follow-up diagnostics that included the URL candidate were isolated under `pre_integration_experiments` as `rejected_url_integrated` / `rejected_url_followups` and are not reused in adopted figures. After reverting that candidate, a full comparison between baseline and final state was re-run. Additional final-state comparisons are stored under `followups`.

## D. Quality Assurance Results

- Initial `make check`: 1,097 run, 1,071 passed, 0 failed, 0 errors, 26 existing opt-in skipped.
- Final `make check`: 1120 run, 1094 passed, 0 failed, 0 errors, 26 skipped. All 23 added tests passed.
- Added tests verify outputs, ordering, error paths, input immutability, and comparison-count bounds rather than runtime thresholds.
- Verified identical-content/different-order IDs, missing/non-string/Unicode IDs, duplicates and identical dicts, excluded findings, Compose legacy/empty/repeated sections, local call propagation, escaped triggers, and suffix generators.
- The evaluated URL proposal was also differentially tested for types, exceptions, quote positions, and multi-encoding, then reverted because memory non-regression was not established. Its 6 dedicated tests are excluded from the final suite count. Existing URL and redaction regression tests run in the full suite.
- Ran `make benchmark`, `make detection-benchmark`, doc references, vendor MANIFEST, sample rendering, self-dependency scan, `git diff --check`, and Node JS syntax check.
- Parsed all Python files with Python 3.9 grammar via AST. This is distinct from actual Python 3.9 runtime testing or type checking.
- No dedicated type checker or linter configuration exists; mypy/ruff success is not claimed. There is no standard compile/bundle step; `make check` serves as the distribution integrity gate.
- Startup verification compared CLI `--help` in fresh interpreters for 31 pairs each, matching output hashes and recording warm-filesystem and identical `runpy` wrapper conditions plus all samples in the measurement data.

### Browser, PDF, and CI

Executable Chrome/Chromium and Python Playwright are not available locally, so the 26 existing opt-in tests were not run. The mandatory browser/PDF gate is not treated as passed.

In baseline [CI run 41657402714](https://github.com/simota/security-scan/actions/runs/41657402714), the Python 3.9/3.12 jobs passed, while the `reports` job failed at the Chrome version guard before tests ran: observed version `156.0.8078.79` vs allowed `155.0.8059.39,156.0.8078.47`. Neither the allowlist, mandatory tests, nor no-skip requirements were relaxed. See PR Checks for candidate commit CI results.

## E. Residual Risks & Exit Criteria

1. Real network audits, external service load, cold-cache startup, physical disk transfer, GC pause distribution, and multi-user P95/P99 and concurrent throughput are unverified.
2. Small report peak fluctuations and timing noise are distinguished via initial values, re-measurements, and same-revision controls. A confidence interval spanning 1 does not by itself prove equivalence.
3. Verifying browser rendering quality, accessibility, and Japanese/English PDF generation requires restoring an approved real browser environment.
4. Remaining opportunities exist in shared catalog indexing, global caching, parallel external audits, and reduced runner copies, but they remain deferred until non-regression—including retention, invalidation, races, and fault recovery—can be verified.
5. Improvement rates and operational cost savings in unverifiable areas are not estimated. Work stopped before adding high-risk changes or complexity chasing effects within measurement noise.

## Reproduction

"Offline performance comparisons" in `docs/ci.md` describes the commands to compare both worktrees under the same harness and the scope of each metric. Use `comparison_invocations` in the measurement data for exact sizes, arguments, and environment. Production file SHA-256 digests for baseline and candidate commits are also recorded there. Benchmarks never execute external audit commands, target applications, or recorded reproduction commands.
