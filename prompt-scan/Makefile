# prompt-scan — install helpers
#
#   make link        symlink skills/prompt-scan into every installed host's skills dir
#   make unlink      remove those symlinks
#   make status      show what is installed, per host
#   make test        run the offline regression tests
#   make check       tests + verify the skill is self-contained and internally consistent
#   make inventory   prompt inventory and lint of TARGET
#   make lint        the lint alone, for CI: TARGET, FAIL_ON=High, SARIF=file, BASELINE=reviewed findings.json
#   make demo        render examples/findings.sample.ja.json (LANG_OUT=en: findings.sample.json) into $(DEMO_OUT)
#   make compare     what changed between BASE and FINDINGS (two findings.json files)
#   make export      FORMAT=summary|sarif|issues export of FINDINGS (OUT=file or directory)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=en NO_PDF=1     # English, HTML only

NAME    := prompt-scan
REPO    := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
SKILL   := $(REPO)/skills/$(NAME)
PYTHON  ?= python3

AGENT   ?= claude codex agy
PROJECT ?=

CODEX_HOME ?= $(HOME)/.codex
AGY_HOME   ?= $(HOME)/.gemini/antigravity-cli

# Each target is one quoted 'guard|dir' word, so paths may contain spaces.
tgt_claude := '$(HOME)/.claude|$(HOME)/.claude/skills'
tgt_codex  := '$(CODEX_HOME)|$(CODEX_HOME)/skills'
tgt_agy    := '$(AGY_HOME)|$(AGY_HOME)/skills'

UNKNOWN := $(filter-out claude codex agy,$(AGENT))
ifneq ($(UNKNOWN),)
$(error unknown AGENT '$(UNKNOWN)' - use claude, codex or agy, or set SKILLS_DIR)
endif

ifneq ($(SKILLS_DIR),)
QTARGETS := '$(SKILLS_DIR)|$(SKILLS_DIR)'
WHERE    := SKILLS_DIR=$(SKILLS_DIR)
else ifneq ($(PROJECT),)
QTARGETS := '$(PROJECT)|$(PROJECT)/.claude/skills'
WHERE    := PROJECT=$(PROJECT)
else
QTARGETS := $(foreach a,$(sort $(AGENT)),$(tgt_$(a)))
WHERE    := $(AGENT)
endif

DOCS := README.md docs/*.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md skills/$(NAME)/templates/*.md

DEMO_OUT ?= $(or $(TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample$(if $(filter ja,$(LANG_OUT)),.ja,).json
NO_PDF   ?=

.PHONY: help link unlink status check demo inventory lint test compare export

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(lastword $(MAKEFILE_LIST)) \
	  | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
	@echo
	@echo "  skill:  $(SKILL)"
	@echo "  vars:   AGENT PROJECT SKILLS_DIR CODEX_HOME AGY_HOME TARGET OUT BASE FINDINGS FORMAT FAIL_ON SARIF BASELINE"
	@echo "          DEMO_OUT DEMO_INPUT LANG_OUT NO_PDF PYTHON"

link: ## symlink the skill into every installed host's skills dir
	@n=0; \
	for t in $(QTARGETS); do \
	  guard=$${t%%|*}; dir=$${t##*|}; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - $$guard does not exist"; continue; fi; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink "$$d")" = "$(SKILL)" ]; then echo "ok       $$d already linked"; n=$$((n+1)); continue; fi; \
	    echo "refusing $$d is a symlink to $$(readlink "$$d") - resolve it, then re-run" >&2; exit 1; \
	  elif [ -e "$$d" ]; then \
	    echo "refusing $$d exists and is not a symlink - move it aside first" >&2; exit 1; \
	  fi; \
	  mkdir -p "$$dir" && ln -s "$(SKILL)" "$$d" || exit 1; \
	  echo "linked   $$d -> $(SKILL)"; n=$$((n+1)); \
	done; \
	if [ $$n -eq 0 ]; then echo "nothing linked - no skills directory found for: $(WHERE)" >&2; exit 1; fi; \
	echo "invoke it with:  prompt-scan   (or /prompt-scan in a slash-command harness)"

unlink: ## remove the symlinks this Makefile created
	@for t in $(QTARGETS); do \
	  dir=$${t##*|}; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink "$$d")" = "$(SKILL)" ]; then rm -f "$$d"; echo "unlinked $$d"; \
	    else echo "left     $$d - points at $$(readlink "$$d"), not this repo"; fi; \
	  elif [ -e "$$d" ]; then echo "left     $$d - not a symlink"; \
	  else echo "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@for t in $(QTARGETS); do \
	  guard=$${t%%|*}; dir=$${t##*|}; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - host not installed"; \
	  elif [ -L "$$d" ]; then echo "symlink  $$d -> $$(readlink "$$d")"; \
	  elif [ -d "$$d" ]; then echo "dir      $$d - not a symlink"; \
	  elif [ -e "$$d" ]; then echo "file     $$d - not a skill directory"; \
	  else echo "absent   $$d"; fi; \
	done

test: ## run offline regression tests (no model calls, no network)
	@cd "$(REPO)" && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v

check: test ## verify the skill is self-contained and internally consistent
	@cd "$(REPO)" || exit 1; fail=0; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/ci/check_doc_refs.py || fail=1; \
	for f in "$(SKILL)"/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -qF "$$b" "$(SKILL)/SKILL.md" || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -10 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	head -1 "$(SKILL)/SKILL.md" | grep -qx -- '---' || { echo "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' "$(SKILL)/SKILL.md" | grep -q '^name: $(NAME)$$' || { echo "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' "$(SKILL)/SKILL.md" | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d chars; listings truncate well before that" >&2; fail=1; }; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  echo "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in "$(SKILL)"/scripts/*.py; do \
	  [ -e "$$p" ] || continue; \
	  $(PYTHON) -c 'import ast,sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$$p" \
	    || { echo "MISS $$p does not parse" >&2; fail=1; }; \
	done; \
	( cd "$(SKILL)/scripts/scan_report_kit" && shasum -a 256 -c --quiet MANIFEST ) >&2 \
	  || { echo "MISS scripts/scan_report_kit differs from its MANIFEST - change scan-report-kit upstream and re-vendor" >&2; fail=1; }; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for sample in examples/findings.sample*.json; do \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$$sample" --out "$$out" --no-pdf \
	    --repo examples/sample-app >/dev/null || { echo "MISS render.py fails on $$sample" >&2; fail=1; }; \
	done; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" examples/sample-app --out "$$out/inventory.json" >/dev/null \
	  || { echo "MISS inventory.py fails on examples/sample-app" >&2; fail=1; }; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" examples/sample-app --sarif "$$out/lint.sarif" 2>/dev/null \
	  || { echo "MISS inventory.py --sarif fails on examples/sample-app" >&2; fail=1; }; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" examples/sample-app --fail-on High 2>/dev/null; \
	[ $$? -eq 1 ] || { echo "MISS inventory.py --fail-on High does not fail on the sample's High lint hits" >&2; fail=1; }; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/compare.py" examples/findings.sample.ja.json examples/findings.sample.json >/dev/null \
	  || { echo "MISS compare.py fails on the samples" >&2; fail=1; }; \
	for fmt in summary sarif; do \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/export.py" $$fmt examples/findings.sample.json --out "$$out/export.$$fmt" >/dev/null \
	    || { echo "MISS export.py $$fmt fails on the sample" >&2; fail=1; }; \
	done; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/export.py" issues examples/findings.sample.ja.json --out "$$out/issues" >/dev/null \
	  || { echo "MISS export.py issues fails on the sample" >&2; fail=1; }; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls "$(SKILL)"/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, samples render, inventory, lint, compare and export run"; \
	exit $$fail

inventory: ## prompt inventory and lint of TARGET (OUT=inventory.json to write a file)
	@[ -n "$(TARGET)" ] || { echo "usage: make inventory TARGET=/path/to/repo [OUT=inventory.json]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" "$(TARGET)" $(if $(OUT),--out "$(OUT)",)

lint: ## the lint alone, for CI (FAIL_ON=High exits 1 on a hit; SARIF=file; BASELINE=reviewed findings.json)
	@[ -n "$(TARGET)" ] && [ -n "$(FAIL_ON)$(SARIF)" ] || { echo "usage: make lint TARGET=/path/to/repo FAIL_ON=High|Medium|Low|Info [SARIF=lint.sarif] [BASELINE=findings.json]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" "$(TARGET)" \
	  $(if $(FAIL_ON),--fail-on $(FAIL_ON),) $(if $(SARIF),--sarif "$(SARIF)",) $(if $(BASELINE),--baseline "$(BASELINE)",)

demo: ## render the sample findings into DEMO_OUT (dashboard + PDF)
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$(DEMO_INPUT)" \
	  --out "$(DEMO_OUT)" --lang $(LANG_OUT) --repo "$(REPO)/examples/sample-app" $(if $(NO_PDF),--no-pdf,)

compare: ## what changed between BASE and FINDINGS (FAIL_ON=High exits 1 on a new High)
	@[ -n "$(BASE)" ] && [ -n "$(FINDINGS)" ] || { echo "usage: make compare BASE=old/findings.json FINDINGS=new/findings.json [OUT=compare.md] [FAIL_ON=High]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/compare.py" "$(BASE)" "$(FINDINGS)" \
	  $(if $(OUT),--out "$(OUT)",) $(if $(FAIL_ON),--fail-on $(FAIL_ON),)

export: ## FORMAT=summary|sarif|issues export of FINDINGS (FAIL_ON=High exits 1 on an Open High)
	@[ -n "$(FORMAT)" ] && [ -n "$(FINDINGS)" ] || { echo "usage: make export FORMAT=summary|sarif|issues FINDINGS=out/findings.json [OUT=path] [FAIL_ON=High]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/export.py" $(FORMAT) "$(FINDINGS)" \
	  $(if $(OUT),--out "$(OUT)",) $(if $(FAIL_ON),--fail-on $(FAIL_ON),)
