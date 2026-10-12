# ux-scan — install helpers
#
#   make link      symlink skills/ux-scan into every installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per host
#   make check     verify the skill is self-contained and internally consistent
#   make inventory UI/UX inventory of TARGET (FLOWS=flows.json OUT=inventory.json)
#   make demo      render examples/findings.sample.ja.json (LANG_OUT=en: findings.sample.json) into $(DEMO_OUT)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=en NO_PDF=1     # English, HTML only

NAME    := ux-scan
# Make's filename functions split on spaces, even inside an absolute path.
# Capture this standalone Makefile before any includes and resolve it in the shell.
shell_quote = '$(subst ','"'"',$(1))'
SOURCE_MAKEFILE := $(MAKEFILE_LIST)
REPO    := $(shell CDPATH= cd -- "$$(dirname -- $(call shell_quote,$(SOURCE_MAKEFILE)))" && pwd -P)
SKILL   := $(REPO)/skills/$(NAME)
PYTHON  ?= python3

AGENT   ?= claude codex agy
PROJECT ?=

CODEX_HOME ?= $(HOME)/.codex
AGY_HOME   ?= $(HOME)/.gemini/antigravity-cli

# Each target is one quoted 'guard|dir' word, so paths may contain spaces.
tgt_claude := $(call shell_quote,$(HOME)/.claude|$(HOME)/.claude/skills)
tgt_codex  := $(call shell_quote,$(CODEX_HOME)|$(CODEX_HOME)/skills)
tgt_agy    := $(call shell_quote,$(AGY_HOME)|$(AGY_HOME)/skills)

ifneq ($(SKILLS_DIR),)
QTARGETS := $(call shell_quote,$(SKILLS_DIR)|$(SKILLS_DIR))
WHERE    := SKILLS_DIR=$(SKILLS_DIR)
else ifneq ($(PROJECT),)
QTARGETS := $(call shell_quote,$(PROJECT)|$(PROJECT)/.claude/skills)
WHERE    := PROJECT=$(PROJECT)
else
UNKNOWN := $(filter-out claude codex agy,$(AGENT))
ifneq ($(UNKNOWN),)
$(error unknown AGENT '$(UNKNOWN)' - use claude, codex or agy, or set SKILLS_DIR)
endif
QTARGETS := $(foreach a,$(sort $(AGENT)),$(tgt_$(a)))
WHERE    := $(AGENT)
endif

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md

DEMO_OUT ?= $(or $(TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample$(if $(filter ja,$(LANG_OUT)),.ja,).json
NO_PDF   ?=

.PHONY: help link unlink status check demo inventory test

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(call shell_quote,$(SOURCE_MAKEFILE)) \
	  | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
	@echo
	@echo "  skill:  $(SKILL)"
	@echo "  vars:   AGENT PROJECT SKILLS_DIR CODEX_HOME AGY_HOME TARGET FLOWS OUT"
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
	echo "invoke it with:  ux-scan   (or /ux-scan in a slash-command harness)"

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

test: ## run offline regression tests
	@cd "$(REPO)" && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v

check: test ## verify the skill is self-contained and internally consistent
	@cd "$(REPO)" || exit 1; fail=0; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/ci/check_doc_refs.py || fail=1; \
	for f in "$(SKILL)"/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -qF "$$b" "$(SKILL)/SKILL.md" || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -5 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	for ref in $$(grep -oE 'reference/[a-z-]+\.md' "$(SKILL)/SKILL.md" | sort -u); do \
	  [ -e "$(SKILL)/$$ref" ] || { echo "MISS SKILL.md cites $$ref, which does not exist" >&2; fail=1; }; \
	done; \
	head -1 "$(SKILL)/SKILL.md" | grep -qx -- '---' || { echo "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' "$(SKILL)/SKILL.md" | grep -q '^name: $(NAME)$$' || { echo "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' "$(SKILL)/SKILL.md" | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d chars; listings truncate well before that" >&2; fail=1; }; \
	[ "$$(tail -n +2 CLAUDE.md)" = "$$(tail -n +2 AGENTS.md)" ] || { echo "MISS AGENTS.md differs from CLAUDE.md below the heading" >&2; fail=1; }; \
	head -1 AGENTS.md | grep -qx '# AGENTS.md' || { echo "MISS AGENTS.md does not open with '# AGENTS.md'" >&2; fail=1; }; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  echo "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in "$(SKILL)"/scripts/*.py; do \
	  $(PYTHON) -c 'import ast,sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$$p" \
	    || { echo "MISS $$p does not parse" >&2; fail=1; }; \
	done; \
	( cd "$(SKILL)/scripts/scan_report_kit" && shasum -a 256 -c --quiet MANIFEST ) >&2 \
	  || { echo "MISS scripts/scan_report_kit differs from its MANIFEST - change scan-report-kit upstream and re-vendor" >&2; fail=1; }; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for lang in en ja; do \
	  sample=examples/findings.sample$$([ $$lang = ja ] && echo .ja).json; o="$$out/$$lang"; mkdir -p "$$o"; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/ci/prepare_sample.py "$$sample" --out "$$o" --no-pdf \
	    || { echo "MISS cannot prepare $$sample" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" examples/tasklane --flows "$$o/flows.json" --out "$$o/inventory.json" >/dev/null \
	    || { echo "MISS inventory.py fails on examples/tasklane" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$$o/findings.json" --out "$$o" --lang $$lang --repo examples/tasklane --no-pdf >/dev/null \
	    || { echo "MISS render.py fails on $$sample" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/findings.py" check "$$o/findings.json" >/dev/null \
	    || { echo "MISS findings.py check fails on $$sample" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/findings.py" renumber "$$o/findings.json" | grep -q 'already in order' \
	    || { echo "MISS $$sample is not numbered in severity order" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/contract_check.py" "$$o" --no-pdf >/dev/null \
	    || { echo "MISS $$sample does not satisfy the output contract" >&2; fail=1; }; \
	done; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls "$(SKILL)"/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, doc refs resolve, sample output contracts pass"; \
	exit $$fail

inventory: ## UI/UX inventory of TARGET (FLOWS=flows.json, OUT=inventory.json)
	@[ -n "$(TARGET)" ] || { echo "usage: make inventory TARGET=/path/to/repo [FLOWS=flows.json] [OUT=inventory.json]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" "$(TARGET)" \
	  $(if $(FLOWS),--flows "$(FLOWS)",) --out "$(or $(OUT),inventory.json)"

demo: ## render the sample (dashboard + report + PDF) into DEMO_OUT
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(REPO)/scripts/ci/prepare_sample.py" "$(DEMO_INPUT)" \
	       --out "$(DEMO_OUT)" $(if $(NO_PDF),--no-pdf,) \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" "$(REPO)/examples/tasklane" \
	       --flows "$(DEMO_OUT)/flows.json" --out "$(DEMO_OUT)/inventory.json" \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$(DEMO_OUT)/findings.json" \
	       --out "$(DEMO_OUT)" --lang $(LANG_OUT) --repo "$(REPO)/examples/tasklane" $(if $(NO_PDF),--no-pdf,) \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/contract_check.py" "$(DEMO_OUT)" $(if $(NO_PDF),--no-pdf,)
