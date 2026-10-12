# prune-scan — install helpers
#
#   make link      symlink skills/prune-scan into every installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per host
#   make check     verify the skill is self-contained and internally consistent
#   make inventory removal-candidate inventory of TARGET (UNITS=units.json OUT=inventory.json)
#   make demo      render examples/findings.sample.ja.json (LANG_OUT=en: findings.sample.json) into $(DEMO_OUT)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=en NO_PDF=1     # English, HTML only

NAME    := prune-scan
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

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md

DEMO_OUT ?= $(or $(TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample$(if $(filter ja,$(LANG_OUT)),.ja,).json
NO_PDF   ?=

.PHONY: help link unlink status check demo inventory test

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(lastword $(MAKEFILE_LIST)) \
	  | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
	@echo
	@echo "  skill:  $(SKILL)"
	@echo "  vars:   AGENT PROJECT SKILLS_DIR CODEX_HOME AGY_HOME TARGET UNITS OUT"
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
	echo "invoke it with:  prune-scan   (or /prune-scan in a slash-command harness)"

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
	  cp examples/units.sample.json "$$o/units.json" && cp "$$sample" "$$o/findings.json" || fail=1; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" examples/larder --units "$$o/units.json" --out "$$o/inventory.json" >/dev/null \
	    || { echo "MISS inventory.py fails on examples/larder" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$$o/findings.json" --out "$$o" --lang $$lang --repo examples/larder --no-pdf >/dev/null \
	    || { echo "MISS render.py fails on $$sample" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/findings.py" check "$$o/findings.json" >/dev/null \
	    || { echo "MISS findings.py check fails on $$sample" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/findings.py" renumber "$$o/findings.json" | grep -q 'already in order' \
	    || { echo "MISS $$sample is not numbered in severity order" >&2; fail=1; }; \
	done; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls "$(SKILL)"/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, doc refs resolve, samples inventory and render"; \
	exit $$fail

inventory: ## removal-candidate inventory of TARGET (UNITS=units.json, OUT=inventory.json)
	@[ -n "$(TARGET)" ] || { echo "usage: make inventory TARGET=/path/to/repo [UNITS=units.json] [OUT=inventory.json]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" "$(TARGET)" \
	  $(if $(UNITS),--units "$(UNITS)",) --out "$(or $(OUT),inventory.json)"

demo: ## render the sample (dashboard + report + PDF) into DEMO_OUT
	@mkdir -p "$(DEMO_OUT)" && cp "$(REPO)/examples/units.sample.json" "$(DEMO_OUT)/units.json" \
	  && cp "$(DEMO_INPUT)" "$(DEMO_OUT)/findings.json" \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/inventory.py" "$(REPO)/examples/larder" \
	       --units "$(DEMO_OUT)/units.json" --out "$(DEMO_OUT)/inventory.json" \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$(DEMO_OUT)/findings.json" \
	       --out "$(DEMO_OUT)" --lang $(LANG_OUT) --repo "$(REPO)/examples/larder" $(if $(NO_PDF),--no-pdf,) \
	  $(if $(NO_PDF),,&& PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/contract_check.py" "$(DEMO_OUT)")
