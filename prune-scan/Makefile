# prune-scan — install, test and demo helpers
#
#   make link      symlink skills/prune-scan into every installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per host
#   make test      run the offline regression tests
#   make check     verify the skill is self-contained and internally consistent
#   make inventory removal-candidate inventory of TARGET (UNITS=units.json OUT=inventory.json)
#   make compare   follow-up: compare LATER's review with EARLIER's (TARGET=repo checks removed files)
#   make usage     requests per route and public asset in LOGS (INVENTORY=inventory.json [FINDINGS=findings.json])
#   make plan      removal plan from a settled FINDINGS record ([OUT=removal-plan.md] [LANG_OUT=ja|en])
#   make demo      render examples/findings.sample.ja.json (LANG_OUT=en: findings.sample.json) into $(DEMO_OUT)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=en NO_PDF=1     # English, HTML only

NAME    := prune-scan
# Make's path functions split on spaces. Find the existing filename at the
# end of the list, retaining spaces even when other makefiles were read first.
shell_quote = '$(subst ','"'"',$(1))'
THIS_MAKEFILE := $(shell files=$(call shell_quote,$(MAKEFILE_LIST)); \
  while [ ! -f "$$files" ]; do \
    rest=$$(printf '%s\n' "$$files" | cut -d ' ' -f 2-); \
    [ "$$rest" != "$$files" ] || exit 1; files=$$rest; \
  done; printf '%s\n' "$$files")
ifeq ($(THIS_MAKEFILE),)
$(error cannot locate this Makefile in MAKEFILE_LIST)
endif
REPO    := $(shell CDPATH= cd -- "$$(dirname -- $(call shell_quote,$(THIS_MAKEFILE)))" && pwd -P)
ifeq ($(REPO),)
$(error cannot resolve the directory containing $(THIS_MAKEFILE))
endif
SKILL   := $(REPO)/skills/$(NAME)
PYTHON  ?= python3

AGENT   ?= claude codex agy
PROJECT ?=

CODEX_HOME ?= $(HOME)/.codex
AGY_HOME   ?= $(HOME)/.gemini/antigravity-cli

# Each target is a pair of shell arguments; no delimiter can collide with a path.
tgt_claude := $(call shell_quote,$(HOME)/.claude) $(call shell_quote,$(HOME)/.claude/skills)
tgt_codex  := $(call shell_quote,$(CODEX_HOME)) $(call shell_quote,$(CODEX_HOME)/skills)
tgt_agy    := $(call shell_quote,$(AGY_HOME)) $(call shell_quote,$(AGY_HOME)/skills)

ifneq ($(SKILLS_DIR),)
QTARGETS := $(call shell_quote,$(SKILLS_DIR)) $(call shell_quote,$(SKILLS_DIR))
WHERE    := SKILLS_DIR=$(SKILLS_DIR)
else ifneq ($(PROJECT),)
QTARGETS := $(call shell_quote,$(PROJECT)) $(call shell_quote,$(PROJECT)/.claude/skills)
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

.PHONY: help link unlink status check demo inventory compare usage plan test

help: ## list targets
	@echo "$(NAME) - skill install, tests and demo"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(call shell_quote,$(THIS_MAKEFILE)) \
	  | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
	@echo
	@printf '  skill:  %s\n' $(call shell_quote,$(SKILL))
	@echo "  vars:   AGENT PROJECT SKILLS_DIR CODEX_HOME AGY_HOME TARGET UNITS OUT EARLIER LATER"
	@echo "          INVENTORY LOGS FINDINGS MOUNT"
	@echo "          DEMO_OUT DEMO_INPUT LANG_OUT NO_PDF PYTHON"

link: ## symlink the skill into every installed host's skills dir
	@skill=$(call shell_quote,$(SKILL)); n=0; \
	set -- $(QTARGETS); while [ "$$#" -gt 0 ]; do \
	  guard=$$1; dir=$$2; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - $$guard does not exist"; continue; fi; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink "$$d")" = "$$skill" ]; then echo "ok       $$d already linked"; n=$$((n+1)); continue; fi; \
	    echo "refusing $$d is a symlink to $$(readlink "$$d") - resolve it, then re-run" >&2; exit 1; \
	  elif [ -e "$$d" ]; then \
	    echo "refusing $$d exists and is not a symlink - move it aside first" >&2; exit 1; \
	  fi; \
	  mkdir -p "$$dir" && ln -s "$$skill" "$$d" || exit 1; \
	  echo "linked   $$d -> $$skill"; n=$$((n+1)); \
	done; \
	if [ $$n -eq 0 ]; then printf 'nothing linked - no skills directory found for: %s\n' $(call shell_quote,$(WHERE)) >&2; exit 1; fi; \
	echo "invoke it with:  prune-scan   (or /prune-scan in a slash-command harness)"

unlink: ## remove the symlinks this Makefile created
	@skill=$(call shell_quote,$(SKILL)); set -- $(QTARGETS); while [ "$$#" -gt 0 ]; do \
	  dir=$$2; shift 2; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink "$$d")" = "$$skill" ]; then rm -f "$$d"; echo "unlinked $$d"; \
	    else echo "left     $$d - points at $$(readlink "$$d"), not this repo"; fi; \
	  elif [ -e "$$d" ]; then echo "left     $$d - not a symlink"; \
	  else echo "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@set -- $(QTARGETS); while [ "$$#" -gt 0 ]; do \
	  guard=$$1; dir=$$2; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - host not installed"; \
	  elif [ -L "$$d" ]; then echo "symlink  $$d -> $$(readlink "$$d")"; \
	  elif [ -d "$$d" ]; then echo "dir      $$d - not a symlink"; \
	  elif [ -e "$$d" ]; then echo "file     $$d - not a skill directory"; \
	  else echo "absent   $$d"; fi; \
	done

test: ## run offline regression tests
	@cd $(call shell_quote,$(REPO)) && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v

check: test ## verify the skill is self-contained and internally consistent
	@cd $(call shell_quote,$(REPO)) || exit 1; skill=$(call shell_quote,$(SKILL)); fail=0; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) scripts/ci/check_doc_refs.py || fail=1; \
	for f in "$$skill"/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -qF "$$b" "$$skill/SKILL.md" || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -5 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	for ref in $$(grep -oE 'reference/[a-z-]+\.md' "$$skill/SKILL.md" | sort -u); do \
	  [ -e "$$skill/$$ref" ] || { echo "MISS SKILL.md cites $$ref, which does not exist" >&2; fail=1; }; \
	done; \
	head -1 "$$skill/SKILL.md" | grep -qx -- '---' || { echo "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' "$$skill/SKILL.md" | grep -q '^name: $(NAME)$$' || { echo "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' "$$skill/SKILL.md" | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d chars; listings truncate well before that" >&2; fail=1; }; \
	[ "$$(tail -n +2 CLAUDE.md)" = "$$(tail -n +2 AGENTS.md)" ] || { echo "MISS AGENTS.md differs from CLAUDE.md below the heading" >&2; fail=1; }; \
	head -1 AGENTS.md | grep -qx '# AGENTS.md' || { echo "MISS AGENTS.md does not open with '# AGENTS.md'" >&2; fail=1; }; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  echo "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in "$$skill"/scripts/*.py; do \
	  $(PYTHON) -c 'import ast,sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$$p" \
	    || { echo "MISS $$p does not parse" >&2; fail=1; }; \
	done; \
	( cd "$$skill/scripts/scan_report_kit" && shasum -a 256 -c --quiet MANIFEST ) >&2 \
	  || { echo "MISS scripts/scan_report_kit differs from its MANIFEST - change scan-report-kit upstream and re-vendor" >&2; fail=1; }; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for lang in en ja; do \
	  sample=examples/findings.sample$$([ $$lang = ja ] && echo .ja).json; o="$$out/$$lang"; mkdir -p "$$o"; \
	  cp examples/units.sample.json "$$o/units.json" && cp "$$sample" "$$o/findings.json" || fail=1; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/inventory.py" examples/larder --units "$$o/units.json" --out "$$o/inventory.json" >/dev/null \
	    || { echo "MISS inventory.py fails on examples/larder" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/render.py" "$$o/findings.json" --out "$$o" --lang $$lang --repo examples/larder --no-pdf >/dev/null \
	    || { echo "MISS render.py fails on $$sample" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/findings.py" check "$$o/findings.json" >/dev/null \
	    || { echo "MISS findings.py check fails on $$sample" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/findings.py" renumber "$$o/findings.json" | grep -q 'already in order' \
	    || { echo "MISS $$sample is not numbered in severity order" >&2; fail=1; }; \
	done; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls "$$skill"/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, doc refs resolve, samples inventory and render"; \
	exit $$fail

inventory: ## removal-candidate inventory of TARGET (UNITS=units.json, OUT=inventory.json)
	@[ -n $(call shell_quote,$(TARGET)) ] || { echo "usage: make inventory TARGET=/path/to/repo [UNITS=units.json] [OUT=inventory.json]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(call shell_quote,$(SKILL)/scripts/inventory.py) $(call shell_quote,$(TARGET)) \
	  $(if $(UNITS),--units $(call shell_quote,$(UNITS)),) --out $(call shell_quote,$(or $(OUT),inventory.json))

compare: ## follow-up review: compare LATER's outputs with EARLIER's (TARGET=repo optional)
	@[ -n $(call shell_quote,$(EARLIER)) ] && [ -n $(call shell_quote,$(LATER)) ] || { echo "usage: make compare EARLIER=/path/to/old-out LATER=/path/to/new-out [TARGET=/path/to/repo]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(call shell_quote,$(SKILL)/scripts/compare.py) $(call shell_quote,$(EARLIER)) $(call shell_quote,$(LATER)) \
	  $(if $(TARGET),--repo $(call shell_quote,$(TARGET)),)

usage: ## requests per route and public asset in LOGS (INVENTORY=inventory.json, FINDINGS optional)
	@[ -n $(call shell_quote,$(INVENTORY)) ] && [ -n $(call shell_quote,$(LOGS)) ] || { echo "usage: make usage INVENTORY=/path/to/inventory.json LOGS=\"access.log ...\" [FINDINGS=findings.json] [MOUNT=/api] [OUT=usage.json]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(call shell_quote,$(SKILL)/scripts/usage.py) $(call shell_quote,$(INVENTORY)) $(LOGS) \
	  $(if $(FINDINGS),--findings $(call shell_quote,$(FINDINGS)),) $(if $(MOUNT),--mount $(call shell_quote,$(MOUNT)),) \
	  $(if $(OUT),--json $(call shell_quote,$(OUT)),) $(if $(filter ja,$(LANG_OUT)),--lang ja,)

plan: ## removal plan from a settled FINDINGS record (OUT=removal-plan.md optional, else stdout)
	@[ -n $(call shell_quote,$(FINDINGS)) ] || { echo "usage: make plan FINDINGS=/path/to/findings.json [OUT=removal-plan.md] [LANG_OUT=ja|en]" >&2; exit 2; }
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(call shell_quote,$(SKILL)/scripts/plan.py) $(call shell_quote,$(FINDINGS)) \
	  $(if $(OUT),--out $(call shell_quote,$(OUT)),) $(if $(filter ja,$(LANG_OUT)),--lang ja,)

demo: ## render the sample (dashboard + report + PDF) into DEMO_OUT
	@out=$(call shell_quote,$(DEMO_OUT)); skill=$(call shell_quote,$(SKILL)); repo=$(call shell_quote,$(REPO)); \
	  mkdir -p "$$out" && cp "$$repo/examples/units.sample.json" "$$out/units.json" \
	  && cp $(call shell_quote,$(DEMO_INPUT)) "$$out/findings.json" \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/inventory.py" "$$repo/examples/larder" \
	       --units "$$out/units.json" --out "$$out/inventory.json" \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/render.py" "$$out/findings.json" \
	       --out "$$out" --lang $(call shell_quote,$(LANG_OUT)) --repo "$$repo/examples/larder" $(if $(NO_PDF),--no-pdf,) \
	  $(if $(NO_PDF),,&& PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/contract_check.py" "$$out")
