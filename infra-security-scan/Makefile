# infra-scan — install helpers
#
#   make link      symlink skills/infra-scan into every installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per host
#   make check     verify the skill is self-contained and internally consistent
#   make scan      baseline IaC scan of TARGET (+ SNAPSHOTS dirs, space-separated) into OUT
#   make demo      render the LANG_OUT sample in examples/ into $(DEMO_OUT)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=en NO_PDF=1     # English, HTML only

NAME    := infra-scan
REPO    := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
# make splits words on spaces; refuse instead of acting on a truncated path.
ifneq ($(word 2,$(REPO)),)
$(error the repository path contains a space; symlink it to a path without spaces and run make -f /that/path/Makefile)
endif
SKILL   := $(REPO)/skills/$(NAME)
PYTHON  ?= python3

AGENT   ?= claude codex agy
PROJECT ?=

CODEX_HOME ?= $(HOME)/.codex
AGY_HOME   ?= $(HOME)/.gemini/antigravity-cli

tgt_claude := $(HOME)/.claude|$(HOME)/.claude/skills
tgt_codex  := $(CODEX_HOME)|$(CODEX_HOME)/skills
tgt_agy    := $(AGY_HOME)|$(AGY_HOME)/skills

UNKNOWN := $(filter-out claude codex agy,$(AGENT))
ifeq ($(SKILLS_DIR)$(PROJECT),)
ifneq ($(UNKNOWN),)
$(error unknown AGENT '$(UNKNOWN)' - use claude, codex or agy, or set SKILLS_DIR)
endif
endif

ifneq ($(SKILLS_DIR),)
TARGETS := $(SKILLS_DIR)|$(SKILLS_DIR)
else ifneq ($(PROJECT),)
TARGETS := $(PROJECT)|$(PROJECT)/.claude/skills
else
TARGETS := $(sort $(foreach a,$(AGENT),$(tgt_$(a))))
endif
QTARGETS := $(foreach t,$(TARGETS),'$(t)')
SPACED   := $(strip $(foreach v,HOME PROJECT SKILLS_DIR CODEX_HOME AGY_HOME,$(if $(word 2,$($(v))),$(v))))
NOSPACE  = $(if $(SPACED),echo "paths with spaces are not supported: $(SPACED)" >&2; exit 2;)

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md

DEMO_OUT ?= $(or $(TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample$(if $(filter ja,$(LANG_OUT)),.ja,).json
NO_PDF   ?=

.PHONY: help link unlink status check demo scan test

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(lastword $(MAKEFILE_LIST)) \
	  | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'
	@echo
	@echo "  skill:  $(SKILL)"
	@echo "  vars:   AGENT PROJECT SKILLS_DIR DEMO_OUT LANG_OUT NO_PDF TARGET OUT SNAPSHOTS"

link: ## symlink the skill into every installed host's skills dir
	@$(NOSPACE) n=0; \
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
	if [ $$n -eq 0 ]; then echo "nothing linked - $(if $(SKILLS_DIR)$(PROJECT),$(firstword $(subst |, ,$(TARGETS))) does not exist,no skills directory found for: $(AGENT))" >&2; exit 1; fi; \
	echo "invoke it with:  infra-scan   (or /infra-scan in a slash-command harness)"

unlink: ## remove the symlinks this Makefile created
	@$(NOSPACE) for t in $(QTARGETS); do \
	  dir=$${t##*|}; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink "$$d")" = "$(SKILL)" ]; then rm -f "$$d"; echo "unlinked $$d"; \
	    else echo "left     $$d - points at $$(readlink "$$d"), not this repo"; fi; \
	  elif [ -e "$$d" ]; then echo "left     $$d - not a symlink"; \
	  else echo "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@$(NOSPACE) for t in $(QTARGETS); do \
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
	misses=$$( \
	for f in $(DOCS); do \
	  grep -ohE '`[^`]+`' "$$f" | tr -c 'A-Za-z0-9._<>/-' '\n' \
	    | grep -E '^(reference|scripts|templates)/[A-Za-z]' | sort -u | while read -r ref; do \
	    for r in $$(case "$$ref" in *'<lang>'*) echo "$$ref" | sed 's/<lang>/ja/'; echo "$$ref" | sed 's/<lang>/en/';; *) echo "$$ref";; esac); do \
	      [ -f "$(SKILL)/$$r" ] || echo "MISS $$f cites $$r, which does not exist"; \
	    done; \
	  done; \
	done); \
	if [ -n "$$misses" ]; then echo "$$misses" >&2; fail=1; fi; \
	for f in "$(SKILL)"/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -qF "reference/$$b" "$(SKILL)/SKILL.md" || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  awk 'NF && !/^# / { exit !/^\*\*Read when:\*\*/ }' "$$f" || { echo "MISS reference/$$b does not start with a **Read when:** line" >&2; fail=1; }; \
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
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$$sample" --out "$$out" --no-pdf >/dev/null \
	    || { echo "MISS render.py fails on $$sample" >&2; fail=1; }; \
	done; \
	rm -rf "$$out"; \
	scan=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-scan.XXXXXX") || exit 1; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/iac_scan.py" tests/fixtures --out "$$scan/iac.json" >/dev/null 2>"$$scan/err" \
	  || { cat "$$scan/err" >&2; echo "MISS iac_scan.py fails on tests/fixtures" >&2; fail=1; }; \
	rm -rf "$$scan"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls "$(SKILL)"/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, samples render, iac_scan runs"; \
	exit $$fail

scan: ## baseline IaC scan of TARGET into OUT (iac.json + findings.json); never calls a cloud
	@[ -n "$(TARGET)" ] && [ -n "$(OUT)" ] || { echo "usage: make scan TARGET=/path/to/iac-repo OUT=/new/output/dir" >&2; exit 2; }
	@# iac_scan.py refuses OUT inside TARGET before creating anything.
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/iac_scan.py" "$(TARGET)" \
	  $(foreach d,$(SNAPSHOTS),--snapshots '$(d)') --out "$(OUT)/iac.json" --into "$(OUT)/findings.json"

demo: ## render the sample findings into DEMO_OUT (dashboard + PDF)
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$(SKILL)/scripts/render.py" "$(DEMO_INPUT)" \
	  --out "$(DEMO_OUT)" --lang $(LANG_OUT) $(if $(NO_PDF),--no-pdf,)
