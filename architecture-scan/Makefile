# architecture-scan — install helpers
#
#   make link      symlink skills/architecture-scan into every installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per host
#   make check     verify the skill is self-contained and internally consistent
#   make demo      render examples/findings.sample.json into $(DEMO_OUT)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=en              # English

# Quote complete paths before shell expansion; only host names are Make lists.
shell_quote = '$(subst ','"'"',$(1))'

# The current makefile is last, but its filename may contain spaces. Discard
# earlier entries only until the remaining literal suffix names an existing file.
INSTALL_MAKEFILE := $(shell candidate=$(call shell_quote,$(MAKEFILE_LIST)); \
  while [ ! -f "$$candidate" ]; do \
    case "$$candidate" in (*' '*) candidate=$${candidate#* };; (*) break;; esac; \
  done; printf '%s\n' "$$candidate")
NAME    := architecture-scan
REPO    := $(shell CDPATH= cd -- "$$(dirname -- $(call shell_quote,$(INSTALL_MAKEFILE)))" && pwd)
SKILL   := $(REPO)/skills/$(NAME)
QSKILL  := $(call shell_quote,$(SKILL))
PYTHON  ?= python3

AGENT   ?= claude codex agy
PROJECT ?=

# Empty or unset overrides use the default configuration directory.
CLAUDE_DIR := $(or $(CLAUDE_CONFIG_DIR),$(HOME)/.claude)
CODEX_HOME ?= $(HOME)/.codex
AGY_HOME   ?= $(HOME)/.gemini/antigravity-cli

# Each host contributes two literal shell arguments: its guard and skills dir.
tgt_claude := $(call shell_quote,$(CLAUDE_DIR)) $(call shell_quote,$(CLAUDE_DIR)/skills)
tgt_codex  := $(call shell_quote,$(CODEX_HOME)) $(call shell_quote,$(CODEX_HOME)/skills)
tgt_agy    := $(call shell_quote,$(AGY_HOME)) $(call shell_quote,$(AGY_HOME)/skills)

ifneq ($(SKILLS_DIR),)
QTARGETS := $(call shell_quote,$(SKILLS_DIR)) $(call shell_quote,$(SKILLS_DIR))
SCOPE   := $(call shell_quote,SKILLS_DIR=$(SKILLS_DIR))
else ifneq ($(PROJECT),)
QTARGETS := $(call shell_quote,$(PROJECT)) $(call shell_quote,$(PROJECT)/.claude/skills)
SCOPE   := $(call shell_quote,PROJECT=$(PROJECT))
else
UNKNOWN := $(filter-out claude codex agy,$(AGENT))
ifneq ($(UNKNOWN),)
$(error unknown AGENT '$(UNKNOWN)' - use claude, codex or agy, or set SKILLS_DIR)
endif
QTARGETS := $(foreach a,$(sort $(AGENT)),$(tgt_$(a)))
SCOPE   := $(call shell_quote,AGENT=$(AGENT))
endif

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md

DEMO_OUT ?= $(or $(TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample.json

.PHONY: help link unlink status check demo test

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(call shell_quote,$(INSTALL_MAKEFILE)) \
	  | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'
	@echo
	@echo $(call shell_quote,  skill:  $(SKILL))
	@echo "  vars:   AGENT PROJECT SKILLS_DIR DEMO_OUT LANG_OUT"

# os.symlink refuses a destination created concurrently, including directories.
link: ## symlink the skill into every installed host's skills dir
	@n=0; set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  guard="$$1"; dir="$$2"; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - $$guard does not exist"; continue; fi; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink -- "$$d")" = $(QSKILL) ]; then echo "ok       $$d already linked"; n=$$((n+1)); continue; fi; \
	    echo "refusing $$d is a symlink to $$(readlink -- "$$d") - resolve it, then re-run" >&2; exit 1; \
	  elif [ -e "$$d" ]; then \
	    echo "refusing $$d exists and is not a symlink - move it aside first" >&2; exit 1; \
	  fi; \
	  mkdir -p -- "$$dir" && $(PYTHON) -c 'import os,sys; os.symlink(sys.argv[1], sys.argv[2])' $(QSKILL) "$$d" || exit 1; \
	  echo "linked   $$d -> "$(QSKILL); n=$$((n+1)); \
	done; \
	if [ $$n -eq 0 ]; then echo "nothing linked - no skills directory found for "$(SCOPE) >&2; exit 1; fi; \
	echo "invoke it with:  $(NAME)   (or /$(NAME) in a slash-command harness)"

unlink: ## remove the symlinks this Makefile created
	@set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  dir="$$2"; shift 2; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink -- "$$d")" = $(QSKILL) ]; then rm -f -- "$$d" || exit 1; echo "unlinked $$d"; \
	    else echo "left     $$d - points at $$(readlink -- "$$d"), not this repo"; fi; \
	  elif [ -e "$$d" ]; then echo "left     $$d - not a symlink"; \
	  else echo "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  guard="$$1"; dir="$$2"; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - host not installed"; \
	  elif [ -L "$$d" ]; then echo "symlink  $$d -> $$(readlink -- "$$d")"; \
	  elif [ -d "$$d" ]; then echo "dir      $$d - not a symlink"; \
	  elif [ -e "$$d" ]; then echo "file     $$d - not a skill directory"; \
	  else echo "absent   $$d"; fi; \
	done

test: ## run offline regression tests
	@cd $(call shell_quote,$(REPO)) && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v

check: test ## verify the skill is self-contained and internally consistent
	@cd $(call shell_quote,$(REPO)) || exit 1; fail=0; \
	misses=$$( \
	for f in $(DOCS); do \
	  grep -ohE '`(reference|scripts|templates)/[A-Za-z][A-Za-z0-9._-]*`' "$$f" | tr -d '`' | sort -u | while read -r ref; do \
	    [ -f $(QSKILL)/"$$ref" ] || echo "MISS $$f cites $$ref, which does not exist"; \
	  done; \
	done); \
	if [ -n "$$misses" ]; then echo "$$misses" >&2; fail=1; fi; \
	for template in issue.ja.md issue.en.md report.ja.md report.en.md; do \
	  [ -f $(QSKILL)/templates/"$$template" ] || { echo "MISS required templates/$$template is missing or not a regular file" >&2; fail=1; }; \
	done; \
	for f in $(QSKILL)/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -q "$$b" $(QSKILL)/SKILL.md || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -10 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	head -1 $(QSKILL)/SKILL.md | grep -qx -- '---' || { echo "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' $(QSKILL)/SKILL.md | grep -q '^name: $(NAME)$$' || { echo "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' $(QSKILL)/SKILL.md | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d chars; listings truncate well before that" >&2; fail=1; }; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  echo "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in $(QSKILL)/scripts/*.py; do \
	  [ -e "$$p" ] || continue; \
	  $(PYTHON) -W error -c 'import ast,sys; ast.parse(open(sys.argv[1], encoding="utf-8").read(), sys.argv[1])' "$$p" \
	    || { echo "MISS $$p does not parse cleanly (syntax or warning)" >&2; fail=1; }; \
	done; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for sample in examples/findings.sample*.json; do \
	  for lang in ja en; do \
	    PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/render.py "$$sample" --out "$$out" --lang $$lang >/dev/null \
	      || { echo "MISS render.py fails on $$sample ($$lang)" >&2; fail=1; }; \
	  done; \
	  cp "$$sample" "$$out/findings.json"; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/render.py "$$out/findings.json" --out "$$out" >/dev/null \
	    || { echo "MISS render.py fails on $$sample (meta.lang)" >&2; fail=1; }; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/findings.py check "$$out" >/dev/null \
	    || { echo "MISS $$sample does not pass the run contract" >&2; fail=1; }; \
	  rm -f "$$out"/*; \
	done; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls $(QSKILL)/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, samples render and pass the contract"; \
	exit $$fail

demo: ## render the sample findings into DEMO_OUT (dashboard + report.md)
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/render.py $(call shell_quote,$(DEMO_INPUT)) \
	  --out $(call shell_quote,$(DEMO_OUT)) --lang $(LANG_OUT)
