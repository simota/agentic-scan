# privacy-scan — install helpers
#
#   make link      symlink skills/privacy-scan into every installed host's skills dir
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

# Paths are literal shell arguments, never Make whitespace-separated lists.
shell_quote = '$(subst ','"'"',$(1))'

# Environment paths are already literal; only Make assignments need expansion.
# The filter also matches the "environment override" origin used by make -e.
path_value = $(if $(filter environment,$(origin $(1))),$(value $(1)),$($(1)))

# A link is ours when it names this skill, or reaches the same physical directory
# through another spelling of the checkout (an alias path or a symlinked parent).
# Recipes define it with: $(ours_fn)
ours_fn = ours() { [ "$$(readlink "$$1")" = "$$skill" ] || \
  { [ -d "$$1" ] && [ "$$(CDPATH= cd -P -- "$$1" && pwd -P)" = "$$(CDPATH= cd -P -- "$$skill" && pwd -P)" ]; }; }

# GNU Make 3.81 reads a literal '#' here as a comment, even inside $(shell).
hash := \#

# This file is the last entry here. Try literal suffixes to skip any preloaded
# or including makefiles without splitting spaces inside this file's path.
# GNU Make 3.81 keeps MAKEFILE_LIST as a recursive variable, so a '$' in a
# makefile path would be expanded on reference; $(value) reads it literally.
MAKEFILE_PATH := $(shell path=$(call shell_quote,$(value MAKEFILE_LIST)); \
  while [ ! -f "$$path" ]; do \
    case "$$path" in (*' '*) path=$${path$(hash)* };; (*) exit 1;; esac; \
  done; printf '%s\n' "$$path")
ifeq ($(MAKEFILE_PATH),)
$(error cannot locate this Makefile from MAKEFILE_LIST)
endif

NAME    := privacy-scan
# Match abspath's CURDIR base while retaining an explicitly supplied path alias.
REPO    := $(shell CDPATH= cd -- $(call shell_quote,$(CURDIR)) && \
  CDPATH= cd -L -- "$$(dirname -- $(call shell_quote,$(MAKEFILE_PATH)))" && pwd -L)
ifeq ($(REPO),)
$(error cannot resolve the repository directory for $(MAKEFILE_PATH))
endif
SKILL   := $(REPO)/skills/$(NAME)
QREPO   := $(call shell_quote,$(REPO))
QSKILL  := $(call shell_quote,$(SKILL))
PYTHON  ?= python3

AGENT   ?= claude codex agy
PROJECT ?=

CODEX_HOME ?= $(call path_value,HOME)/.codex
AGY_HOME   ?= $(call path_value,HOME)/.gemini/antigravity-cli

root_claude := $(call path_value,HOME)/.claude
root_codex  := $(call path_value,CODEX_HOME)
root_agy    := $(call path_value,AGY_HOME)
project_path := $(call path_value,PROJECT)
skills_dir_path := $(call path_value,SKILLS_DIR)

UNKNOWN := $(filter-out claude codex agy,$(AGENT))
ifneq ($(UNKNOWN),)
$(error unknown AGENT '$(UNKNOWN)' - use claude, codex or agy, or set SKILLS_DIR)
endif

# Pass each guard and destination as separate, quoted shell arguments. No
# delimiter is reserved inside a path; only host IDs enter Make's list functions.
# Recipes prefix leading-hyphen paths with ./ before passing them to utilities.
ifneq ($(skills_dir_path),)
QTARGETS := $(call shell_quote,$(skills_dir_path)) $(call shell_quote,$(skills_dir_path))
else ifneq ($(project_path),)
QTARGETS := $(call shell_quote,$(project_path)) $(call shell_quote,$(project_path)/.claude/skills)
else
QTARGETS := $(foreach a,$(sort $(AGENT)),$(call shell_quote,$(root_$(a))) $(call shell_quote,$(root_$(a))/skills))
endif

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md

DEMO_OUT ?= $(or $(call path_value,TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample.json

.PHONY: help link unlink status check demo test

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(call shell_quote,$(MAKEFILE_PATH)) \
	  | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'
	@echo
	@printf '  skill:  %s\n' $(QSKILL)
	@echo "  vars:   AGENT PROJECT SKILLS_DIR DEMO_OUT LANG_OUT"

link: ## symlink the skill into every installed host's skills dir
	@skill=$(QSKILL); n=0; $(ours_fn); \
	if [ ! -f "$$skill/SKILL.md" ]; then \
	  printf '%s\n' "refusing $$skill is not a skill directory (missing SKILL.md)" >&2; exit 1; \
	fi; \
	set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  guard=$$1; dir=$$2; shift 2; \
	  case "$$dir" in (-*) dir="./$$dir";; esac; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then printf '%s\n' "skip     $$d - $$guard does not exist"; continue; fi; \
	  if [ -L "$$d" ]; then \
	    if ours "$$d"; then printf '%s\n' "ok       $$d already linked"; n=$$((n+1)); continue; fi; \
	    printf '%s\n' "refusing $$d is a symlink to $$(readlink "$$d") - resolve it, then re-run" >&2; exit 1; \
	  elif [ -e "$$d" ]; then \
	    printf '%s\n' "refusing $$d exists and is not a symlink - move it aside first" >&2; exit 1; \
	  fi; \
	  mkdir -p "$$dir" && ln -s "$$skill" "$$d" || exit 1; \
	  printf '%s\n' "linked   $$d -> $$skill"; n=$$((n+1)); \
	done; \
	if [ $$n -eq 0 ]; then printf '%s\n' "nothing linked - no skills directory found for: $(AGENT)" >&2; exit 1; fi; \
	printf '%s\n' "invoke it with:  $(NAME)   (or /$(NAME) in a slash-command harness)"

unlink: ## remove the symlinks this Makefile created
	@skill=$(QSKILL); $(ours_fn); set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  dir=$$2; shift 2; \
	  case "$$dir" in (-*) dir="./$$dir";; esac; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ]; then \
	    if ours "$$d"; then rm -f "$$d" || exit 1; printf '%s\n' "unlinked $$d"; \
	    else printf '%s\n' "left     $$d - points at $$(readlink "$$d"), not this repo"; fi; \
	  elif [ -e "$$d" ]; then printf '%s\n' "left     $$d - not a symlink"; \
	  else printf '%s\n' "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  guard=$$1; dir=$$2; shift 2; \
	  case "$$dir" in (-*) dir="./$$dir";; esac; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then printf '%s\n' "skip     $$d - host not installed"; \
	  elif [ -L "$$d" ]; then printf '%s\n' "symlink  $$d -> $$(readlink "$$d")"; \
	  elif [ -d "$$d" ]; then printf '%s\n' "dir      $$d - not a symlink"; \
	  elif [ -e "$$d" ]; then printf '%s\n' "file     $$d - not a skill directory"; \
	  else printf '%s\n' "absent   $$d"; fi; \
	done

test: ## run offline regression tests
	@cd $(QREPO) && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests -v

check: test ## verify the skill is self-contained and internally consistent
	@cd $(QREPO) || exit 1; fail=0; \
	misses=$$( \
	for f in $(DOCS); do \
	  grep -ohE '`(reference|scripts|templates)/[A-Za-z][A-Za-z0-9._-]*`' "$$f" | tr -d '`' | sort -u | while read -r ref; do \
	    [ -f $(QSKILL)/"$$ref" ] || printf '%s\n' "MISS $$f cites $$ref, which does not exist"; \
	  done; \
	done); \
	if [ -n "$$misses" ]; then printf '%s\n' "$$misses" >&2; fail=1; fi; \
	for f in $(QSKILL)/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -q "$$b" $(QSKILL)/SKILL.md || { printf '%s\n' "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -10 "$$f" | grep -q '\*\*Read when:\*\*' || { printf '%s\n' "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	head -1 $(QSKILL)/SKILL.md | grep -qx -- '---' || { printf '%s\n' "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' $(QSKILL)/SKILL.md | grep -q '^name: $(NAME)$$' || { printf '%s\n' "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' $(QSKILL)/SKILL.md | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { printf '%s\n' "MISS description is $$d chars; listings truncate well before that" >&2; fail=1; }; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  printf '%s\n' "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in $(QSKILL)/scripts/*.py; do \
	  [ -e "$$p" ] || continue; \
	  $(PYTHON) -c 'import ast,sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$$p" \
	    || { printf '%s\n' "MISS $$p does not parse" >&2; fail=1; }; \
	done; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for sample in examples/findings.sample*.json; do \
	  for lang in ja en; do \
	    PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/render.py "$$sample" --out "$$out" --lang $$lang >/dev/null \
	      || { printf '%s\n' "MISS render.py fails on $$sample ($$lang)" >&2; fail=1; }; \
	  done; \
	  cp "$$sample" "$$out/findings.json"; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/findings.py check "$$out" >/dev/null \
	    || { printf '%s\n' "MISS $$sample does not pass the run contract" >&2; fail=1; }; \
	  rm -f "$$out"/*; \
	done; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && printf '%s\n' "check ok - $$(ls $(QSKILL)/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, samples render and pass the contract"; \
	exit $$fail

demo: ## render the sample findings into DEMO_OUT (dashboard + report.md)
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/render.py \
	  --out=$(call shell_quote,$(call path_value,DEMO_OUT)) --lang=$(call shell_quote,$(LANG_OUT)) \
	  -- $(call shell_quote,$(call path_value,DEMO_INPUT))
