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

NAME    := privacy-scan
PYTHON  ?= python3
# Keep a single filename intact, including spaces. Otherwise retain the last
# filename for conventional MAKEFILES, multiple -f arguments and includes.
shell_quote = '$(subst ','"'"',$(1))'
MAKEFILE_PATH := $(shell files=$(call shell_quote,$(MAKEFILE_LIST)); \
  if [ -f "$$files" ]; then printf '%s\n' "$$files"; else printf '%s\n' "$${files##* }"; fi)
# Like Make's abspath, use the actual cwd but preserve explicitly named symlinks.
REPO    := $(shell $(PYTHON) -c 'import os, sys; print(os.path.dirname(os.path.abspath(sys.argv[1])))' $(call shell_quote,$(MAKEFILE_PATH)))
SKILL   := $(REPO)/skills/$(NAME)

AGENT   ?= claude codex agy
PROJECT ?=

CODEX_HOME ?= $(HOME)/.codex
AGY_HOME   ?= $(HOME)/.gemini/antigravity-cli

root_claude := $(HOME)/.claude
root_codex  := $(CODEX_HOME)
root_agy    := $(AGY_HOME)

UNKNOWN := $(filter-out claude codex agy,$(AGENT))
ifneq ($(UNKNOWN),)
$(error unknown AGENT '$(UNKNOWN)' - use claude, codex or agy, or set SKILLS_DIR)
endif

# Pass each guard and destination as separate, quoted shell arguments. No
# delimiter is reserved inside a path; only host IDs enter Make's list functions.
ifneq ($(SKILLS_DIR),)
QTARGETS := $(call shell_quote,$(SKILLS_DIR)) $(call shell_quote,$(SKILLS_DIR))
else ifneq ($(PROJECT),)
QTARGETS := $(call shell_quote,$(PROJECT)) $(call shell_quote,$(PROJECT)/.claude/skills)
else
QTARGETS := $(foreach a,$(sort $(AGENT)),$(call shell_quote,$(root_$(a))) $(call shell_quote,$(root_$(a))/skills))
endif

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md

DEMO_OUT ?= $(or $(TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample.json

.PHONY: help link unlink status check demo test

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(call shell_quote,$(MAKEFILE_PATH)) \
	  | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'
	@echo
	@printf '%s\n' $(call shell_quote,  skill:  $(SKILL))
	@echo "  vars:   AGENT PROJECT SKILLS_DIR DEMO_OUT LANG_OUT"

link: ## symlink the skill into every installed host's skills dir
	@skill=$(call shell_quote,$(SKILL)); \
	[ -f "$$skill/SKILL.md" ] || { echo "refusing $$skill/SKILL.md does not exist" >&2; exit 1; }; \
	n=0; set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
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
	if [ $$n -eq 0 ]; then echo "nothing linked - no skills directory found for: $(AGENT)" >&2; exit 1; fi; \
	echo "invoke it with:  $(NAME)   (or /$(NAME) in a slash-command harness)"

unlink: ## remove the symlinks this Makefile created
	@skill=$(call shell_quote,$(SKILL)); set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  dir=$$2; shift 2; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink "$$d")" = "$$skill" ]; then rm -f "$$d" || exit 1; echo "unlinked $$d"; \
	    else echo "left     $$d - points at $$(readlink "$$d"), not this repo"; fi; \
	  elif [ -e "$$d" ]; then echo "left     $$d - not a symlink"; \
	  else echo "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
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
	misses=$$( \
	for f in $(DOCS); do \
	  grep -ohE '`(reference|scripts|templates)/[A-Za-z][A-Za-z0-9._-]*`' "$$f" | tr -d '`' | sort -u | while read -r ref; do \
	    [ -f "$$skill/$$ref" ] || echo "MISS $$f cites $$ref, which does not exist"; \
	  done; \
	done); \
	if [ -n "$$misses" ]; then echo "$$misses" >&2; fail=1; fi; \
	for f in "$$skill"/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -q "$$b" "$$skill/SKILL.md" || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -10 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	head -1 "$$skill/SKILL.md" | grep -qx -- '---' || { echo "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' "$$skill/SKILL.md" | grep -q '^name: $(NAME)$$' || { echo "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' "$$skill/SKILL.md" | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d chars; listings truncate well before that" >&2; fail=1; }; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  echo "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in "$$skill"/scripts/*.py; do \
	  [ -e "$$p" ] || continue; \
	  $(PYTHON) -c 'import ast,sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$$p" \
	    || { echo "MISS $$p does not parse" >&2; fail=1; }; \
	done; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for sample in examples/findings.sample*.json; do \
	  for lang in ja en; do \
	    PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/render.py" "$$sample" --out "$$out" --lang $$lang >/dev/null \
	      || { echo "MISS render.py fails on $$sample ($$lang)" >&2; fail=1; }; \
	  done; \
	  cp "$$sample" "$$out/findings.json"; \
	  PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$skill/scripts/findings.py" check "$$out" >/dev/null \
	    || { echo "MISS $$sample does not pass the run contract" >&2; fail=1; }; \
	  rm -f "$$out"/*; \
	done; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls "$$skill"/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, samples render and pass the contract"; \
	exit $$fail

demo: ## render the sample findings into DEMO_OUT (dashboard + report.md)
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(call shell_quote,$(SKILL)/scripts/render.py) $(call shell_quote,$(DEMO_INPUT)) \
	  --out $(call shell_quote,$(DEMO_OUT)) --lang $(call shell_quote,$(LANG_OUT))
