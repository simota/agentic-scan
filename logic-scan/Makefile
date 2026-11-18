# logic-scan — install helpers
#
#   make help      list the targets
#   make link      symlink skills/logic-scan into every installed host's skills dir
#   make unlink    remove every symlink to this skill from those dirs
#   make status    show what is installed, per host
#   make test      run the offline regression tests
#   make check     verify the skill is self-contained and internally consistent
#   make demo      render examples/findings.sample.json into DEMO_OUT (default: a new mktemp dir)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=en              # English
#
# link goes on past a host it refuses (an existing directory, or a symlink to
# something else) and exits non-zero at the end. A link to this skill counts as
# linked whatever path spells it. DEMO_OUT, when given, is written as is: its
# dashboard.html and report.md are replaced, and render refuses either one, or
# DEMO_OUT itself, when it is a symlink.
#
# Paths may hold spaces and quotes. A `$` in a path is expanded by make before
# the shell sees it, so such a path must be written as `$$`. PYTHON is a
# command, not a path: `PYTHON=python3.12` or `PYTHON="uv run python"`; put an
# interpreter whose path holds spaces on PATH instead.

# Quote complete paths before shell expansion; only host names are Make lists.
shell_quote = '$(subst ','"'"',$(1))'

# GNU Make before 4.3 reads a bare `#` inside a function call as a comment.
HASH := \#

# The current makefile is last, but its filename may contain spaces. Discard
# earlier entries only until the remaining literal suffix names an existing file.
INSTALL_MAKEFILE := $(shell candidate=$(call shell_quote,$(MAKEFILE_LIST)); \
  while [ ! -f "$$candidate" ]; do \
    case "$$candidate" in (*' '*) candidate=$${candidate$(HASH)* };; (*) break;; esac; \
  done; printf '%s\n' "$$candidate")
NAME    := logic-scan
REPO    := $(shell CDPATH= cd -- "$$(dirname -- $(call shell_quote,$(INSTALL_MAKEFILE)))" && pwd)
SKILL   := $(REPO)/skills/$(NAME)
QSKILL  := $(call shell_quote,$(SKILL))
PYTHON  ?= python3

AGENT   ?= claude codex agy
PROJECT ?=

# These names are generic enough that a shell may already export them (a cloud
# PROJECT id, a direnv SKILLS_DIR), so only the command line narrows the install.
ifeq ($(origin AGENT),environment)
override AGENT := claude codex agy
endif
ifeq ($(origin PROJECT),environment)
override PROJECT :=
endif
ifeq ($(origin SKILLS_DIR),environment)
override SKILLS_DIR :=
endif

# Empty or unset overrides use the default configuration directory.
CLAUDE_DIR := $(or $(CLAUDE_CONFIG_DIR),$(HOME)/.claude)
# Derived names, like CLAUDE_DIR: a command-line `CODEX_HOME=` would override
# any reassignment of CODEX_HOME itself.
CODEX_DIR  := $(or $(CODEX_HOME),$(HOME)/.codex)
AGY_DIR    := $(or $(AGY_HOME),$(HOME)/.gemini/antigravity-cli)

# Each host contributes two literal shell arguments: its guard and skills dir.
tgt_claude := $(call shell_quote,$(CLAUDE_DIR)) $(call shell_quote,$(CLAUDE_DIR)/skills)
tgt_codex  := $(call shell_quote,$(CODEX_DIR)) $(call shell_quote,$(CODEX_DIR)/skills)
tgt_agy    := $(call shell_quote,$(AGY_DIR)) $(call shell_quote,$(AGY_DIR)/skills)

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
ifeq ($(strip $(AGENT)),)
$(error AGENT is empty - use claude, codex or agy, or leave it unset for all three)
endif
QTARGETS := $(foreach a,$(sort $(AGENT)),$(tgt_$(a)))
SCOPE   := $(call shell_quote,AGENT=$(AGENT))
endif

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md skills/$(NAME)/templates/*.md

# Empty: a new private directory per run (a fixed name in a shared /tmp could
# hold another user's symlink, and render writes through symlinks).
DEMO_OUT ?=
LANG_OUT ?= ja
DEMO_INPUT ?= $(REPO)/examples/findings.sample.json

.PHONY: help link unlink status check demo test
# `make -j link unlink` must still run the goals in the order given.
.NOTPARALLEL:

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(call shell_quote,$(INSTALL_MAKEFILE)) \
	  | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'
	@echo
	@echo $(call shell_quote,  skill:  $(SKILL))
	@echo "  vars:   AGENT PROJECT SKILLS_DIR CLAUDE_CONFIG_DIR CODEX_HOME AGY_HOME"
	@echo "          PYTHON DEMO_INPUT DEMO_OUT LANG_OUT"

# os.symlink refuses a destination created concurrently, including directories.
link: ## symlink the skill into every installed host's skills dir
	@n=0; fail=0; skill=$$(CDPATH= cd -P -- $(QSKILL) && pwd) || exit 1; set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  guard="$$1"; dir="$$2"; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then \
	    if [ -e "$$guard" ]; then echo "skip     $$d - $$guard is not a directory"; \
	    else echo "skip     $$d - $$guard does not exist"; fi; continue; fi; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(CDPATH= cd -P -- "$$d" 2>/dev/null && pwd)" = "$$skill" ]; then echo "ok       $$d already linked"; n=$$((n+1)); continue; fi; \
	    echo "refusing $$d is a symlink to $$(readlink -- "$$d") - resolve it, then re-run" >&2; fail=1; continue; \
	  elif [ -e "$$d" ]; then \
	    echo "refusing $$d exists and is not a symlink - move it aside first" >&2; fail=1; continue; \
	  fi; \
	  if mkdir -p -- "$$dir" && $(PYTHON) -c 'import os,sys; os.symlink(sys.argv[1], sys.argv[2])' $(QSKILL) "$$d"; then \
	    echo "linked   $$d -> "$(QSKILL); n=$$((n+1)); \
	  else fail=1; fi; \
	done; \
	if [ $$n -eq 0 ] && [ $$fail -eq 0 ]; then echo "nothing linked - no skills directory found for "$(SCOPE) >&2; exit 1; fi; \
	if [ $$fail -ne 0 ]; then echo "$$n linked; the hosts refused above are not" >&2; exit 1; fi; \
	echo "invoke it with:  $(NAME)   (or /$(NAME) in a slash-command harness)"

unlink: ## remove every symlink to this skill from the hosts' skills dirs
	@skill=$$(CDPATH= cd -P -- $(QSKILL) && pwd) || exit 1; set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  dir="$$2"; shift 2; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(CDPATH= cd -P -- "$$d" 2>/dev/null && pwd)" = "$$skill" ]; then rm -f -- "$$d" || exit 1; echo "unlinked $$d"; \
	    else echo "left     $$d - points at $$(readlink -- "$$d"), not this repo"; fi; \
	  elif [ -e "$$d" ]; then echo "left     $$d - not a symlink"; \
	  else echo "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@skill=$$(CDPATH= cd -P -- $(QSKILL) && pwd) || exit 1; set -- $(QTARGETS); \
	while [ "$$#" -gt 0 ]; do \
	  guard="$$1"; dir="$$2"; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - host not installed"; \
	  elif [ -L "$$d" ]; then \
	    target=$$(CDPATH= cd -P -- "$$d" 2>/dev/null && pwd); \
	    if [ "$$target" = "$$skill" ]; then echo "linked   $$d -> $$(readlink -- "$$d")"; \
	    elif [ ! -e "$$d" ]; then echo "dangling $$d -> $$(readlink -- "$$d")"; \
	    else echo "foreign  $$d -> $$(readlink -- "$$d"), not this repo"; fi; \
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
	  grep -ohE '`(reference|scripts|templates)/[A-Za-z][A-Za-z0-9._<>-]*' "$$f" | tr -d '`' | sort -u | while read -r ref; do \
	    for lang in ja en; do \
	      path=$$(printf '%s\n' "$$ref" | sed "s/<lang>/$$lang/g"); \
	      [ -f $(QSKILL)/"$$path" ] || [ -d $(QSKILL)/"$$path" ] || echo "MISS $$f cites $$path, which does not exist"; \
	    done; \
	  done | sort -u; \
	done); \
	if [ -n "$$misses" ]; then echo "$$misses" >&2; fail=1; fi; \
	for template in issue.ja.md issue.en.md plan.ja.md plan.en.md; do \
	  [ -f $(QSKILL)/templates/"$$template" ] || { echo "MISS required templates/$$template is missing or not a regular file" >&2; fail=1; }; \
	done; \
	for f in $(QSKILL)/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -qF "reference/$$b" $(QSKILL)/SKILL.md || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -10 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	head -1 $(QSKILL)/SKILL.md | grep -qx -- '---' || { echo "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' $(QSKILL)/SKILL.md | grep -q '^name: $(NAME)$$' || { echo "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$($(PYTHON) -c 'import sys; v=next((l[13:].strip() for l in open(sys.argv[1], encoding="utf-8") if l.startswith("description: ")), ""); print(len(v.strip("\"")))' $(QSKILL)/SKILL.md); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d chars; listings truncate well before that" >&2; fail=1; }; \
	links=$$(find $(QSKILL) -type l); \
	if [ -n "$$links" ]; then echo "$$links" >&2; \
	  echo "MISS a symlink sits inside the skill; it is linked, not copied, so nothing in it may point elsewhere" >&2; fail=1; fi; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  echo "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in $(QSKILL)/scripts/*.py; do \
	  [ -e "$$p" ] || continue; \
	  $(PYTHON) -W error -c 'import ast,pathlib,sys; ast.parse(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1])' "$$p" \
	    || { echo "MISS $$p does not parse cleanly (syntax or warning)" >&2; fail=1; }; \
	done; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for sample in examples/findings.sample*.json; do \
	  [ -e "$$sample" ] || { echo "MISS no examples/findings.sample*.json to render and check" >&2; fail=1; continue; }; \
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

demo: ## render the sample into DEMO_OUT, or a new private temp dir
	@out=$(call shell_quote,$(DEMO_OUT)); \
	made=; if [ -z "$$out" ]; then out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-demo.XXXXXX") || exit 1; made=1; fi; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(QSKILL)/scripts/render.py $(call shell_quote,$(DEMO_INPUT)) \
	  --out "$$out" --lang $(call shell_quote,$(LANG_OUT)) \
	  || { status=$$?; [ -z "$$made" ] || rmdir -- "$$out" 2>/dev/null; exit $$status; }
