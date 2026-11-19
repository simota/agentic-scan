# performance-scan — install helpers
#
#   make link      symlink skills/performance-scan into every installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per host
#   make check     verify the skill is self-contained and internally consistent
#   make demo      render examples/findings.sample.json (LANG_OUT=ja: findings.sample.ja.json) into $(DEMO_OUT)
#
# A host that is not installed is skipped and named. Narrowing is explicit:
#
#   make link AGENT=claude             # this host only
#   make link PROJECT=/path/to/repo    # that project's .claude/skills instead
#   make link SKILLS_DIR=/some/path    # one literal path; AGENT unused
#   make demo LANG_OUT=ja              # Japanese sample and labels (default: the record's language)

NAME    := performance-scan
# PYTHON is an executable name or path, including paths containing spaces.
PYTHON  ?= python3
# Make's path functions split on whitespace, even when the filename is quoted.
shell_quote = '$(subst ','"'"',$(1))'
# Earlier -f/MAKEFILES entries may precede this file. Select an existing suffix,
# preserving spaces inside its path instead of taking Make's last whitespace word.
REPO    := $(shell $(call shell_quote,$(PYTHON)) -c 'from pathlib import Path; import sys; \
  parts = sys.argv[1].split(" "); paths = (Path(" ".join(parts[i:])) for i in range(len(parts))); \
  print(next(p for p in paths if p.is_file()).resolve().parent)' $(call shell_quote,$(MAKEFILE_LIST)))
SKILL   := $(REPO)/skills/$(NAME)

# Generic names such as PROJECT are often exported for unrelated tools. Only a
# command-line or makefile setting may redirect where links are written.
# "environment%" also covers make -e ("environment override"), including a -e
# inherited from a parent make. (Plain conditionals: macOS still ships GNU
# Make 3.81, which lacks undefine.)
ifneq ($(filter environment%,$(origin AGENT)),)
override AGENT := claude codex agy
endif
ifneq ($(filter environment%,$(origin PROJECT)),)
override PROJECT :=
endif
ifneq ($(filter environment%,$(origin SKILLS_DIR)),)
override SKILLS_DIR :=
endif
AGENT   ?= claude codex agy
PROJECT ?=
SKILLS_DIR ?=

# An exported but empty value falls back to the default instead of ".". The
# resolved values are override variables, so neither make -e (environment wins
# over makefile assignments) nor a command-line setting can bypass the fallback.
override claude_home := $(or $(CLAUDE_HOME),$(CLAUDE_CONFIG_DIR),$(HOME)/.claude)
override codex_home  := $(or $(CODEX_HOME),$(HOME)/.codex)
override agy_home    := $(or $(AGY_HOME),$(HOME)/.gemini/antigravity-cli)

INSTALL = $(call shell_quote,$(PYTHON)) $(call shell_quote,$(REPO)/scripts/install.py) \
  --skill $(call shell_quote,$(SKILL)) --agents $(call shell_quote,$(AGENT)) \
  --project $(call shell_quote,$(PROJECT)) --skills-dir $(call shell_quote,$(SKILLS_DIR)) \
  --claude-home $(call shell_quote,$(claude_home)) \
  --codex-home $(call shell_quote,$(codex_home)) --agy-home $(call shell_quote,$(agy_home))

DOCS := README.md skills/$(NAME)/*.md skills/$(NAME)/reference/*.md

# Inside the repository (git-ignored): a fixed name under a shared /tmp could be
# pre-created by another user with links that the renderer would follow.
DEMO_OUT ?= $(REPO)/.demo
# Empty: render in the record's own language.
LANG_OUT ?=
DEMO_INPUT ?= $(REPO)/examples/findings.sample$(if $(filter ja,$(LANG_OUT)),.ja,).json

.PHONY: help link unlink status check demo test

help: ## list targets
	@echo "$(NAME) - skill install"
	@echo
	@grep -E '^[a-z-]+:.*## ' $(call shell_quote,$(REPO)/Makefile) \
	  | awk -F':.*## ' '{printf "  %-8s %s\n", $$1, $$2}'
	@echo
	@echo $(call shell_quote,  skill:  $(SKILL))
	@echo "  vars:   AGENT PROJECT SKILLS_DIR CLAUDE_HOME CODEX_HOME AGY_HOME PYTHON DEMO_OUT LANG_OUT"

link: ## symlink the skill into every installed host's skills dir
	@$(INSTALL) link

unlink: ## remove the symlinks this Makefile created
	@$(INSTALL) unlink

status: ## show what is installed, per host
	@$(INSTALL) status

test: ## run offline regression tests
	@cd $(call shell_quote,$(REPO)) && PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) -m unittest discover -s tests -v

check: test ## verify the skill is self-contained and internally consistent
	@cd $(call shell_quote,$(REPO)) || exit 1; fail=0; \
	misses=$$( \
	for f in $(DOCS); do \
	  grep -ohE '`(reference|scripts|templates)/[A-Za-z][A-Za-z0-9._-]*`' "$$f" | tr -d '`' | sort -u | while read -r ref; do \
	    [ -e $(call shell_quote,$(SKILL))/"$$ref" ] || echo "MISS $$f cites $$ref, which does not exist"; \
	  done; \
	done); \
	if [ -n "$$misses" ]; then echo "$$misses" >&2; fail=1; fi; \
	for f in $(call shell_quote,$(SKILL))/reference/*.md; do \
	  [ -e "$$f" ] || continue; b=$$(basename "$$f"); \
	  grep -qF "reference/$$b" $(call shell_quote,$(SKILL)/SKILL.md) || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -10 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	head -1 $(call shell_quote,$(SKILL)/SKILL.md) | grep -qx -- '---' || { echo "MISS SKILL.md does not open a frontmatter fence" >&2; fail=1; }; \
	sed -n '2,8p' $(call shell_quote,$(SKILL)/SKILL.md) | grep -q '^name: $(NAME)$$' || { echo "MISS SKILL.md frontmatter has no 'name: $(NAME)' line" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' $(call shell_quote,$(SKILL)/SKILL.md) | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d bytes; listings truncate well before that" >&2; fail=1; }; \
	if grep -nE '`[^`]*\.\./' $(DOCS) >&2; then \
	  echo "MISS a cited path reaches through a parent directory" >&2; fail=1; fi; \
	for p in $(call shell_quote,$(SKILL))/scripts/*.py $(call shell_quote,$(REPO))/scripts/*.py; do \
	  [ -e "$$p" ] || continue; \
	  $(call shell_quote,$(PYTHON)) -c 'import ast,sys; ast.parse(open(sys.argv[1]).read(), sys.argv[1])' "$$p" \
	    || { echo "MISS $$p does not parse" >&2; fail=1; }; \
	done; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	for sample in examples/findings.sample*.json; do \
	  for lang in ja en; do \
	    err=$$(PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/render.py) "$$sample" --out "$$out" --lang $$lang 2>&1 >/dev/null) \
	      || { echo "$$err" >&2; echo "MISS render.py fails on $$sample ($$lang)" >&2; fail=1; }; \
	  done; \
	  cp "$$sample" "$$out/findings.json"; \
	  PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/findings.py) check "$$out" >/dev/null \
	    || { echo "MISS $$sample does not pass the run contract" >&2; fail=1; }; \
	  rm -f "$$out"/*; \
	done; \
	PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/compare.py) \
	  examples/findings.sample.baseline.json examples/findings.sample.json --fail-on High >/dev/null 2>&1 \
	  || { echo "MISS compare.py fails on the sample baseline and sample" >&2; fail=1; }; \
	PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/summary.py) \
	  examples/findings.sample.json --baseline examples/findings.sample.baseline.json >/dev/null \
	  || { echo "MISS summary.py fails on the sample" >&2; fail=1; }; \
	for lang in ja en; do \
	  PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/issues.py) \
	    examples/findings.sample.json --out "$$out/issues-$$lang" --lang $$lang >/dev/null \
	    || { echo "MISS issues.py fails on the sample ($$lang)" >&2; fail=1; }; \
	done; \
	mkdir "$$out/run" && cp examples/findings.sample.json "$$out/run/findings.json" \
	  && PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/compare.py) \
	    examples/findings.sample.baseline.json "$$out/run/findings.json" --carry "$$out/carry.json" >/dev/null 2>&1 \
	  && PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/findings.py) \
	    merge "$$out/run/findings.json" "$$out/carry.json" >/dev/null \
	  && PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/findings.py) \
	    set "$$out/run/findings.json" P-001 --status Fixed --render >/dev/null \
	  && PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/findings.py) check "$$out/run" >/dev/null \
	  || { echo "MISS compare --carry, merge, set --render and check fail on the samples" >&2; fail=1; }; \
	PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/sarif.py) \
	  examples/findings.sample.json --out "$$out/sample.sarif" --baseline examples/findings.sample.baseline.json >/dev/null \
	  || { echo "MISS sarif.py fails on the sample" >&2; fail=1; }; \
	rm -rf "$$out"; \
	[ $$fail -eq 0 ] && echo "check ok - $$(ls $(call shell_quote,$(SKILL))/reference/*.md | wc -l | tr -d ' ') reference files cited and headed, samples render and pass the contract, compare/carry/set/summary/issues/sarif run"; \
	exit $$fail

demo: ## render the sample findings into DEMO_OUT (dashboard + report.md)
	@PYTHONDONTWRITEBYTECODE=1 $(call shell_quote,$(PYTHON)) $(call shell_quote,$(SKILL)/scripts/render.py) $(call shell_quote,$(DEMO_INPUT)) \
	  --out $(call shell_quote,$(DEMO_OUT)) $(if $(LANG_OUT),--lang $(call shell_quote,$(LANG_OUT)))
