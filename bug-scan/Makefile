# bug-scan: install, test and demo helpers
#
#   make link      symlink skills/bug-scan into every installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per host
#   make test      run the offline tests
#   make check     verify the skill is self-contained and internally consistent
#   make demo      render the sample into $(DEMO_OUT)
#
#   make link AGENT=claude             # this host only
#   make link SKILLS_DIR=/some/path    # one literal path
#   make demo LANG_OUT=en NO_PDF=1     # English, HTML only

NAME    := bug-scan
REPO    := $(shell pwd -P)
SKILL   := $(REPO)/skills/$(NAME)
PYTHON  ?= python3
AGENT   ?= claude codex agy
CODEX_HOME ?= $(HOME)/.codex
AGY_HOME   ?= $(HOME)/.gemini/antigravity-cli
DEMO_OUT ?= $(or $(TMPDIR),/tmp)/$(NAME)-demo
LANG_OUT ?= ja
NO_PDF   ?=

tgt_claude := $(HOME)/.claude $(HOME)/.claude/skills
tgt_codex  := $(CODEX_HOME) $(CODEX_HOME)/skills
tgt_agy    := $(AGY_HOME) $(AGY_HOME)/skills

ifneq ($(SKILLS_DIR),)
TARGETS := $(SKILLS_DIR) $(SKILLS_DIR)
else
UNKNOWN := $(filter-out claude codex agy,$(AGENT))
ifneq ($(UNKNOWN),)
$(error unknown AGENT '$(UNKNOWN)' - use claude, codex or agy, or set SKILLS_DIR)
endif
TARGETS := $(foreach a,$(sort $(AGENT)),$(tgt_$(a)))
endif

.PHONY: help link unlink status test check demo

help: ## list targets
	@grep -E '^[a-z-]+:.*## ' Makefile | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'

link: ## symlink the skill into every installed host's skills dir
	@n=0; set -- $(TARGETS); while [ "$$#" -gt 0 ]; do \
	  guard=$$1; dir=$$2; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - $$guard does not exist"; continue; fi; \
	  if [ -L "$$d" ]; then \
	    if [ "$$(readlink "$$d")" = "$(SKILL)" ]; then echo "ok       $$d already linked"; n=$$((n+1)); continue; fi; \
	    echo "refusing $$d is a symlink to $$(readlink "$$d")" >&2; exit 1; \
	  elif [ -e "$$d" ]; then echo "refusing $$d exists and is not a symlink" >&2; exit 1; fi; \
	  mkdir -p "$$dir" && ln -s "$(SKILL)" "$$d" || exit 1; \
	  echo "linked   $$d -> $(SKILL)"; n=$$((n+1)); \
	done; \
	[ $$n -gt 0 ] || { echo "nothing linked: no skills directory found" >&2; exit 1; }

unlink: ## remove the symlinks this Makefile created
	@set -- $(TARGETS); while [ "$$#" -gt 0 ]; do \
	  dir=$$2; shift 2; d="$$dir/$(NAME)"; \
	  if [ -L "$$d" ] && [ "$$(readlink "$$d")" = "$(SKILL)" ]; then rm -f "$$d"; echo "unlinked $$d"; \
	  elif [ -e "$$d" ] || [ -L "$$d" ]; then echo "left     $$d - not ours"; else echo "absent   $$d"; fi; \
	done

status: ## show what is installed, per host
	@set -- $(TARGETS); while [ "$$#" -gt 0 ]; do \
	  guard=$$1; dir=$$2; shift 2; d="$$dir/$(NAME)"; \
	  if [ ! -d "$$guard" ]; then echo "skip     $$d - host not installed"; \
	  elif [ -L "$$d" ]; then echo "symlink  $$d -> $$(readlink "$$d")"; \
	  elif [ -e "$$d" ]; then echo "other    $$d"; else echo "absent   $$d"; fi; \
	done

test: ## run offline tests
	@PYTHONDONTWRITEBYTECODE=1 $(PYTHON) -m unittest discover -s tests

check: test ## verify the skill is self-contained and internally consistent
	@fail=0; skill=skills/$(NAME); \
	for f in $$skill/reference/*.md; do \
	  b=$$(basename "$$f"); \
	  grep -qF "$$b" $$skill/SKILL.md || { echo "MISS reference/$$b exists but SKILL.md never names it" >&2; fail=1; }; \
	  head -5 "$$f" | grep -q '\*\*Read when:\*\*' || { echo "MISS reference/$$b has no **Read when:** header" >&2; fail=1; }; \
	done; \
	for ref in $$(grep -oE 'reference/[a-z-]+\.md' $$skill/SKILL.md | sort -u); do \
	  [ -e "$$skill/$$ref" ] || { echo "MISS SKILL.md cites $$ref, which does not exist" >&2; fail=1; }; \
	done; \
	for script in $$(grep -ohE 'scripts/[a-z_]+\.py' $$skill/SKILL.md $$skill/reference/*.md README.md | sort -u); do \
	  [ -e "$$skill/$$script" ] || { echo "MISS docs cite $$script, which does not exist" >&2; fail=1; }; \
	done; \
	head -1 $$skill/SKILL.md | grep -qx -- '---' || { echo "MISS SKILL.md has no frontmatter" >&2; fail=1; }; \
	sed -n '2,6p' $$skill/SKILL.md | grep -q '^name: $(NAME)$$' || { echo "MISS frontmatter name" >&2; fail=1; }; \
	d=$$(sed -n 's/^description: //p' $$skill/SKILL.md | head -1 | wc -c); \
	[ "$$d" -le 400 ] || { echo "MISS description is $$d chars; listings truncate before that" >&2; fail=1; }; \
	for p in $$skill/scripts/*.py; do \
	  $(PYTHON) -c 'import ast,sys; ast.parse(open(sys.argv[1],encoding="utf-8").read(), sys.argv[1], feature_version=(3,9))' "$$p" \
	    || { echo "MISS $$p does not parse on Python 3.9" >&2; fail=1; }; \
	done; \
	out=$$(mktemp -d "$${TMPDIR:-/tmp}/$(NAME)-check.XXXXXX") || exit 1; \
	cp examples/findings.sample.json "$$out/findings.json"; cp examples/surfaces.sample.json "$$out/surfaces.json"; cp examples/history.sample.json "$$out/history.json"; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/findings.py renumber "$$out/findings.json" | grep -q 'already in order' \
	  || { echo "MISS the sample is not numbered in priority order" >&2; fail=1; }; \
	en="$$out/en"; mkdir -p "$$en"; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/render.py "$$out/findings.json" --out "$$en" --lang en --no-pdf >/dev/null \
	  || { echo "MISS the sample does not render in English" >&2; fail=1; }; \
	rm -rf "$$en"; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/render.py "$$out/findings.json" --out "$$out" --no-pdf >/dev/null \
	  || { echo "MISS the sample does not render" >&2; fail=1; }; \
	echo '{"limitations": ["report.pdf not produced: make check runs without a browser"]}' > "$$out.frag"; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/findings.py merge "$$out/findings.json" "$$out.frag" >/dev/null; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/render.py "$$out/findings.json" --out "$$out" --no-pdf >/dev/null; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/contract_check.py "$$out" --no-pdf >/dev/null \
	  || { echo "MISS the sample does not pass the contract" >&2; fail=1; }; \
	exp="$$out.export"; \
	PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/export.py issues "$$out/findings.json" --out "$$exp/issues" >/dev/null \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/export.py sarif "$$out/findings.json" --out "$$exp/bug-scan.sarif" >/dev/null \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/export.py csv "$$out/findings.json" --out "$$exp/register.csv" >/dev/null \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $$skill/scripts/impact.py "$$out" --files api/orders/validate.py >/dev/null \
	  || { echo "MISS the sample does not export or analyse" >&2; fail=1; }; \
	rm -rf "$$out" "$$out.frag" "$$exp"; \
	[ $$fail -eq 0 ] && echo "check ok"; exit $$fail

demo: ## render the sample into DEMO_OUT (LANG_OUT=en, NO_PDF=1)
	@mkdir -p "$(DEMO_OUT)" && cp examples/findings.sample.json "$(DEMO_OUT)/findings.json" \
	  && cp examples/surfaces.sample.json "$(DEMO_OUT)/surfaces.json" && cp examples/history.sample.json "$(DEMO_OUT)/history.json" \
	  && PYTHONDONTWRITEBYTECODE=1 $(PYTHON) $(SKILL)/scripts/render.py "$(DEMO_OUT)/findings.json" --out "$(DEMO_OUT)" --lang $(LANG_OUT) $(if $(NO_PDF),--no-pdf,)
