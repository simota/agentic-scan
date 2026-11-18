# agentic-scan: run one target across every scan skill in this repo.
#
#   make link      symlink every skill into each installed host's skills dir
#   make unlink    remove those symlinks
#   make status    show what is installed, per skill and host
#   make test      run every skill's offline tests
#   make check     test + self-containment checks, per skill
#   make list      list the skills this Makefile finds
#
#   make test ONLY="bug-scan ux-scan"   # a subset
#   make link AGENT=claude              # passed through to each skill's Makefile
#
# Each skill keeps its own Makefile; this one only fans a target out to them.
# A failing skill does not stop the rest; the run fails at the end if any did.

# A skill is a top-level directory with a Makefile and skills/<name>/SKILL.md.
SCANS := $(patsubst %/Makefile,%,$(wildcard */Makefile))
SCANS := $(foreach s,$(SCANS),$(if $(wildcard $(s)/skills/$(s)/SKILL.md),$(s)))
ONLY  ?=
ifneq ($(ONLY),)
UNKNOWN := $(filter-out $(SCANS),$(ONLY))
ifneq ($(UNKNOWN),)
$(error unknown skill '$(UNKNOWN)' - run make list)
endif
SCANS := $(ONLY)
endif

TARGETS := link unlink status test check

.DEFAULT_GOAL := help
.PHONY: help list $(TARGETS)

help:
	@sed -n '3,11p' Makefile | sed 's/^# \{0,1\}//'

list:
	@for s in $(SCANS); do echo "$$s"; done

$(TARGETS):
	@failed=""; \
	for s in $(SCANS); do \
	  echo "== $$s"; \
	  $(MAKE) --no-print-directory -C "$$s" $@ || failed="$$failed $$s"; \
	done; \
	echo; \
	if [ -n "$$failed" ]; then echo "$@ failed:$$failed"; exit 1; fi; \
	echo "$@ ok: $(words $(SCANS)) skills"
