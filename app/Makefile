MAKE=make
TOPTARGETS=all clean sanitize debug profile
SUBDIRS=$(wildcard */.)

.PHONY: $(TOPTARGETS)
$(TOPTARGETS): $(SUBDIRS)
	@echo done

.PHONY: $(SUBDIRS)
$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS)
