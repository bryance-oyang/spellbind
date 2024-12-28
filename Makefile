MAKE=make
TOPTARGETS=all clean sanitize debug profile
SUB=test app

.PHONY: $(TOPTARGETS)
$(TOPTARGETS): src $(SUB)
	@echo done

.PHONY: $(SUB)
$(SUB): src
	$(MAKE) -C $@ $(MAKECMDGOALS)

.PHONY: src
src:
	$(MAKE) -C $@ $(MAKECMDGOALS)
