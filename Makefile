OBJDIR = obj
COVDIR = $(OBJDIR)/cov

VERSION_SPEC = src/tkm-version.ads
VERSION      = $(GIT_REV)
GIT_REV      = `git describe --always`

DESTDIR = /usr/local

NUM_CPUS := $(shell getconf _NPROCESSORS_ONLN)

BUILD_OPTS = -p -j$(NUM_CPUS)

all: build_tools

git-rev: FORCE
	@if [ -d .git ]; then \
		if [ -r $@ ]; then \
			if [ "$$(cat $@)" != "$(GIT_REV)" ]; then \
				echo $(GIT_REV) > $@; \
			fi; \
		else \
			echo $(GIT_REV) > $@; \
		fi \
	fi

$(VERSION_SPEC): git-rev
	@echo "package Tkm.Version is"                  > $@
	@echo "   Version_String : constant String :=" >> $@
	@echo "     \"$(VERSION)\";"                   >> $@
	@echo "end Tkm.Version;"                       >> $@

build_tools: tkm_tools.gpr $(VERSION_SPEC)
	@gprbuild $(BUILD_OPTS) -P$<

build_tests: tkm_tests.gpr
	@gprbuild $(GMAKE_OPTS) -P$<

tests: build_tests
	@obj/tests/test_runner

build_all: build_tests build_tools

cov: tkm_tests.gpr
	@rm -f $(COVDIR)/*.gcda
	@gprbuild $(BUILD_OPTS) -P$< -XBUILD="coverage"
	@$(COVDIR)/test_runner || true
	@lcov -c -d $(COVDIR) -o $(COVDIR)/cov.info
	@lcov -e $(COVDIR)/cov.info "$(PWD)/src/*.adb" -o $(COVDIR)/cov.info
	@genhtml --no-branch-coverage $(COVDIR)/cov.info -o $(COVDIR)

install: install_tools

install_tools: build_tools
	install -v -d $(DESTDIR)/bin
	install -m 755 $(OBJDIR)/key_manager $(DESTDIR)/bin

install_tests: build_tests
	install -v -d $(DESTDIR)/tests
	install -m 755 $(OBJDIR)/tests/test_runner $(DESTDIR)/tests

clean:
	@rm -rf $(OBJDIR)
	@rm -f git-rev $(VERSION_SPEC)

FORCE:

.PHONY: build_tools build_tests build_all tests cov install install_tools \
	install_tests clean
