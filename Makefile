OBJDIR = obj
COVDIR = $(OBJDIR)/cov

VERSION_SPEC = src/tkm-version.ads
VERSION      = $(subst v,,$(GIT_REV))
GIT_REV      = $(shell git describe --always)

DESTDIR = /usr/local

NUM_CPUS := $(shell getconf _NPROCESSORS_ONLN)

BUILD_OPTS = -p -j$(NUM_CPUS) -XOBJ_DIR=$(CURDIR)/$(OBJDIR)

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

build_tools: build_keymanager build_cfgtool

build_cfgtool: tkm_cfgtool.gpr $(VERSION_SPEC)
	@gprbuild $(BUILD_OPTS) -P$<

build_keymanager: tkm_keymanager.gpr $(VERSION_SPEC)
	@gprbuild $(BUILD_OPTS) -P$<

build_tests: tkm_tests.gpr
	@gprbuild $(BUILD_OPTS) -P$<

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
	mkdir -p $(DESTDIR)/bin
	mkdir -p $(DESTDIR)/share/tkm
	install -m 755 $(OBJDIR)/tkm_keymanager $(DESTDIR)/bin
	install -m 755 $(OBJDIR)/tkm_cfgtool $(DESTDIR)/bin
	cp schema/* $(DESTDIR)/share/tkm

install_tests: build_tests
	mkdir -p $(DESTDIR)/tests
	install -m 755 $(OBJDIR)/tests/test_runner $(DESTDIR)/tests
	cp -r data schema $(DESTDIR)/tests

clean:
	@rm -rf $(OBJDIR)
	@rm -f git-rev $(VERSION_SPEC)
	@$(MAKE) -C doc clean

doc:
	@$(MAKE) -C doc

FORCE:

.PHONY: doc tests
