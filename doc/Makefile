DESTDIR   ?= html
STYLEPATH ?= .
PREPARE   := $(shell mkdir -p $(DESTDIR))

ASCIIDOC_OPTS = \
	--backend=xhtml11 \
	--conf-file=page.conf \
	-a stylesdir=$(STYLEPATH) \
	-a linkcss \
	-a disable-javascript \
	-o -

all: $(DESTDIR)/asciidoc.css $(DESTDIR)/system-overview.svg build_page

$(DESTDIR)/asciidoc.css: asciidoc.css
	cp $< $@

$(DESTDIR)/system-overview.svg: images/system-overview.svg
	cp $< $@

build_page: $(DESTDIR)/index.html

$(DESTDIR)/index.html: index page.conf ../README
	asciidoc $(ASCIIDOC_OPTS) $< > $@

clean:
	@rm -rf $(DESTDIR)
