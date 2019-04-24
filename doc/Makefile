DESTDIR ?= html
PREPARE := $(shell mkdir -p $(DESTDIR))

ASCIIDOC_OPTS = \
	-a icons=font \
	-a iconfont-remote! \
	-a stylesdir=css \
	-a stylesheet=styles.css \
	-a sectanchors \
	-o -

all: build_page

$(DESTDIR)/system-overview.svg: images/system-overview.svg
	cp $< $@

build_page: $(DESTDIR)/index.html

README: ../README
	tail -n +4 $< > $@

$(DESTDIR)/index.html: $(DESTDIR)/fonts $(DESTDIR)/css/font-awesome.css
$(DESTDIR)/index.html: $(DESTDIR)/system-overview.svg
$(DESTDIR)/index.html: index README css/styles.css
	TZ=UTC asciidoctor $(ASCIIDOC_OPTS) $< > $@

$(DESTDIR)/css/font-awesome.css: css/font-awesome.css
	mkdir -p $(DESTDIR)/css
	cp $< $@

$(DESTDIR)/fonts: fonts
	cp -R $< $@

clean:
	@rm -rf $(DESTDIR) README
