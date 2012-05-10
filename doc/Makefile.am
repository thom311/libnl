# -*- Makefile -*-

.PHONY: gendoc api_ref asciidoc

ASCIIDOCOPTS=-a pygments -a language=c -a icons \
	     -a toc2 \
	     -a numbered \
	     -a imagesdir="./images/" \
	     -a iconsdir="./images/icons" \
	     -a stylesdir="${abs_srcdir}/stylesheets/"

EXTRA_DIST = \
	Doxyfile \
	DoxygenLayout.xml \
	core.txt \
	route.txt \
	index.txt \
	libnl.css \
	README \
	doxygen-link.py \
	gen-tags.sh \
	resolve-asciidoc-refs.py \
	stylesheets/asciidoc.css \
	stylesheets/asciidoc-manpage.css \
	stylesheets/docbook-xsl.css \
	stylesheets/flask.css \
	stylesheets/flask-manpage.css \
	stylesheets/pygments.css \
	stylesheets/slidy.css \
	stylesheets/toc2.css \
	stylesheets/volnitsky.css \
	stylesheets/volnitsky-manpage.css \
	stylesheets/xhtml11-quirks.css \
	images/asciidoc__1.png \
	images/asciidoc__2.png \
	images/asciidoc__3.png \
	images/asciidoc__4.png \
	images/asciidoc__5.png \
	images/asciidoc__6.png \
	images/asciidoc__7.png \
	images/attribute_hdr.png \
	images/classful_qdisc.png \
	images/classless_qdisc_nbands.png \
	images/classless_qdisc.png \
	images/ifinfomsg.png \
	images/library_overview.png \
	images/nlmsgerr.png \
	images/nlmsghdr.png \
	images/qdisc_default.png \
	images/qdisc_mq.png \
	images/tc_obj.png \
	images/tc_overview.png \
	images/icons/caution.png \
	images/icons/example.png \
	images/icons/home.png \
	images/icons/important.png \
	images/icons/next.png \
	images/icons/note.png \
	images/icons/prev.png \
	images/icons/README \
	images/icons/tip.png \
	images/icons/up.png \
	images/icons/warning.png \
	images/icons/callouts/1.png \
	images/icons/callouts/2.png \
	images/icons/callouts/3.png \
	images/icons/callouts/4.png \
	images/icons/callouts/5.png \
	images/icons/callouts/6.png \
	images/icons/callouts/7.png \
	images/icons/callouts/8.png \
	images/icons/callouts/9.png \
	images/icons/callouts/10.png \
	images/icons/callouts/11.png \
	images/icons/callouts/12.png \
	images/icons/callouts/13.png \
	images/icons/callouts/14.png \
	images/icons/callouts/15.png

link_doc:
if LINK_DOC
	./gen-tags.sh > libnl.dict
else
	@echo "Warning: Linking to API reference is disabled, check configure output"
endif
	

%.html: %.txt link_doc
	./resolve-asciidoc-refs.py $< > asciidoc.tmp
	asciidoc $(ASCIIDOCOPTS) -o $@ asciidoc.tmp
if LINK_DOC
	./doxygen-link.py libnl.dict $@ > asciidoc.tmp
	mv asciidoc.tmp $@
endif

asciidoc: core.html route.html index.html

api_ref:
	doxygen Doxyfile;

gendoc:
if GENERATE_DOC
if HAVE_DOXYGEN
	$(MAKE) api_ref
else
	@echo "Warning: Building of API reference (doxygen) is disabled, check autoconf logs"
endif
if HAVE_ASCIIDOC
	$(MAKE) asciidoc
else
	@echo "Warning: Building of asciidoc files is disabled, check autoconf logs"
endif
else
	@echo "Warning: Building of documentation disabled by user or autoconf"
endif

clean-local:
	rm -f api/* libnl.dict *.html;
