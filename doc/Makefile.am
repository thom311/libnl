# -*- Makefile -*-

.PHONY: gendoc api_refs asciidoc

ASCIIDOCOPTS=-a pygments -a language=c -a icons \
	     -a toc2 \
	     -a imagesdir="./images/" \
	     -a iconsdir="./images/icons" \
	     -a stylesdir="${abs_srcdir}/stylesheets/"

%.html: %.txt
	asciidoc $(ASCIIDOCOPTS) $<
	./doxygen-link.py libnl.dict $@ > doxygen-link.tmp
	mv doxygen-link.tmp $@

asciidoc: core.html route.html index.html

api_ref:
	doxygen Doxyfile;
	./gen-tags.sh | ./tags2dict.sh > libnl.dict

gendoc:
	$(MAKE) api_ref
	$(MAKE) asciidoc

clean-local:
	rm -f api/* libnl.dict *.html;
