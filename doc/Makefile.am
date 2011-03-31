# -*- Makefile -*-

.PHONY: gendoc

ASCIIDOCOPTS=-n -a pygments -a toc -a language=c -a icons \
	     -a imagesdir="images/" \
	     -a stylesdir="${abs_srcdir}/stylesheets/"

gendoc:
	doxygen Doxyfile;
	./gen-tags.sh | ./tags2dict.sh > libnl.dict
	asciidoc $(ASCIIDOCOPTS) core.txt
	./doxygen-link.py libnl.dict core.html > core.tmp.html
	mv core.tmp.html core.html

distclean-local:
	rm -f api/* libnl.tags *.html;
