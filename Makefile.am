# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I m4

OPT_DIRS =
PKGCONFIGS =

if ENABLE_CLI
OPT_DIRS += src
PKGCONFIGS += libnl-cli-3.0.pc
endif

SUBDIRS = include lib doc man python $(OPT_DIRS)

pkgconfig_DATA = libnl-3.0.pc \
		 libnl-route-3.0.pc \
		 libnl-genl-3.0.pc \
		 libnl-nf-3.0.pc \
		 $(PKGCONFIGS)


pkgsysconfdir = ${sysconfdir}/libnl
pkgsysconf_DATA = etc/pktloc etc/classid

EXTRA_DIST = \
	$(pkgsysconf_DATA)

.PHONY: cscope
cscope:
	cscope -b -q -R -Iinclude -slib -ssrc;
