# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I m4

OPT_DIRS =

if ENABLE_CLI
OPT_DIRS += src
endif

SUBDIRS = include lib doc man python $(OPT_DIRS)

pkgconfig_DATA = libnl-3.1.pc \
		 libnl-route-3.1.pc \
		 libnl-genl-3.1.pc \
		 libnl-nf-3.1.pc

sysconfdir = @sysconfdir@/libnl
sysconf_DATA = etc/pktloc etc/classid

EXTRA_DIST = \
	$(sysconf_DATA)

.PHONY: cscope
cscope:
	cscope -b -q -R -Iinclude -slib -ssrc;
