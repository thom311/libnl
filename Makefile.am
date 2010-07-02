# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = include lib src doc

pkgconfig_DATA = libnl-2.0.pc

sysconfdir = @sysconfdir@/libnl
sysconf_DATA = etc/pktloc

.PHONY: cscope
cscope:
	cscope -b -q -R -Iinclude -slib -ssrc;
