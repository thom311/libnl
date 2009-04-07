#
# lib/Makefile
#
# 	This library is free software; you can redistribute it and/or
#	modify it under the terms of the GNU Lesser General Public
#	License as published by the Free Software Foundation version 2.1
#	of the License.
#
# Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
#

ifeq ($(shell [ ! -r ../Makefile.opts ] && echo 1),)
    include ../Makefile.opts
endif

CORE_C    := $(wildcard *.c)
CORE_OBJ  := $(CORE_C:%.c=%.o)

ROUTE_C   := $(wildcard route/*.c)
ROUTE_C   += $(wildcard route/cls/*.c)
ROUTE_C   += $(wildcard route/sch/*.c)
ROUTE_C   += $(wildcard route/link/*.c)
ROUTE_C   += $(wildcard fib_lookup/*.c)
ROUTE_OBJ := $(ROUTE_C:%.c=%.o)

GENL_C    := $(wildcard genl/*.c)
GENL_OBJ  := $(GENL_C:%.c=%.o)

NF_C    := $(wildcard netfilter/*.c)
NF_OBJ    := $(NF_C:%.c=%.o)

ALL_C     := $(CORE_C) $(ROUTE_C) $(GENL_C) $(NF_C)
ALL_OBJ   := $(ALL_C:%.c=%.o)
DEPS      := $(ALL_C:%.c=%.d)

CFLAGS    += -fPIC

CORE_LIB  := $(PACKAGE_NAME).so
ROUTE_LIB := $(PACKAGE_NAME)-route.so
GENL_LIB  := $(PACKAGE_NAME)-genl.so
NF_LIB    := $(PACKAGE_NAME)-nf.so
LIBS      := $(CORE_LIB) $(ROUTE_LIB) $(GENL_LIB) $(NF_LIB)
LIBS_V    := $(LIBS:%.so=%.so.$(PACKAGE_VERSION))

export

.PHONY: all clean install $(LIBS)

all:
	@echo "  MAKE $(LIBS)"; \
	$(MAKE) $(LIBS)

$(CORE_LIB).$(PACKAGE_VERSION): $(CORE_OBJ)
	@echo "  LD $@"; \
	$(CC) -shared -Wl,-soname=$@ -o $@ $^ $(LIBNL_LIB)

$(CORE_LIB): $(CORE_LIB).$(PACKAGE_VERSION)
	@echo "  LN $@ -> $<"; \
	$(RM) -f $@; $(LN) $< -s $@

$(ROUTE_LIB).$(PACKAGE_VERSION): $(ROUTE_OBJ) $(CORE_LIB)
	@echo "  LD $@"; \
	$(CC) -shared -Wl,-soname=$@ -o $@ $^ $(LIBNL_LIB) -lnl

$(ROUTE_LIB): $(ROUTE_LIB).$(PACKAGE_VERSION)
	@echo "  LN $@ -> $<"; \
	$(RM) -f $@; $(LN) $< -s $@

$(GENL_LIB).$(PACKAGE_VERSION): $(GENL_OBJ) $(CORE_LIB)
	@echo "  LD $@"; \
	$(CC) -shared -Wl,-soname=$@ -o $@ $^ $(LIBNL_LIB) -lnl

$(GENL_LIB): $(GENL_LIB).$(PACKAGE_VERSION)
	@echo "  LN $@ -> $<"; \
	$(RM) -f $@; $(LN) $< -s $@

$(NF_LIB).$(PACKAGE_VERSION): $(NF_OBJ) $(CORE_LIB) $(ROUTE_LIB)
	@echo "  LD $@"; \
	$(CC) -shared -Wl,-soname=$@ -o $@ $^ $(LIBNL_LIB) -lnl -lnl-route

$(NF_LIB): $(NF_LIB).$(PACKAGE_VERSION)
	@echo "  LN $@ -> $<"; \
	$(RM) -f $@; $(LN) $< -s $@

clean:
	@echo "  CLEAN lib"; \
	$(RM) -f $(ALL_OBJ) $(LIBS) $(DEPS) *.so.*

distclean:
	@echo "  DISTCLEAN lib"; \
	$(RM) -f $(DEPS)

install:
	mkdir -p $(DESTDIR)$(libdir)/
	install -m 0644 $(LIBS_V) $(DESTDIR)$(libdir)
	$(LN) -sf $(CORE_LIB:%.so=%.so.$(PACKAGE_VERSION)) $(DESTDIR)$(libdir)/$(CORE_LIB)
	$(LN) -sf $(ROUTE_LIB:%.so=%.so.$(PACKAGE_VERSION)) $(DESTDIR)$(libdir)/$(ROUTE_LIB)
	$(LN) -sf $(GENL_LIB:%.so=%.so.$(PACKAGE_VERSION)) $(DESTDIR)$(libdir)/$(GENL_LIB)
	$(LN) -sf $(NF_LIB:%.so=%.so.$(PACKAGE_VERSION)) $(DESTDIR)$(libdir)/$(NF_LIB)

$(DEPS): ../Makefile.opts

include ../Makefile.rules
