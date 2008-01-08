#
# lib/Makefile
#
# 	This library is free software; you can redistribute it and/or
#	modify it under the terms of the GNU Lesser General Public
#	License as published by the Free Software Foundation version 2.1
#	of the License.
#
# Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
#

ifeq ($(shell [ ! -r ../Makefile.opts ] && echo 1),)
    include ../Makefile.opts
endif

# Core
CIN      := $(wildcard *.c)
# NETLINK_ROUTE
CIN      += $(wildcard route/*.c)
# Schedulers
CIN      += $(wildcard route/sch/*.c)
# Classifiers
CIN      += $(wildcard route/cls/*.c)
# Link Info Modules
CIN      += $(wildcard route/link/*.c)
# NETLINK_GENERIC
CIN      += $(wildcard genl/*.c)
# fib lookup
CIN      += $(wildcard fib_lookup/*.c)
# Netfilter
CIN      += $(wildcard netfilter/*.c)

DEPS     := $(CIN:%.c=%.d)
OBJ      := $(CIN:%.c=%.o)
CFLAGS   += -fPIC
OUT_SLIB := $(PACKAGE_NAME).so.$(PACKAGE_VERSION)
LN_SLIB  := $(PACKAGE_NAME).so
LN1_SLIB := $(LN_SLIB).1

export

.PHONY: all clean install librtn.a $(OUT_SLIB)


all:
	@echo "  MAKE $(OUT_SLIB)"; \
	$(MAKE) $(OUT_SLIB)

$(OUT_SLIB): ../Makefile.opts $(OBJ)
	@echo "  LD $(OUT_SLIB)"; \
	$(CC) -shared -Wl,-soname,libnl.so.1 -o $(OUT_SLIB) $(OBJ) $(LIBNL_LIB) -lc
	@echo "  LN $(OUT_SLIB) $(LN1_SLIB)"; \
	rm -f $(LN1_SLIB) ; $(LN) -s $(OUT_SLIB) $(LN1_SLIB)
	@echo "  LN $(LN1_SLIB) $(LN_SLIB)"; \
	rm -f $(LN_SLIB) ; $(LN) -s $(LN1_SLIB) $(LN_SLIB)

clean:
	@echo "  CLEAN lib"; \
	$(RM) -f $(OBJ) $(OUT_SLIB) $(LN_SLIB) $(LN1_SLIB); \
	$(RM) -f $(DEPS) $(OUT_SLIB) $(LN_SLIB) $(LN1_SLIB)

distclean:
	@echo "  DISTCLEAN lib"; \
	$(RM) -f $(DEPS)

install:
	mkdir -p $(DESTDIR)$(libdir)/
	install -m 0644 $(OUT_SLIB) $(DESTDIR)$(libdir)
	rm -f $(DESTDIR)$(libdir)/$(LN1_SLIB)
	$(LN) -s $(OUT_SLIB) $(DESTDIR)$(libdir)/$(LN1_SLIB)
	rm -f $(DESTDIR)$(libdir)/$(LN_SLIB)
	$(LN) -s $(LN1_SLIB) $(DESTDIR)$(libdir)/$(LN_SLIB)

$(DEPS): ../Makefile.opts

include ../Makefile.rules
