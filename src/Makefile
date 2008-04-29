#
# src/Makefile
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

LDFLAGS	+= -L../lib -lnl
CIN 	:= $(wildcard nl-*.c) $(wildcard genl-*.c) $(wildcard nf-*.c)
TOOLS	:= $(CIN:%.c=%)

all: $(TOOLS)

$(TOOLS): utils.o
nl-route-add nl-route-delete nl-route-list: route-utils.o

nl-%: nl-%.c
	@echo "  LD $@"; \
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

genl-%: genl-%.c
	@echo "  LD $@"; \
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

nf-%: nf-%.c
	@echo "  LD $@"; \
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	@echo "  CLEAN src"; \
	rm -f $(TOOLS) *.o

distclean: clean

install:
	@true

include ../Makefile.rules
