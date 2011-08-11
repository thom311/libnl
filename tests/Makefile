#
# src/Makefile
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

LDFLAGS	+= -L../lib -lnl -lnl-genl -lnl-route
CIN 	:= $(wildcard test-*.c)
TESTS	:= $(CIN:%.c=%)

all: $(TESTS)

test-%: test-%.c
	@echo "  LD $@"; \
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	@echo "  CLEAN src"; \
	rm -f $(TESTS)

distclean: clean

install:
	@true
