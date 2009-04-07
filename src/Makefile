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
nl-route-add nl-route-delete nl-route-list: route-utils.o rtnl-utils.o
nl-route-get: rtnl-utils.o
nl-addr-add nl-addr-delete nl-addr-list: addr-utils.o rtnl-utils.o
nl-link-list nl-link-set nl-link-stats: link-utils.o rtnl-utils.o
nl-link-ifindex2name nl-link-name2ifindex: rtnl-utils.o
nl-neigh-add nl-neigh-delete nl-neigh-list: neigh-utils.o rtnl-utils.o
nl-qdisc-delete nl-qdisc-list: qdisc-utils.o rtnl-utils.o
nl-rule-list: rule-utils.o rtnl-utils.o
nl-neightbl-list: rtnl-utils.o
nl-monitor: rtnl-utils.o
nl-tctree-list: rtnl-utils.o

genl-ctrl-list: ctrl-utils.o

nf-ct-list: ct-utils.o
nf-log: log-utils.o rtnl-utils.o
nf-queue: queue-utils.o rtnl-utils.o

nl-%: nl-%.o
	@echo "  LD $@"; \
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lnl-route

genl-%: genl-%.o
	@echo "  LD $@"; \
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lnl-genl

nf-%: nf-%.o
	@echo "  LD $@"; \
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS) -lnl-nf -lnl-route

clean:
	@echo "  CLEAN src"; \
	rm -f $(TOOLS) *.o

distclean: clean

install:
	@true

include ../Makefile.rules
