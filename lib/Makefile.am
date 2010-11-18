# -*- Makefile -*-

AM_CPPFLAGS  = -Wall -I${top_srcdir}/include -I${top_builddir}/include -D_GNU_SOURCE -DSYSCONFDIR=\"$(sysconfdir)/libnl\"
AM_LDFLAGS = -version-info 3:0:0

lib_LTLIBRARIES = \
	libnl.la libnl-genl.la libnl-route.la libnl-nf.la

libnl_la_SOURCES = \
	addr.c attr.c cache.c cache_mngr.c cache_mngt.c data.c \
	error.c handlers.c msg.c nl.c object.c socket.c utils.c

libnl_genl_la_LIBADD  = libnl.la
libnl_genl_la_SOURCES = \
	genl/ctrl.c genl/family.c genl/genl.c genl/mngt.c

libnl_nf_la_LIBADD  = libnl-route.la
libnl_nf_la_SOURCES = \
	netfilter/ct.c netfilter/ct_obj.c netfilter/log.c \
	netfilter/log_msg.c netfilter/log_msg_obj.c netfilter/log_obj.c \
	netfilter/netfilter.c netfilter/nfnl.c netfilter/queue.c \
	netfilter/queue_msg.c netfilter/queue_msg_obj.c netfilter/queue_obj.c

CLEANFILES = \
	route/pktloc_grammar.c route/pktloc_grammar.h \
	route/pktloc_syntax.c route/pktloc_syntax.h \
	route/cls/ematch_grammar.c route/cls/ematch_grammar.h \
	route/cls/ematch_syntax.c route/cls/ematch_syntax.h

# Hack to avoid using ylwrap. It does not function correctly in combination
# with --header-file=
route/pktloc_grammar.c: route/pktloc_grammar.l
	$(LEX) --header-file=route/pktloc_grammar.h $(LFLAGS) -o $@ $^

route/pktloc_syntax.c: route/pktloc_syntax.y
	$(YACC) -d $(YFLAGS) -o $@ $^

route/cls/ematch_grammar.c: route/cls/ematch_grammar.l
	$(LEX) --header-file=route/cls/ematch_grammar.h $(LFLAGS) -o $@ $^

route/cls/ematch_syntax.c: route/cls/ematch_syntax.y
	$(YACC) -d $(YFLAGS) -o $@ $^

libnl_route_la_LIBADD  = libnl.la
libnl_route_la_SOURCES = \
	route/addr.c route/class.c route/class_api.c route/class_obj.c \
	route/cls.c route/cls_api.c route/cls_obj.c route/link.c \
	route/neigh.c route/neightbl.c route/nexthop.c route/qdisc.c \
	route/qdisc_api.c route/qdisc_obj.c route/route.c route/route_obj.c \
	route/route_utils.c route/rtnl.c route/rule.c route/tc.c route/classid.c \
	\
	route/cls/fw.c route/cls/police.c route/cls/u32.c route/cls/basic.c \
	route/cls/cgroup.c \
	\
	route/cls/ematch_syntax.c route/cls/ematch_grammar.c \
	route/cls/ematch.c \
	route/cls/ematch/container.c route/cls/ematch/cmp.c \
	route/cls/ematch/nbyte.c route/cls/ematch/text.c \
	route/cls/ematch/meta.c \
	\
	route/link/api.c route/link/vlan.c \
	route/link/bridge.c route/link/inet6.c route/link/inet.c \
	\
	route/sch/blackhole.c route/sch/cbq.c route/sch/dsmark.c \
	route/sch/fifo.c route/sch/htb.c route/sch/netem.c route/sch/prio.c \
	route/sch/red.c route/sch/sfq.c route/sch/tbf.c \
	\
	fib_lookup/lookup.c fib_lookup/request.c \
	\
	route/pktloc_syntax.c route/pktloc_grammar.c route/pktloc.c


if ENABLE_CLI
nobase_pkglib_LTLIBRARIES = \
	cli/qdisc/htb.la \
	cli/qdisc/blackhole.la \
	cli/qdisc/pfifo.la \
	cli/qdisc/bfifo.la \
	cli/cls/basic.la \
	cli/cls/cgroup.la

cli_qdisc_htb_la_LDFLAGS = -module -version-info 0:0:0
cli_qdisc_blackhole_la_LDFLAGS = -module -version-info 0:0:0
cli_qdisc_pfifo_la_LDFLAGS = -module -version-info 0:0:0
cli_qdisc_bfifo_la_LDFLAGS = -module -version-info 0:0:0
cli_cls_basic_la_LDFLAGS = -module -version-info 0:0:0
cli_cls_cgroup_la_LDFLAGS = -module -version-info 0:0:0
endif
