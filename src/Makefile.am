# -*- Makefile -*-

SUBDIRS = lib

AM_CPPFLAGS  = \
	-I${top_srcdir}/include/linux-private \
	-I${top_srcdir}/include \
	-I${top_builddir}/include \
	-D_GNU_SOURCE \
	-DSYSCONFDIR=\"$(sysconfdir)/libnl\"

AM_CFLAGS = -Wall

LDADD = \
	${top_builddir}/src/lib/libnl-cli-3.la \
	${top_builddir}/lib/libnl-3.la \
	${top_builddir}/lib/libnl-nf-3.la \
	${top_builddir}/lib/libnl-genl-3.la \
	${top_builddir}/lib/libnl-route-3.la \
	${top_builddir}/lib/libnl-idiag-3.la

cli_programs = \
	genl-ctrl-list \
	idiag-socket-details \
	nf-ct-add \
	nf-ct-list \
	nf-exp-add \
	nf-exp-delete \
	nf-exp-list \
	nf-log \
	nf-monitor \
	nf-queue \
	nl-addr-add \
	nl-addr-delete \
	nl-addr-list \
	nl-class-add \
	nl-class-delete \
	nl-classid-lookup \
	nl-class-list \
	nl-cls-add \
	nl-cls-delete \
	nl-cls-list \
	nl-fib-lookup \
	nl-link-enslave \
	nl-link-ifindex2name \
	nl-link-list \
	nl-link-name2ifindex \
	nl-link-release \
	nl-link-set \
	nl-link-stats \
	nl-list-caches \
	nl-list-sockets \
	nl-monitor \
	nl-neigh-add \
	nl-neigh-delete \
	nl-neigh-list \
	nl-neightbl-list \
	nl-pktloc-lookup \
	nl-qdisc-add \
	nl-qdisc-delete \
	nl-qdisc-list \
	nl-route-add \
	nl-route-delete \
	nl-route-get \
	nl-route-list \
	nl-rule-list \
	nl-tctree-list \
	nl-util-addr

if ENABLE_CLI_INSTALL_BIN
bin_PROGRAMS = $(cli_programs)
else
if ENABLE_CLI_INSTALL_SBIN
sbin_PROGRAMS = $(cli_programs)
else
noinst_PROGRAMS = $(cli_programs)
endif
endif

genl_ctrl_list_SOURCES = genl-ctrl-list.c 

nf_ct_list_SOURCES = nf-ct-list.c 
nf_ct_add_SOURCES = nf-ct-add.c
nf_log_SOURCES = nf-log.c
nf_queue_SOURCES = nf-queue.c 
nf_monitor_SOURCES = nf-monitor.c

nf_exp_list_SOURCES = nf-exp-list.c 
nf_exp_add_SOURCES = nf-exp-add.c 
nf_exp_delete_SOURCES = nf-exp-delete.c 

nl_addr_add_SOURCES = nl-addr-add.c
nl_addr_delete_SOURCES = nl-addr-delete.c
nl_addr_list_SOURCES = nl-addr-list.c

nl_link_list_SOURCES = nl-link-list.c
nl_link_set_SOURCES = nl-link-set.c
nl_link_stats_SOURCES = nl-link-stats.c
nl_link_ifindex2name_SOURCES = nl-link-ifindex2name.c
nl_link_name2ifindex_SOURCES = nl-link-name2ifindex.c

nl_monitor_SOURCES = nl-monitor.c

nl_neigh_add_SOURCES = nl-neigh-add.c
nl_neigh_delete_SOURCES = nl-neigh-delete.c
nl_neigh_list_SOURCES = nl-neigh-list.c

nl_neightbl_list_SOURCES = nl-neightbl-list.c

nl_qdisc_add_SOURCES = nl-qdisc-add.c
nl_qdisc_delete_SOURCES = nl-qdisc-delete.c
nl_qdisc_list_SOURCES = nl-qdisc-list.c

nl_class_add_SOURCES = nl-class-add.c
nl_class_delete_SOURCES = nl-class-delete.c
nl_class_list_SOURCES = nl-class-list.c

nl_cls_add_SOURCES = nl-cls-add.c
nl_cls_list_SOURCES = nl-cls-list.c
nl_cls_delete_SOURCES = nl-cls-delete.c

nl_route_add_SOURCES = nl-route-add.c
nl_route_delete_SOURCES = nl-route-delete.c
nl_route_get_SOURCES = nl-route-get.c
nl_route_list_SOURCES = nl-route-list.c

nl_rule_list_SOURCES = nl-rule-list.c

nl_tctree_list_SOURCES = nl-tctree-list.c

nl_fib_lookup_SOURCES = nl-fib-lookup.c

nl_list_caches_SOURCES = nl-list-caches.c
nl_list_sockets_SOURCES = nl-list-sockets.c

nl_util_addr_SOURCES = nl-util-addr.c

nl_pktloc_lookup_SOURCES = nl-pktloc-lookup.c

nl_classid_lookup_SOURCES = nl-classid-lookup.c

idiag_socket_details_SOURCES = idiag-socket-details.c
