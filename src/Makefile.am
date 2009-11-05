# -*- Makefile -*-

AM_CFLAGS  = -Wall -I${top_srcdir}/include -D_GNU_SOURCE
AM_LDFLAGS = -L${top_builddir}/lib

noinst_PROGRAMS = \
	genl-ctrl-list \
	nf-ct-list nf-log nf-queue nf-monitor \
	nl-addr-add nl-addr-delete nl-addr-list \
	nl-link-list nl-link-set nl-link-stats \
	nl-link-ifindex2name nl-link-name2ifindex \
	nl-neigh-add nl-neigh-delete nl-neigh-list \
	nl-qdisc-delete nl-qdisc-list \
	nl-rule-list \
	nl-neightbl-list \
	nl-monitor \
	nl-tctree-list \
	nl-route-add nl-route-delete nl-route-get nl-route-list \
	nl-fib-lookup \
	nl-list-caches nl-list-sockets \
	nl-util-addr

rtnl_utils_c = rtnl-utils.c utils.c

genl_ctrl_list_SOURCES = genl-ctrl-list.c ctrl-utils.c utils.c
genl_ctrl_list_LDADD = -lnl-genl

nf_ct_list_SOURCES = nf-ct-list.c ct-utils.c utils.c
nf_ct_list_LDADD = -lnl-nf
nf_log_SOURCES = nf-log.c log-utils.c ${rtnl_utils_c}
nf_log_LDADD = -lnl-nf
nf_queue_SOURCES = nf-queue.c queue-utils.c ${rtnl_utils_c}
nf_queue_LDADD = -lnl-nf
nf_monitor_SOURCES = nf-monitor.c utils.c
nf_monitor_LDADD = -lnl-nf

addr_c = addr-utils.c ${rtnl_utils_c}
nl_addr_add_SOURCES = nl-addr-add.c ${addr_c}
nl_addr_add_LDADD = -lnl-route
nl_addr_delete_SOURCES = nl-addr-delete.c ${addr_c}
nl_addr_delete_LDADD = -lnl-route
nl_addr_list_SOURCES = nl-addr-list.c ${addr_c}
nl_addr_list_LDADD = -lnl-route

link_c = link-utils.c ${rtnl_utils_c}
nl_link_list_SOURCES = nl-link-list.c ${link_c}
nl_link_list_LDADD = -lnl-route
nl_link_set_SOURCES = nl-link-set.c ${link_c}
nl_link_set_LDADD = -lnl-route
nl_link_stats_SOURCES = nl-link-stats.c ${link_c}
nl_link_stats_LDADD = -lnl-route
nl_link_ifindex2name_SOURCES = nl-link-ifindex2name.c ${rtnl_utils_c}
nl_link_ifindex2name_LDADD = -lnl-route
nl_link_name2ifindex_SOURCES = nl-link-name2ifindex.c ${rtnl_utils_c}
nl_link_name2ifindex_LDADD = -lnl-route

nl_monitor_SOURCES = nl-monitor.c ${rtnl_utils_c}
nl_monitor_LDADD = -lnl-route

neigh_c = neigh-utils.c ${rtnl_utils_c}
nl_neigh_add_SOURCES = nl-neigh-add.c ${neigh_c}
nl_neigh_add_LDADD = -lnl-route
nl_neigh_delete_SOURCES = nl-neigh-delete.c ${neigh_c}
nl_neigh_delete_LDADD = -lnl-route
nl_neigh_list_SOURCES = nl-neigh-list.c ${neigh_c}
nl_neigh_list_LDADD = -lnl-route

nl_neightbl_list_SOURCES = nl-neightbl-list.c ${rtnl_utils_c}
nl_neightbl_list_LDADD = -lnl-route

qdisc_c = qdisc-utils.c ${rtnl_utils_c}
nl_qdisc_delete_SOURCES = nl-qdisc-delete.c ${qdisc_c}
nl_qdisc_delete_LDADD = -lnl-route
nl_qdisc_list_SOURCES = nl-qdisc-list.c ${qdisc_c}
nl_qdisc_list_LDADD = -lnl-route

route_c = route-utils.c ${rtnl_utils_c}
nl_route_add_SOURCES = nl-route-add.c ${route_c}
nl_route_add_LDADD = -lnl-route
nl_route_delete_SOURCES = nl-route-delete.c ${route_c}
nl_route_delete_LDADD = -lnl-route
nl_route_get_SOURCES = nl-route-get.c ${route_c}
nl_route_get_LDADD = -lnl-route
nl_route_list_SOURCES = nl-route-list.c ${route_c}
nl_route_list_LDADD = -lnl-route

nl_rule_list_SOURCES = nl-rule-list.c rule-utils.c ${rtnl_utils_c}
nl_rule_list_LDADD = -lnl-route

nl_tctree_list_SOURCES = nl-tctree-list.c ${rtnl_utils_c}
nl_tctree_list_LDADD = -lnl-route

nl_fib_lookup_SOURCES = nl-fib-lookup.c ${rtnl_utils_c}
nl_fib_lookup_LDADD = -lnl-route

nl_list_caches_SOURCES = nl-list-caches.c ${rtnl_utils_c}
nl_list_caches_LDADD = -lnl-route
nl_list_sockets_SOURCES = nl-list-sockets.c ${rtnl_utils_c}
nl_list_sockets_LDADD = -lnl-route

nl_util_addr_SOURCES = nl-util-addr.c ${rtnl_utils_c}
nl_util_addr_LDADD = -lnl-route
