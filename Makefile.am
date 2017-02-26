# -*- Makefile -*-

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = \
	lib \
	man \
	python \
	tests

if ENABLE_CLI
SUBDIRS += src
endif

pkgconfig_DATA = \
	libnl-3.0.pc \
	libnl-route-3.0.pc \
	libnl-genl-3.0.pc \
	libnl-nf-3.0.pc \
	libnl-xfrm-3.0.pc \
	libnl-idiag-3.0.pc

###############################################################################

libnlincludedir = $(includedir)/libnl@MAJ_VERSION@

libnlinclude_netlinkdir = $(libnlincludedir)/netlink
libnlinclude_netlink_HEADERS = \
	include/netlink/addr.h \
	include/netlink/attr.h \
	include/netlink/cache-api.h \
	include/netlink/cache.h \
	include/netlink/data.h \
	include/netlink/errno.h \
	include/netlink/handlers.h \
	include/netlink/hash.h \
	include/netlink/hashtable.h \
	include/netlink/list.h \
	include/netlink/msg.h \
	include/netlink/netlink-compat.h \
	include/netlink/netlink-kernel.h \
	include/netlink/netlink.h \
	include/netlink/object-api.h \
	include/netlink/object.h \
	include/netlink/socket.h \
	include/netlink/types.h \
	include/netlink/utils.h \
	include/netlink/version.h
libnlinclude_netlink_fib_lookupdir = $(libnlincludedir)/netlink/fib_lookup
libnlinclude_netlink_fib_lookup_HEADERS = \
	include/netlink/fib_lookup/lookup.h \
	include/netlink/fib_lookup/request.h
libnlinclude_netlink_genldir = $(libnlincludedir)/netlink/genl
libnlinclude_netlink_genl_HEADERS = \
	include/netlink/genl/ctrl.h \
	include/netlink/genl/family.h \
	include/netlink/genl/genl.h \
	include/netlink/genl/mngt.h
libnlinclude_netlink_idiagdir = $(libnlincludedir)/netlink/idiag
libnlinclude_netlink_idiag_HEADERS = \
	include/netlink/idiag/idiagnl.h \
	include/netlink/idiag/meminfo.h \
	include/netlink/idiag/msg.h \
	include/netlink/idiag/req.h \
	include/netlink/idiag/vegasinfo.h
libnlinclude_netlink_netfilterdir = $(libnlincludedir)/netlink/netfilter
libnlinclude_netlink_netfilter_HEADERS = \
	include/netlink/netfilter/ct.h \
	include/netlink/netfilter/exp.h \
	include/netlink/netfilter/log.h \
	include/netlink/netfilter/log_msg.h \
	include/netlink/netfilter/netfilter.h \
	include/netlink/netfilter/nfnl.h \
	include/netlink/netfilter/queue.h \
	include/netlink/netfilter/queue_msg.h
libnlinclude_netlink_routedir = $(libnlincludedir)/netlink/route
libnlinclude_netlink_route_HEADERS = \
	include/netlink/route/action.h \
	include/netlink/route/addr.h \
	include/netlink/route/class.h \
	include/netlink/route/classifier.h \
	include/netlink/route/link.h \
	include/netlink/route/neighbour.h \
	include/netlink/route/neightbl.h \
	include/netlink/route/nexthop.h \
	include/netlink/route/pktloc.h \
	include/netlink/route/qdisc.h \
	include/netlink/route/route.h \
	include/netlink/route/rtnl.h \
	include/netlink/route/rule.h \
	include/netlink/route/tc-api.h \
	include/netlink/route/tc.h
libnlinclude_netlink_route_actdir = $(libnlincludedir)/netlink/route/act
libnlinclude_netlink_route_act_HEADERS = \
	include/netlink/route/act/gact.h \
	include/netlink/route/act/mirred.h \
	include/netlink/route/act/skbedit.h
libnlinclude_netlink_route_clsdir = $(libnlincludedir)/netlink/route/cls
libnlinclude_netlink_route_cls_HEADERS = \
	include/netlink/route/cls/basic.h \
	include/netlink/route/cls/cgroup.h \
	include/netlink/route/cls/ematch.h \
	include/netlink/route/cls/fw.h \
	include/netlink/route/cls/police.h \
	include/netlink/route/cls/u32.h
libnlinclude_netlink_route_cls_ematchdir = $(libnlincludedir)/netlink/route/cls/ematch
libnlinclude_netlink_route_cls_ematch_HEADERS = \
	include/netlink/route/cls/ematch/cmp.h \
	include/netlink/route/cls/ematch/meta.h \
	include/netlink/route/cls/ematch/nbyte.h \
	include/netlink/route/cls/ematch/text.h
libnlinclude_netlink_route_linkdir = $(libnlincludedir)/netlink/route/link
libnlinclude_netlink_route_link_HEADERS = \
	include/netlink/route/link/api.h \
	include/netlink/route/link/bonding.h \
	include/netlink/route/link/bridge.h \
	include/netlink/route/link/can.h \
	include/netlink/route/link/inet.h \
	include/netlink/route/link/inet6.h \
	include/netlink/route/link/info-api.h \
	include/netlink/route/link/ip6tnl.h \
	include/netlink/route/link/ipgre.h \
	include/netlink/route/link/ipip.h \
	include/netlink/route/link/ipvlan.h \
	include/netlink/route/link/ipvti.h \
	include/netlink/route/link/macsec.h \
	include/netlink/route/link/macvlan.h \
	include/netlink/route/link/macvtap.h \
	include/netlink/route/link/ppp.h \
	include/netlink/route/link/sit.h \
	include/netlink/route/link/sriov.h \
	include/netlink/route/link/veth.h \
	include/netlink/route/link/vlan.h \
	include/netlink/route/link/vrf.h \
	include/netlink/route/link/vxlan.h
libnlinclude_netlink_route_qdiscdir = $(libnlincludedir)/netlink/route/qdisc
libnlinclude_netlink_route_qdisc_HEADERS = \
	include/netlink/route/qdisc/cbq.h \
	include/netlink/route/qdisc/dsmark.h \
	include/netlink/route/qdisc/fifo.h \
	include/netlink/route/qdisc/fq_codel.h \
	include/netlink/route/qdisc/hfsc.h \
	include/netlink/route/qdisc/htb.h \
	include/netlink/route/qdisc/netem.h \
	include/netlink/route/qdisc/plug.h \
	include/netlink/route/qdisc/prio.h \
	include/netlink/route/qdisc/red.h \
	include/netlink/route/qdisc/sfq.h \
	include/netlink/route/qdisc/tbf.h
libnlinclude_netlink_xfrmdir = $(libnlincludedir)/netlink/xfrm
libnlinclude_netlink_xfrm_HEADERS = \
	include/netlink/xfrm/ae.h \
	include/netlink/xfrm/lifetime.h \
	include/netlink/xfrm/sa.h \
	include/netlink/xfrm/selector.h \
	include/netlink/xfrm/sp.h \
	include/netlink/xfrm/template.h

if ENABLE_CLI
libnlinclude_netlink_clidir = $(libnlincludedir)/netlink/cli
libnlinclude_netlink_cli_HEADERS = \
	include/netlink/cli/addr.h \
	include/netlink/cli/class.h \
	include/netlink/cli/cls.h \
	include/netlink/cli/ct.h \
	include/netlink/cli/exp.h \
	include/netlink/cli/link.h \
	include/netlink/cli/neigh.h \
	include/netlink/cli/qdisc.h \
	include/netlink/cli/route.h \
	include/netlink/cli/rule.h \
	include/netlink/cli/tc.h \
	include/netlink/cli/utils.h
endif

noinst_HEADERS = \
	include/linux-private/linux/can/netlink.h \
	include/linux-private/linux/fib_rules.h \
	include/linux-private/linux/gen_stats.h \
	include/linux-private/linux/genetlink.h \
	include/linux-private/linux/if.h \
	include/linux-private/linux/if_addr.h \
	include/linux-private/linux/if_arp.h \
	include/linux-private/linux/if_bridge.h \
	include/linux-private/linux/if_ether.h \
	include/linux-private/linux/if_link.h \
	include/linux-private/linux/if_macsec.h \
	include/linux-private/linux/if_tunnel.h \
	include/linux-private/linux/if_vlan.h \
	include/linux-private/linux/in.h \
	include/linux-private/linux/in6.h \
	include/linux-private/linux/inet_diag.h \
	include/linux-private/linux/ip.h \
	include/linux-private/linux/ip_mp_alg.h \
	include/linux-private/linux/ipv6.h \
	include/linux-private/linux/libc-compat.h \
	include/linux-private/linux/neighbour.h \
	include/linux-private/linux/netfilter.h \
	include/linux-private/linux/netfilter/nf_conntrack_common.h \
	include/linux-private/linux/netfilter/nfnetlink.h \
	include/linux-private/linux/netfilter/nfnetlink_compat.h \
	include/linux-private/linux/netfilter/nfnetlink_conntrack.h \
	include/linux-private/linux/netfilter/nfnetlink_log.h \
	include/linux-private/linux/netfilter/nfnetlink_queue.h \
	include/linux-private/linux/netlink.h \
	include/linux-private/linux/pkt_cls.h \
	include/linux-private/linux/pkt_sched.h \
	include/linux-private/linux/rtnetlink.h \
	include/linux-private/linux/snmp.h \
	include/linux-private/linux/sock_diag.h \
	include/linux-private/linux/socket.h \
	include/linux-private/linux/tc_act/tc_gact.h \
	include/linux-private/linux/tc_act/tc_mirred.h \
	include/linux-private/linux/tc_act/tc_skbedit.h \
	include/linux-private/linux/tc_ematch/tc_em_meta.h \
	include/linux-private/linux/veth.h \
	include/linux-private/linux/xfrm.h \
	include/netlink-private/cache-api.h \
	include/netlink-private/genl.h \
	include/netlink-private/netlink.h \
	include/netlink-private/object-api.h \
	include/netlink-private/route/link/api.h \
	include/netlink-private/route/link/sriov.h \
	include/netlink-private/route/tc-api.h \
	include/netlink-private/socket.h \
	include/netlink-private/tc.h \
	include/netlink-private/types.h \
	include/netlink-private/utils.h

###############################################################################

if ENABLE_CLI
pkgconfig_DATA += libnl-cli-3.0.pc
endif

pkgsysconfdir = $(sysconfdir)/libnl
pkgsysconf_DATA = \
	etc/pktloc \
	etc/classid

EXTRA_DIST = \
	$(pkgsysconf_DATA) \
	libnl-3.sym \
	libnl-cli-3.sym \
	libnl-genl-3.sym \
	libnl-idiag-3.sym \
	libnl-nf-3.sym \
	libnl-route-3.sym \
	libnl-xfrm-3.sym
