/*
 * src/utils.h		Utilities
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __SRC_UTILS_H_
#define __SRC_UTILS_H_

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/addr.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/neighbour.h>
#include <netlink/route/neightbl.h>
#include <netlink/route/route.h>
#include <netlink/route/rule.h>
#include <netlink/route/qdisc.h>
#include <netlink/route/class.h>
#include <netlink/route/classifier.h>
#include <netlink/fib_lookup/lookup.h>
#include <netlink/fib_lookup/request.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/mngt.h>
#include <netlink/netfilter/ct.h>

extern uint32_t parse_u32(const char *);

extern void		nlt_print_version(void);
extern void		fatal(int err, const char *fmt, ...);
extern struct nl_addr *	nlt_addr_parse(const char *, int);

extern int		nlt_connect(struct nl_sock *, int);
extern struct nl_sock *	nlt_alloc_socket(void);

extern int nlt_parse_dumptype(const char *str);
extern int nlt_confirm(struct nl_object *, struct nl_dump_params *, int);

extern struct nl_cache *nlt_alloc_link_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_addr_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_neigh_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_neightbl_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_qdisc_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_route_cache(struct nl_sock *, int);
extern struct nl_cache *nlt_alloc_rule_cache(struct nl_sock *);
extern struct nl_cache *alloc_cache(struct nl_sock *, const char *,
			     int (*ac)(struct nl_sock *, struct nl_cache **));

#endif
