/*
 * src/rtnl-utils.h	rtnetlink helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __SRC_RTNL_UTILS_H_
#define __SRC_RTNL_UTILS_H_

#include "utils.h"

extern struct nl_cache *nlt_alloc_link_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_addr_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_neigh_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_neightbl_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_qdisc_cache(struct nl_sock *);
extern struct nl_cache *nlt_alloc_route_cache(struct nl_sock *, int);
extern struct nl_cache *nlt_alloc_rule_cache(struct nl_sock *);

#endif
