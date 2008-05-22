/*
 * src/neigh-utils.h     Neighbour Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __NEIGH_UTILS_H_
#define __NEIGH_UTILS_H_

#include "utils.h"

extern struct rtnl_neigh *nlt_alloc_neigh(void);
extern void parse_dst(struct rtnl_neigh *, char *);
extern void parse_lladdr(struct rtnl_neigh *, char *);
extern void parse_dev(struct rtnl_neigh *, struct nl_cache *, char *);
extern void parse_family(struct rtnl_neigh *, char *);
extern void parse_state(struct rtnl_neigh *, char *);

#endif
