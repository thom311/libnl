/*
 * src/route-utils.h     Route Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __ROUTE_UTILS_H_
#define __ROUTE_UTILS_H_

#include "utils.h"

extern void	parse_family(struct rtnl_route *, char *);
extern void	parse_dst(struct rtnl_route *, char *);
extern void	parse_src(struct rtnl_route *, char *);
extern void	parse_pref_src(struct rtnl_route *, char *);
extern void	parse_metric(struct rtnl_route *, char *);
extern void	parse_nexthop(struct rtnl_route *, char *, struct nl_cache *);
extern void	parse_table(struct rtnl_route *, char *);
extern void	parse_prio(struct rtnl_route *, char *);
extern void	parse_scope(struct rtnl_route *, char *);
extern void	parse_protocol(struct rtnl_route *, char *);
extern void	parse_type(struct rtnl_route *, char *);
extern void	parse_iif(struct rtnl_route *, char *, struct nl_cache *);

#endif
