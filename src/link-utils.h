/*
 * src/link-utils.h     Link Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __LINK_UTILS_H_
#define __LINK_UTILS_H_

#include "utils.h"

extern struct rtnl_link *nlt_alloc_link(void);
extern void parse_family(struct rtnl_link *, char *);
extern void parse_name(struct rtnl_link *, char *);
extern void parse_mtu(struct rtnl_link *, char *);
extern void parse_ifindex(struct rtnl_link *, char *);
extern void parse_txqlen(struct rtnl_link *, char *);
extern void parse_weight(struct rtnl_link *, char *);

#endif
