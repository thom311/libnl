/*
 * src/addr-utils.h     Address Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __ADDR_UTILS_H_
#define __ADDR_UTILS_H_

#include "utils.h"

extern void parse_family(struct rtnl_addr *, char *);
extern void parse_local(struct rtnl_addr *, char *);
extern void parse_dev(struct rtnl_addr *, struct nl_cache *, char *);
extern void parse_label(struct rtnl_addr *, char *);
extern void parse_peer(struct rtnl_addr *, char *);
extern void parse_scope(struct rtnl_addr *, char *);
extern void parse_broadcast(struct rtnl_addr *, char *);

#endif
