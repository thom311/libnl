/*
 * src/addr-utils.c     Address Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "addr-utils.h"

void parse_family(struct rtnl_addr *addr, char *arg)
{
	int family;

	if ((family = nl_str2af(arg)) != AF_UNSPEC)
		rtnl_addr_set_family(addr, family);
}

void parse_local(struct rtnl_addr *addr, char *arg)
{
	struct nl_addr *a;
	int err;

	a = nlt_addr_parse(arg, rtnl_addr_get_family(addr));
	if ((err = rtnl_addr_set_local(addr, a)) < 0)
		fatal(err, "Unable to set local address: %s",
			nl_geterror(err));

	nl_addr_put(a);
}

void parse_dev(struct rtnl_addr *addr, struct nl_cache *link_cache, char *arg)
{
	int ival;

	if (!(ival = rtnl_link_name2i(link_cache, arg)))
		fatal(ENOENT, "Link \"%s\" does not exist", arg);

	rtnl_addr_set_ifindex(addr, ival);
}

void parse_label(struct rtnl_addr *addr, char *arg)
{
	int err;

	if ((err = rtnl_addr_set_label(addr, arg)) < 0)
		fatal(err, "Unable to set address label: %s", nl_geterror(err));
}

void parse_peer(struct rtnl_addr *addr, char *arg)
{
	struct nl_addr *a;
	int err;

	a = nlt_addr_parse(arg, rtnl_addr_get_family(addr));
	if ((err = rtnl_addr_set_peer(addr, a)) < 0)
		fatal(err, "Unable to set peer address: %s", nl_geterror(err));

	nl_addr_put(a);
}

void parse_scope(struct rtnl_addr *addr, char *arg)
{
	int ival;

	if ((ival = rtnl_str2scope(arg)) < 0)
		fatal(EINVAL, "Unknown address scope \"%s\"", arg);

	rtnl_addr_set_scope(addr, ival);
}

void parse_broadcast(struct rtnl_addr *addr, char *arg)
{
	struct nl_addr *a;
	int err;

	a = nlt_addr_parse(arg, rtnl_addr_get_family(addr));
	if ((err = rtnl_addr_set_broadcast(addr, a)) < 0)
		fatal(err, "Unable to set broadcast address: %s",
			nl_geterror(err));

	nl_addr_put(a);
}

