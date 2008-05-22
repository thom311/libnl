/*
 * src/neigh-utils.c     Neighbour Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "neigh-utils.h"

struct rtnl_neigh *nlt_alloc_neigh(void)
{
	struct rtnl_neigh *neigh;

	neigh = rtnl_neigh_alloc();
	if (!neigh)
		fatal(ENOMEM, "Unable to allocate neighbout object");

	return neigh;
}

void parse_dst(struct rtnl_neigh *neigh, char *arg)
{
	struct nl_addr *a;
	int err;

	a = nlt_addr_parse(arg, rtnl_neigh_get_family(neigh));
	if ((err = rtnl_neigh_set_dst(neigh, a)) < 0)
		fatal(err, "Unable to set local address: %s",
			nl_geterror(err));

	nl_addr_put(a);
}

void parse_lladdr(struct rtnl_neigh *neigh, char *arg)
{
	struct nl_addr *a;

	a = nlt_addr_parse(arg, AF_UNSPEC);
	rtnl_neigh_set_lladdr(neigh, a);
	nl_addr_put(a);
}

void parse_dev(struct rtnl_neigh *neigh, struct nl_cache *link_cache, char *arg)
{
	int ival;

	if (!(ival = rtnl_link_name2i(link_cache, arg)))
		fatal(ENOENT, "Link \"%s\" does not exist", arg);

	rtnl_neigh_set_ifindex(neigh, ival);
}

void parse_family(struct rtnl_neigh *neigh, char *arg)
{
	int family;

	if ((family = nl_str2af(arg)) == AF_UNSPEC)
		fatal(EINVAL, "Unable to translate address family \"%s\"", arg);

	rtnl_neigh_set_family(neigh, family);
}

void parse_state(struct rtnl_neigh *neigh, char *arg)
{
	int state;
	
	if ((state = rtnl_neigh_str2state(arg)) < 0)
		fatal(state, "Unable to translate state \"%s\": %s",
			arg, state);

	rtnl_neigh_set_state(neigh, state);
}
