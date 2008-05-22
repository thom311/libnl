/*
 * src/rtnl-utils.c	rtnetlink helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "rtnl-utils.h"

struct nl_cache *nlt_alloc_link_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "link", rtnl_link_alloc_cache);
}

struct nl_cache *nlt_alloc_addr_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "address", rtnl_addr_alloc_cache);
}

struct nl_cache *nlt_alloc_neigh_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "neighbour", rtnl_neigh_alloc_cache);
}

struct nl_cache *nlt_alloc_neightbl_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "neighbour table", rtnl_neightbl_alloc_cache);
}

struct nl_cache *nlt_alloc_route_cache(struct nl_sock *sk, int flags)
{
	struct nl_cache *cache;
	int err;

	if ((err = rtnl_route_alloc_cache(sk, AF_UNSPEC, flags, &cache)) < 0)
		fatal(err, "Unable to allocate route cache: %s\n",
		      nl_geterror(err));

	nl_cache_mngt_provide(cache);

	return cache;
}

struct nl_cache *nlt_alloc_rule_cache(struct nl_sock *sk)
{
	struct nl_cache *cache;
	int err;

	if ((err = rtnl_rule_alloc_cache(sk, AF_UNSPEC, &cache)) < 0)
		fatal(err, "Unable to allocate routing rule cache: %s\n",
		      nl_geterror(err));

	nl_cache_mngt_provide(cache);

	return cache;
}

struct nl_cache *nlt_alloc_qdisc_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "queueing disciplines", rtnl_qdisc_alloc_cache);
}

