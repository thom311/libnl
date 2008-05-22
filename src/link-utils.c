/*
 * src/link-utils.c     Link Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "link-utils.h"

struct rtnl_link *nlt_alloc_link(void)
{
	struct rtnl_link *link;

	link = rtnl_link_alloc();
	if (!link)
		fatal(ENOMEM, "Unable to allocate link object");

	return link;
}

void parse_family(struct rtnl_link *link, char *arg)
{
	int family;

	if ((family = nl_str2af(arg)) == AF_UNSPEC)
		fatal(EINVAL, "Unable to translate address family \"%s\"", arg);

	rtnl_link_set_family(link, family);
}

void parse_name(struct rtnl_link *link, char *arg)
{
	rtnl_link_set_name(link, arg);
}

void parse_mtu(struct rtnl_link *link, char *arg)
{
	uint32_t mtu = parse_u32(arg);
	rtnl_link_set_mtu(link, mtu);
}

void parse_ifindex(struct rtnl_link *link, char *arg)
{
	uint32_t index = parse_u32(arg);
	rtnl_link_set_ifindex(link, index);
}

void parse_txqlen(struct rtnl_link *link, char *arg)
{
	uint32_t qlen = parse_u32(arg);
	rtnl_link_set_txqlen(link, qlen);
}

void parse_weight(struct rtnl_link *link, char *arg)
{
	uint32_t weight = parse_u32(arg);
	rtnl_link_set_weight(link, weight);
}
