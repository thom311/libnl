/*
 * lib/route/nexthop.c	Routing Nexthop
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup route_obj
 * @defgroup nexthop Nexthop
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>

/**
 * @name Allocation/Freeing
 * @{
 */

struct rtnl_nexthop *rtnl_route_nh_alloc(void)
{
	struct rtnl_nexthop *nh;

	nh = calloc(1, sizeof(*nh));
	if (!nh) {
		nl_errno(ENOMEM);
		return NULL;
	}

	nl_init_list_head(&nh->rtnh_list);

	return nh;
}

struct rtnl_nexthop *rtnl_route_nh_clone(struct rtnl_nexthop *src)
{
	struct rtnl_nexthop *nh;

	nh = rtnl_route_nh_alloc();
	if (!nh)
		return NULL;

	nh->rtnh_flags = src->rtnh_flags;
	nh->rtnh_flag_mask = src->rtnh_flag_mask;
	nh->rtnh_weight = src->rtnh_weight;
	nh->rtnh_ifindex = src->rtnh_ifindex;
	nh->rtnh_mask = src->rtnh_mask;

	if (src->rtnh_gateway) {
		nh->rtnh_gateway = nl_addr_clone(src->rtnh_gateway);
		if (!nh->rtnh_gateway) {
			free(nh);
			return NULL;
		}
	}

	return nh;
}

void rtnl_route_nh_free(struct rtnl_nexthop *nh)
{
	nl_addr_put(nh->rtnh_gateway);
	free(nh);
}

/** @} */

/**
 * @name Attributes
 */

void rtnl_route_nh_set_weight(struct rtnl_nexthop *nh, int weight)
{
	nh->rtnh_weight = weight;
	nh->rtnh_mask |= NEXTHOP_HAS_WEIGHT;
}

int rtnl_route_nh_get_weight(struct rtnl_nexthop *nh)
{
	if (nh->rtnh_mask & NEXTHOP_HAS_WEIGHT)
		return nh->rtnh_weight;
	else
		return 0;
}

void rtnl_route_nh_set_ifindex(struct rtnl_nexthop *nh, int ifindex)
{
	nh->rtnh_ifindex = ifindex;
	nh->rtnh_mask |= NEXTHOP_HAS_IFINDEX;
}

int rtnl_route_nh_get_ifindex(struct rtnl_nexthop *nh)
{
	if (nh->rtnh_mask & NEXTHOP_HAS_IFINDEX)
		return nh->rtnh_ifindex;
	else
		return -1;
}	

void rtnl_route_nh_set_gateway(struct rtnl_nexthop *nh, struct nl_addr *addr)
{
	struct nl_addr *old = nh->rtnh_gateway;

	nh->rtnh_gateway = nl_addr_get(addr);
	if (old)
		nl_addr_put(old);

	nh->rtnh_mask |= NEXTHOP_HAS_GATEWAY;
}

struct nl_addr *rtnl_route_nh_get_gateway(struct rtnl_nexthop *nh)
{
	if (nh->rtnh_mask & NEXTHOP_HAS_GATEWAY)
		return nh->rtnh_gateway;
	else
		return NULL;
}

void rtnl_route_nh_set_flags(struct rtnl_nexthop *nh, unsigned int flags)
{
	nh->rtnh_flag_mask |= flags;
	nh->rtnh_flags |= flags;
	nh->rtnh_mask |= NEXTHOP_HAS_FLAGS;
}

void rtnl_route_nh_unset_flags(struct rtnl_nexthop *nh, unsigned int flags)
{
	nh->rtnh_flag_mask |= flags;
	nh->rtnh_flags &= ~flags;
	nh->rtnh_mask |= NEXTHOP_HAS_FLAGS;
}

unsigned int rtnl_route_nh_get_flags(struct rtnl_nexthop *nh)
{
	if (nh->rtnh_mask & NEXTHOP_HAS_FLAGS)
		return nh->rtnh_flags;
	else
		return 0;
}

/** @} */
/** @} */
