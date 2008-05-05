/*
 * lib/route/route.c	Routes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup rtnl
 * @defgroup route Routing
 * @brief
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink/data.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include <netlink/route/link.h>

static struct nl_cache_ops rtnl_route_ops;

static int route_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			    struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	struct rtnl_route *route;
	int err;

	if (!(route = rtnl_route_parse(nlh)))
		return -EINVAL;

	if ((err = pp->pp_cb((struct nl_object *) route, pp)) < 0)
		goto errout;

	err = P_ACCEPT;

errout:
	rtnl_route_put(route);
	return err;
}

static int route_request_update(struct nl_cache *c, struct nl_handle *h)
{
	struct rtmsg rhdr = {
		.rtm_family = c->c_iarg1,
	};

	if (c->c_iarg2 & ROUTE_CACHE_CONTENT)
		rhdr.rtm_flags |= RTM_F_CLONED;

	return nl_send_simple(h, RTM_GETROUTE, NLM_F_DUMP, &rhdr, sizeof(rhdr));
}

/**
 * @name Cache Management
 * @{
 */

/**
 * Build a route cache holding all routes currently configured in the kernel
 * @arg handle		netlink handle
 * @arg family		Address family of routes to cover or AF_UNSPEC
 * @arg flags		Flags
 *
 * Allocates a new cache, initializes it properly and updates it to
 * contain all routes currently configured in the kernel.
 *
 * @note The caller is responsible for destroying and freeing the
 *       cache after using it.
 * @return The cache or NULL if an error has occured.
 */
struct nl_cache *rtnl_route_alloc_cache(struct nl_handle *handle,
					int family, int flags)
{
	struct nl_cache *cache;

	cache = nl_cache_alloc(&rtnl_route_ops);
	if (!cache)
		return NULL;

	cache->c_iarg1 = family;
	cache->c_iarg2 = flags;

	if (handle && nl_cache_refill(handle, cache) < 0) {
		free(cache);
		return NULL;
	}

	return cache;
}

/** @} */

/**
 * @name Route Addition
 * @{
 */

static struct nl_msg *build_route_msg(struct rtnl_route *tmpl, int cmd,
				      int flags)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (msg == NULL)
		return NULL;

	if (rtnl_route_build_msg(msg, tmpl) < 0) {
		nlmsg_free(msg);
		return NULL;
	}

	return msg;
}

struct nl_msg *rtnl_route_build_add_request(struct rtnl_route *tmpl, int flags)
{
	return build_route_msg(tmpl, RTM_NEWROUTE, NLM_F_CREATE | flags);
}

int rtnl_route_add(struct nl_handle *handle, struct rtnl_route *route,
		   int flags)
{
	struct nl_msg *msg;
	int err;

	msg = rtnl_route_build_add_request(route, flags);
	if (!msg)
		return nl_get_errno();

	err = nl_send_auto_complete(handle, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(handle);
}

struct nl_msg *rtnl_route_build_del_request(struct rtnl_route *tmpl, int flags)
{
	return build_route_msg(tmpl, RTM_DELROUTE, flags);
}

int rtnl_route_delete(struct nl_handle *handle, struct rtnl_route *route,
		      int flags)
{
	struct nl_msg *msg;
	int err;

	msg = rtnl_route_build_del_request(route, flags);
	if (!msg)
		return nl_get_errno();

	err = nl_send_auto_complete(handle, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(handle);
}

/** @} */

static struct nl_af_group route_groups[] = {
	{ AF_INET,	RTNLGRP_IPV4_ROUTE },
	{ AF_INET6,	RTNLGRP_IPV6_ROUTE },
	{ AF_DECnet,	RTNLGRP_DECnet_ROUTE },
	{ END_OF_GROUP_LIST },
};

static struct nl_cache_ops rtnl_route_ops = {
	.co_name		= "route/route",
	.co_hdrsize		= sizeof(struct rtmsg),
	.co_msgtypes		= {
					{ RTM_NEWROUTE, NL_ACT_NEW, "new" },
					{ RTM_DELROUTE, NL_ACT_DEL, "del" },
					{ RTM_GETROUTE, NL_ACT_GET, "get" },
					END_OF_MSGTYPES_LIST,
				  },
	.co_protocol		= NETLINK_ROUTE,
	.co_groups		= route_groups,
	.co_request_update	= route_request_update,
	.co_msg_parser		= route_msg_parser,
	.co_obj_ops		= &route_obj_ops,
};

static void __init route_init(void)
{
	nl_cache_mngt_register(&rtnl_route_ops);
}

static void __exit route_exit(void)
{
	nl_cache_mngt_unregister(&rtnl_route_ops);
}

/** @} */
