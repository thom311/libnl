/*
 * lib/route/link/bridge_info.c	bridge info support
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2022 MaxLinear, Inc.
 */

/**
 * @ingroup link
 * @defgroup bridge Bridging
 *
 * @details
 * @{
 */

#include <netlink-private/netlink.h>
#include <netlink-private/route/link/api.h>

struct bridge_info
{
	uint32_t		ce_mask; /* to support attr macros */
};

static struct nla_policy bi_attrs_policy[IFLA_BR_MAX+1] = {

};

static inline struct bridge_info *bridge_info(struct rtnl_link *link)
{
	return link->l_info;
}

static int bridge_info_alloc(struct rtnl_link *link)
{
	struct bridge_info *bi;

	if (link->l_info)
		memset(link->l_info, 0, sizeof(*bi));
	else {
		bi = calloc(1, sizeof(*bi));
		if (!bi)
			return -NLE_NOMEM;

		link->l_info = bi;
	}

	return 0;
}

static int bridge_info_parse(struct rtnl_link *link, struct nlattr *data,
			     struct nlattr *xstats)
{
	struct nlattr *tb[IFLA_BR_MAX+1];
	struct bridge_info *bi;
	int err = 0;

	NL_DBG(3, "Parsing Bridge link info\n");

	if ((err = nla_parse_nested(tb, IFLA_BR_MAX, data, bi_attrs_policy)) < 0)
		goto errout;

	if ((err = bridge_info_alloc(link)) < 0)
		goto errout;

	bi = link->l_info;

errout:
	return err;
}

static int bridge_info_put_attrs(struct nl_msg *msg, struct rtnl_link *link)
{
	struct bridge_info *bi = link->l_info;
	struct nlattr *data;

	data = nla_nest_start(msg, IFLA_INFO_DATA);
	if (!data)
		return -NLE_MSGSIZE;

	nla_nest_end(msg, data);
	return 0;
}

static void bridge_info_free(struct rtnl_link *link)
{
	free(link->l_info);
	link->l_info = NULL;
}

static struct rtnl_link_info_ops bridge_info_ops = {
	.io_name		= "bridge",
	.io_alloc		= bridge_info_alloc,
	.io_parse		= bridge_info_parse,
	.io_put_attrs		= bridge_info_put_attrs,
	.io_free		= bridge_info_free,
};

#define IS_BRIDGE_INFO_ASSERT(link) \
	do { \
		if ((link)->l_info_ops != &bridge_info_ops) { \
			APPBUG("Link is not a bridge link. Set type \"bridge\" first."); \
		} \
	} while(0)

static void __init bridge_info_init(void)
{
	rtnl_link_register_info(&bridge_info_ops);
}

static void __exit bridge_info_exit(void)
{
	rtnl_link_unregister_info(&bridge_info_ops);
}

/** @} */
