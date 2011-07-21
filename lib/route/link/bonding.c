/*
 * lib/route/link/bonding.c	Bonding Link Module
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2011 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup link
 * @defgroup bonding Bonding
 *
 * <a href="../route.html#_links_network_devices">Link Documentation</a>
 *
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/route/link/api.h>

static struct rtnl_link_info_ops bonding_info_ops = {
	.io_name		= "bond",
};

static void __init bonding_init(void)
{
	rtnl_link_register_info(&bonding_info_ops);
}

static void __exit bonding_exit(void)
{
	rtnl_link_unregister_info(&bonding_info_ops);
}

/** @} */
