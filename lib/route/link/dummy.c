/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2011 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup link
 * @defgroup dummy Dummy
 *
 * @details
 * \b Link Type Name: "dummy"
 *
 * @{
 */

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink-private/route/link/api.h>

static struct rtnl_link_info_ops dummy_info_ops = {
	.io_name		= "dummy",
};

static void __init dummy_init(void)
{
	rtnl_link_register_info(&dummy_info_ops);
}

static void __exit dummy_exit(void)
{
	rtnl_link_unregister_info(&dummy_info_ops);
}

/** @} */
