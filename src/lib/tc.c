/*
 * src/lib/tc.c     CLI Traffic Control Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

#include <netlink/cli/utils.h>
#include <netlink/cli/tc.h>
#include <netlink/route/tc.h>

/**
 * @ingroup cli
 * @defgroup cli_tc Queueing Disciplines
 * @{
 */
void nl_cli_tc_parse_dev(struct rtnl_tc *tc, struct nl_cache *link_cache, char *name)
{
	struct rtnl_link *link;
	
	link = rtnl_link_get_by_name(link_cache, name);
	if (!link)
		nl_cli_fatal(ENOENT, "Link \"%s\" does not exist.", name);

	rtnl_tc_set_link(tc, link);
	rtnl_link_put(link);
}

void nl_cli_tc_parse_parent(struct rtnl_tc *tc, char *arg)
{
	uint32_t parent;
	int err;

	if ((err = rtnl_tc_str2handle(arg, &parent)) < 0)
		nl_cli_fatal(err, "Unable to parse handle \"%s\": %s",
		      arg, nl_geterror(err));

	rtnl_tc_set_parent(tc, parent);
}

void nl_cli_tc_parse_handle(struct rtnl_tc *tc, char *arg, int create)
{
	uint32_t handle, parent;
	int err;

	parent = rtnl_tc_get_parent(tc);

	if ((err = rtnl_tc_str2handle(arg, &handle)) < 0) {
		if (err == -NLE_OBJ_NOTFOUND && create)
			err = rtnl_classid_generate(arg, &handle, parent);

		if (err < 0)
			nl_cli_fatal(err, "Unable to parse handle \"%s\": %s",
				     arg, nl_geterror(err));
	}

	rtnl_tc_set_handle(tc, handle);
}

void nl_cli_tc_parse_mtu(struct rtnl_tc *tc, char *arg)
{
	rtnl_tc_set_mtu(tc, nl_cli_parse_u32(arg));
}

void nl_cli_tc_parse_mpu(struct rtnl_tc *tc, char *arg)
{
	rtnl_tc_set_mpu(tc, nl_cli_parse_u32(arg));
}

void nl_cli_tc_parse_overhead(struct rtnl_tc *tc, char *arg)
{
	rtnl_tc_set_overhead(tc, nl_cli_parse_u32(arg));
}

void nl_cli_tc_parse_linktype(struct rtnl_tc *tc, char *arg)
{
	int type;

	if ((type = nl_str2llproto(arg)) < 0)
		nl_cli_fatal(type, "Unable to parse linktype \"%s\": %s",
			arg, nl_geterror(type));

	rtnl_tc_set_linktype(tc, type);
}

/** @} */
