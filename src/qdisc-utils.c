/*
 * src/qdisc-utils.c     QDisc Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "qdisc-utils.h"

struct rtnl_qdisc *nlt_alloc_qdisc(void)
{
	struct rtnl_qdisc *qdisc;

	qdisc = rtnl_qdisc_alloc();
	if (!qdisc)
		fatal(ENOMEM, "Unable to allocate qdisc object");

	return qdisc;
}

void parse_dev(struct rtnl_qdisc *qdisc, struct nl_cache *link_cache, char *arg)
{
	int ival;

	if (!(ival = rtnl_link_name2i(link_cache, arg)))
		fatal(ENOENT, "Link \"%s\" does not exist", arg);

	rtnl_qdisc_set_ifindex(qdisc, ival);
}

void parse_parent(struct rtnl_qdisc *qdisc, char *arg)
{
	uint32_t parent;
	int err;

	if ((err = rtnl_tc_str2handle(arg, &parent)) < 0)
		fatal(err, "Unable to parse handle \"%s\": %s",
		      arg, nl_geterror(err));

	rtnl_qdisc_set_parent(qdisc, parent);
}

void parse_handle(struct rtnl_qdisc *qdisc, char *arg)
{
	uint32_t handle;
	int err;

	if ((err = rtnl_tc_str2handle(arg, &handle)) < 0)
		fatal(err, "Unable to parse handle \"%s\": %s",
		      arg, nl_geterror(err));

	rtnl_qdisc_set_handle(qdisc, handle);
}

void parse_kind(struct rtnl_qdisc *qdisc, char *arg)
{
	rtnl_qdisc_set_kind(qdisc, arg);
}
