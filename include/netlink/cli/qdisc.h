/*
 * netlink/cli/qdisc.h     CLI QDisc Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008-2010 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __NETLINK_CLI_QDISC_H_
#define __NETLINK_CLI_QDISC_H_

#include <netlink/route/qdisc.h>
#include <netlink/route/qdisc-modules.h>

#define nl_cli_qdisc_alloc_cache(sk) \
		nl_cli_alloc_cache((sk), "queueing disciplines", \
				   rtnl_qdisc_alloc_cache)

struct nl_cli_qdisc_module
{
	const char *		qm_name;
	struct rtnl_qdisc_ops *	qm_ops;
	struct rtnl_class_ops *	qm_class_ops;
	void		      (*qm_parse_qdisc_argv)(struct rtnl_qdisc *, int, char **);
	void		      (*qm_parse_class_argv)(struct rtnl_class *, int, char **);
	struct nl_list_head	qm_list;
};

extern struct nl_cli_qdisc_module *nl_cli_qdisc_lookup(struct rtnl_qdisc_ops *);
extern struct nl_cli_qdisc_module *nl_cli_qdisc_lookup_by_class(struct rtnl_class_ops *);
extern void nl_cli_qdisc_register(struct nl_cli_qdisc_module *);
extern void nl_cli_qdisc_unregister(struct nl_cli_qdisc_module *);

extern struct rtnl_qdisc *nl_cli_qdisc_alloc(void);

extern void nl_cli_qdisc_parse_kind(struct rtnl_qdisc *, char *);

#endif
