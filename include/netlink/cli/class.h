/*
 * netlink/cli/class.h     CLI Class Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __NETLINK_CLI_CLASS_H_
#define __NETLINK_CLI_CLASS_H_

#include <netlink/route/class.h>
#include <netlink/route/class-modules.h>

#define nl_cli_class_alloc_cache(sk) \
		nl_cli_alloc_cache((sk), "traffic classes", \
				   rtnl_class_alloc_cache)

extern struct rtnl_class *nl_cli_class_alloc(void);

extern void nl_cli_class_parse_dev(struct rtnl_class *, struct nl_cache *, char *);
extern void nl_cli_class_parse_parent(struct rtnl_class *, char *);
extern void nl_cli_class_parse_handle(struct rtnl_class *, char *);
extern void nl_cli_class_parse_kind(struct rtnl_class *, char *);

#endif
