/*
 * netlink/cli/tc.h     CLI Traffic Control Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __NETLINK_CLI_TC_H_
#define __NETLINK_CLI_TC_H_

#include <netlink/route/tc.h>

extern void nl_cli_tc_parse_dev(struct rtnl_tc *, struct nl_cache *, char *);
extern void nl_cli_tc_parse_parent(struct rtnl_tc *, char *);
extern void nl_cli_tc_parse_handle(struct rtnl_tc *, char *, int);
extern void nl_cli_tc_parse_mtu(struct rtnl_tc *, char *);
extern void nl_cli_tc_parse_mpu(struct rtnl_tc *, char *);
extern void nl_cli_tc_parse_overhead(struct rtnl_tc *, char *);
extern void nl_cli_tc_parse_linktype(struct rtnl_tc *, char *);

#endif
