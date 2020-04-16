/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_RED_H_
#define NETLINK_RED_H_

#include <netlink/netlink.h>

extern  void rtnl_red_set_limit(struct rtnl_qdisc *qdisc, int limit);
extern int rtnl_red_get_limit(struct rtnl_qdisc *qdisc);

#endif
