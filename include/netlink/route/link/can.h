/*
 * netlink/route/link/can.h		CAN interface
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2012 Benedikt Spranger <b.spranger@linutronix.de>
 */

#ifndef NETLINK_LINK_CAN_H_
#define NETLINK_LINK_CAN_H_

#include <netlink/netlink.h>
#include <netlink/route/link.h>
#include <linux/can/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

extern int rtnl_link_is_can(struct rtnl_link *link);

extern char *rtnl_link_can_ctrlmode2str(int, char *, size_t);
extern int rtnl_link_can_str2ctrlmode(const char *);

#ifdef __cplusplus
}
#endif

#endif
