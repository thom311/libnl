/*
 * src/queue-utils.h		Queue Helper
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __QUEUE_UTILS_H_
#define __QUEUE_UTILS_H_

#include "utils.h"
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/queue.h>
#include <netlink/netfilter/queue_msg.h>

extern struct nfnl_queue *nlt_alloc_queue(void);

#endif
