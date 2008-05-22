/*
 * src/log-utils.h		Log Helper
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __LOG_UTILS_H_
#define __LOG_UTILS_H_

#include "utils.h"
#include <linux/netfilter/nfnetlink_log.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>

extern struct nfnl_log *nlt_alloc_log(void);

#endif
