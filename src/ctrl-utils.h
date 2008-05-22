/*
 * src/ctrl-utils.h		Generic Netlink Ctrl Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#ifndef __SRC_CTRL_UTILS_H_
#define __SRC_CTRL_UTILS_H_

#include "utils.h"

extern struct nl_cache *nlt_alloc_genl_family_cache(struct nl_sock *);

#endif
