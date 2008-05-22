/*
 * src/ctrl-utils.c		Generic Ctrl Netlink Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "ctrl-utils.h"

struct nl_cache *nlt_alloc_genl_family_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "generic netlink family",
			   genl_ctrl_alloc_cache);
}
