/*
 * src/ct-utils.c		Conntrack Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "log-utils.h"

struct nfnl_log *nlt_alloc_log(void)
{
	struct nfnl_log *log;

	log = nfnl_log_alloc();
	if (!log)
		fatal(ENOMEM, "Unable to allocate log object");

	return log;
}
