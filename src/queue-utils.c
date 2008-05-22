/*
 * src/queue-utils.c		Queue Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "queue-utils.h"

struct nfnl_queue *nlt_alloc_queue(void)
{
	struct nfnl_queue *queue;

	queue = nfnl_queue_alloc();
	if (!queue)
		fatal(ENOMEM, "Unable to allocate queue object");

	return queue;
}

