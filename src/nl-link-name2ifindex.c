/*
 * src/nl-link-name2ifindex.c     Transform a interface name to its index
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "utils.h"

static void print_usage(void)
{
	printf("Usage: nl-link-ifindex2name <ifindex>\n");
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	uint32_t ifindex;

	if (argc < 2)
		print_usage();

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);

	if (!(ifindex = rtnl_link_name2i(link_cache, argv[1])))
		fatal(ENOENT, "Interface \"%s\" does not exist", argv[1]);

	printf("%u\n", ifindex);

	return 0;
}
