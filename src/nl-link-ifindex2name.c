/*
 * src/nl-link-ifindex2name.c     Transform a interface index to its name
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
	char name[IFNAMSIZ];
	uint32_t ifindex;

	if (argc < 2)
		print_usage();

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);

	ifindex = parse_u32(argv[1]);

	if (!rtnl_link_i2name(link_cache, ifindex, name, sizeof(name)))
		fatal(ENOENT, "Interface index %d does not exist", ifindex);

	printf("%s\n", name);

	return 0;
}
