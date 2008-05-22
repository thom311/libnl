/*
 * src/genl-ctrl-list.c	List Generic Netlink Controller
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "ctrl-utils.h"

static void print_usage(void)
{
	printf(
	"Usage: genl-ctrl-list [OPTION]...\n"
	"\n"
	"Options\n"
	" -f, --format=TYPE     Output format { brief | details | stats }\n"
	" -h, --help            Show this help\n"
	" -v, --version         Show versioning information\n"
	);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *family_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_ONELINE,
		.dp_fd = stdout,
	};
 
	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_GENERIC);
	family_cache = nlt_alloc_genl_family_cache(sock);
 
	for (;;) {
		int c, optidx = 0;
		static struct option long_opts[] = {
			{ "format", 1, 0, 'f' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ 0, 0, 0, 0 }
		};
	
		c = getopt_long(argc, argv, "f:hv", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'f': params.dp_type = nlt_parse_dumptype(optarg); break;
		case 'h': print_usage(); break;
		case 'v': nlt_print_version(); break;
		}
 	}

	nl_cache_dump(family_cache, &params);

	return 0;
}
