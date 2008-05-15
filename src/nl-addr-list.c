/*
 * src/nl-addr-list.c     List addresses
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation version 2 of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "addr-utils.h"

static void print_usage(void)
{
	printf(
	"Usage: nl-addr-list [OPTION]... [ADDRESS]\n"
	"\n"
	"Options\n"
	" -f, --format=TYPE     Output format { brief | details | stats }\n"
	" -h, --help            Show this help\n"
	" -v, --version         Show versioning information\n"
	"\n"
	"Address Options\n"
	" -a, --local=ADDR	local address, e.g. 10.0.0.1\n"
	" -d, --dev=DEV		device the address is on\n"
	"     --family=FAMILY   address family\n"
	"     --label=STRING    address label\n"
	"     --peer=ADDR       peer address\n"
	"     --scope=SCOPE	address scope\n"
	"     --broadcast=ADDR  broadcast address\n"
	);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_handle *sock;
	struct rtnl_addr *addr;
	struct nl_cache *link_cache, *addr_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_ONELINE,
		.dp_fd = stdout,
	};

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);
	addr_cache = nlt_alloc_addr_cache(sock);
	addr = nlt_alloc_addr();

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_FAMILY = 257,
			ARG_LABEL = 258,
			ARG_PEER,
			ARG_SCOPE,
			ARG_BROADCAST,
		};
		static struct option long_opts[] = {
			{ "format", 1, 0, 'f' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "local", 1, 0, 'a' },
			{ "dev", 1, 0, 'd' },
			{ "family", 1, 0, ARG_FAMILY },
			{ "label", 1, 0, ARG_LABEL },
			{ "peer", 1, 0, ARG_PEER },
			{ "scope", 1, 0, ARG_SCOPE },
			{ "broadcast", 1, 0, ARG_BROADCAST },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "f:hva:d:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'f': params.dp_type = nlt_parse_dumptype(optarg); break;
		case 'h': print_usage(); break;
		case 'v': nlt_print_version(); break;
		case 'a': parse_local(addr, optarg); break;
		case 'd': parse_dev(addr, link_cache, optarg); break;
		case ARG_FAMILY: parse_family(addr, optarg); break;
		case ARG_LABEL: parse_label(addr, optarg); break;
		case ARG_PEER: parse_peer(addr, optarg); break;
		case ARG_SCOPE: parse_scope(addr, optarg); break;
		case ARG_BROADCAST: parse_broadcast(addr, optarg); break;
		}
	}

	nl_cache_dump_filter(addr_cache, &params, OBJ_CAST(addr));

	return 0;
}
