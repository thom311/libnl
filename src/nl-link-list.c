/*
 * src/nl-link-dump.c	Dump link attributes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#if 0
static void print_usage(void)
{
	printf(
	"Usage: nl-link-dump <mode> [<filter>]\n"
	"  mode := { brief | detailed | stats | xml }\n"
	"  filter := [dev DEV] [mtu MTU] [txqlen TXQLEN] [weight WEIGHT] [link LINK]\n"
	"            [master MASTER] [qdisc QDISC] [addr ADDR] [broadcast BRD]\n"
	"            [{ up | down }] [{ arp | noarp }] [{ promisc | nopromisc }]\n"
	"            [{ dynamic | nodynamic }] [{ multicast | nomulticast }]\n"
	"            [{ trailers | notrailers }] [{ allmulticast | noallmulticast }]\n");
	exit(1);
}
#endif

#include "link-utils.h"

static void print_usage(void)
{
	printf(
	"Usage: nl-link-list [OPTION]... [Link]\n"
	"\n"
	"Options\n"
	" -f, --format=TYPE     Output format { brief | details | stats }\n"
	" -h, --help            Show this help\n"
	" -v, --version         Show versioning information\n"
	"\n"
	"Link Options\n"
	" -n, --name=NAME	link name\n"
	" -i, --index           interface index\n"
	"     --mtu=NUM         MTU value\n"
	"     --txqlen=NUM      TX queue length\n"
	"     --weight=NUM      weight\n"
	);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	struct rtnl_link *link;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_ONELINE,
		.dp_fd = stdout,
	};

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);
	link = nlt_alloc_link();

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_FAMILY = 257,
			ARG_MTU = 258,
			ARG_TXQLEN,
			ARG_WEIGHT,
		};
		static struct option long_opts[] = {
			{ "format", 1, 0, 'f' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "name", 1, 0, 'n' },
			{ "index", 1, 0, 'i' },
			{ "family", 1, 0, ARG_FAMILY },
			{ "mtu", 1, 0, ARG_MTU },
			{ "txqlen", 1, 0, ARG_TXQLEN },
			{ "weight", 1, 0, ARG_WEIGHT },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "f:hvn:i:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'f': params.dp_type = nlt_parse_dumptype(optarg); break;
		case 'h': print_usage(); break;
		case 'v': nlt_print_version(); break;
		case 'n': parse_name(link, optarg); break;
		case 'i': parse_ifindex(link, optarg); break;
		case ARG_FAMILY: parse_family(link, optarg); break;
		case ARG_MTU: parse_mtu(link, optarg); break;
		case ARG_TXQLEN: parse_txqlen(link, optarg); break;
		case ARG_WEIGHT: parse_weight(link, optarg); break;
		}
	}

	nl_cache_dump_filter(link_cache, &params, OBJ_CAST(link));

	return 0;
}
