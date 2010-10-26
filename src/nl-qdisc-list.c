/*
 * src/nl-qdisc-list.c     List Queueing Disciplines
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2010 Thomas Graf <tgraf@suug.ch>
 */

#include <netlink/cli/utils.h>
#include <netlink/cli/tc.h>
#include <netlink/cli/qdisc.h>
#include <netlink/cli/link.h>

static void print_usage(void)
{
	printf(
	"Usage: nl-qdisc-list [OPTION]... [QDISC]\n"
	"\n"
	"OPTIONS\n"
	"     --details         Show details\n"
	"     --stats           Show statistics\n"
	" -h, --help            Show this help\n"
	" -v, --version         Show versioning information\n"
	"\n"
	" -d, --dev=DEV         Device the qdisc is attached to. (default: all)\n"
	" -p, --parent=ID       Identifier of parent qdisc.\n"
	" -i, --id=ID           Identifier.\n"
	" -k, --kind=NAME       Kind of qdisc (e.g. pfifo_fast)\n"
	"\n"
	"EXAMPLE\n"
	"    # Display statistics of all qdiscs attached to eth0\n"
	"    $ nl-qdisc-list --details --dev=eth0\n"
	"\n"
	);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct rtnl_qdisc *qdisc;
	struct rtnl_tc *tc;
	struct nl_cache *link_cache, *qdisc_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
 
	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_ROUTE);
	link_cache = nl_cli_link_alloc_cache(sock);
	qdisc_cache = nl_cli_qdisc_alloc_cache(sock);
 	qdisc = nl_cli_qdisc_alloc();
	tc = (struct rtnl_tc *) qdisc;
 
	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_DETAILS = 257,
			ARG_STATS = 258,
		};
		static struct option long_opts[] = {
			{ "details", 0, 0, ARG_DETAILS },
			{ "stats", 0, 0, ARG_STATS },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "dev", 1, 0, 'd' },
			{ "parent", 1, 0, 'p' },
			{ "id", 1, 0, 'i' },
			{ "kind", 1, 0, 'k' },
			{ 0, 0, 0, 0 }
		};
	
		c = getopt_long(argc, argv, "hvd:p:i:k:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case ARG_DETAILS: params.dp_type = NL_DUMP_DETAILS; break;
		case ARG_STATS: params.dp_type = NL_DUMP_STATS; break;
		case 'h': print_usage(); break;
		case 'v': nl_cli_print_version(); break;
		case 'd': nl_cli_tc_parse_dev(tc, link_cache, optarg); break;
		case 'p': nl_cli_tc_parse_parent(tc, optarg); break;
		case 'i': nl_cli_tc_parse_handle(tc, optarg); break;
		case 'k': nl_cli_qdisc_parse_kind(qdisc, optarg); break;
		}
 	}

	nl_cache_dump_filter(qdisc_cache, &params, OBJ_CAST(qdisc));

	return 0;
}
