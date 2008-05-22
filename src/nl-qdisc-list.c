/*
 * src/nl-qdisc-list.c     List Qdiscs
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "qdisc-utils.h"

static int quiet = 0;

static void print_usage(void)
{
	printf(
	"Usage: nl-qdisc-list [OPTION]... [QDISC]\n"
	"\n"
	"Options\n"
	" -f, --format=TYPE     Output format { brief | details | stats }\n"
	" -h, --help            Show this help\n"
	" -v, --version         Show versioning information\n"
	"\n"
	"QDisc Options\n"
	" -d, --dev=DEV         Device the qdisc is attached to\n"
	" -p, --parent=HANDLE   Identifier of parent qdisc\n"
	" -H, --handle=HANDLE   Identifier\n"
	" -k, --kind=NAME       Kind of qdisc (e.g. pfifo_fast)\n"
	);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct rtnl_qdisc *qdisc;
	struct nl_cache *link_cache, *qdisc_cache;
	struct nl_dump_params params = {
		.dp_type = NL_DUMP_ONELINE,
		.dp_fd = stdout,
	};
 
	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);
	qdisc_cache = nlt_alloc_qdisc_cache(sock);
 	qdisc = nlt_alloc_qdisc();
 
	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_YES = 257,
		};
		static struct option long_opts[] = {
			{ "format", 1, 0, 'f' },
			{ "quiet", 0, 0, 'q' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "dev", 1, 0, 'd' },
			{ "parent", 1, 0, 'p' },
			{ "handle", 1, 0, 'H' },
			{ "kind", 1, 0, 'k' },
			{ 0, 0, 0, 0 }
		};
	
		c = getopt_long(argc, argv, "f:qhvd:p:H:k:",
				long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'f': params.dp_type = nlt_parse_dumptype(optarg); break;
		case 'q': quiet = 1; break;
		case 'h': print_usage(); break;
		case 'v': nlt_print_version(); break;
		case 'd': parse_dev(qdisc, link_cache, optarg); break;
		case 'p': parse_parent(qdisc, optarg); break;
		case 'H': parse_handle(qdisc, optarg); break;
		case 'k': parse_kind(qdisc, optarg); break;
		}
 	}

	nl_cache_dump_filter(qdisc_cache, &params, OBJ_CAST(qdisc));

	return 0;
}
