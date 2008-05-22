/*
 * src/nl-route-list.c     List route attributes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "route-utils.h"

static void print_usage(void)
{
	printf(
	"Usage: nl-route-list [OPTION]... [ROUTE]\n"
	"\n"
	"Options\n"
	" -c, --cache           List the contents of the route cache\n"
	" -f, --format=TYPE	Output format { brief | details | stats }\n"
	" -h, --help            Show this help\n"
	" -v, --version		Show versioning information\n"
	"\n"
	"Route Options\n"
	" -d, --dst=ADDR        destination prefix, e.g. 10.10.0.0/16\n"
	" -n, --nexthop=NH      nexthop configuration:\n"
	"                         dev=DEV         route via device\n"
	"                         weight=WEIGHT   weight of nexthop\n"
	"                         flags=FLAGS\n"
	"                         via=GATEWAY     route via other node\n"
	"                         realms=REALMS\n"
	"                         e.g. dev=eth0,via=192.168.1.12\n"
	" -t, --table=TABLE     Routing table\n"
	"     --family=FAMILY	Address family\n"
	"     --src=ADDR        Source prefix\n"
	"     --iif=DEV         Incomming interface\n"
	"     --pref-src=ADDR   Preferred source address\n"
	"     --metrics=OPTS    Metrics configurations\n"
	"     --priority=NUM    Priotity\n"
	"     --scope=SCOPE     Scope\n"
	"     --protocol=PROTO  Protocol\n"
	"     --type=TYPE       { unicast | local | broadcast | multicast }\n"
	);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct nl_cache *link_cache, *route_cache;
	struct rtnl_route *route;
	struct nl_dump_params params = {
		.dp_fd = stdout,
		.dp_type = NL_DUMP_BRIEF
	};
	int print_cache = 0;

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);
	route = nlt_alloc_route();

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_FAMILY = 257,
			ARG_SRC = 258,
			ARG_IIF,
			ARG_PREF_SRC,
			ARG_METRICS,
			ARG_PRIORITY,
			ARG_SCOPE,
			ARG_PROTOCOL,
			ARG_TYPE,
		};
		static struct option long_opts[] = {
			{ "cache", 0, 0, 'c' },
			{ "format", 1, 0, 'f' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "dst", 1, 0, 'd' },
			{ "nexthop", 1, 0, 'n' },
			{ "table", 1, 0, 't' },
			{ "family", 1, 0, ARG_FAMILY },
			{ "src", 1, 0, ARG_SRC },
			{ "iif", 1, 0, ARG_IIF },
			{ "pref-src", 1, 0, ARG_PREF_SRC },
			{ "metrics", 1, 0, ARG_METRICS },
			{ "priority", 1, 0, ARG_PRIORITY },
			{ "scope", 1, 0, ARG_SCOPE },
			{ "protocol", 1, 0, ARG_PROTOCOL },
			{ "type", 1, 0, ARG_TYPE },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "cf:hvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'c': print_cache = 1; break;
		case 'f': params.dp_type = nlt_parse_dumptype(optarg); break;
		case 'h': print_usage(); break;
		case 'v': nlt_print_version(); break;
		case 'd': parse_dst(route, optarg); break;
		case 'n': parse_nexthop(route, optarg, link_cache); break;
		case 't': parse_table(route, optarg); break;
		case ARG_FAMILY: parse_family(route, optarg); break;
		case ARG_SRC: parse_src(route, optarg); break;
		case ARG_IIF: parse_iif(route, optarg, link_cache); break;
		case ARG_PREF_SRC: parse_pref_src(route, optarg); break;
		case ARG_METRICS: parse_metric(route, optarg); break;
		case ARG_PRIORITY: parse_prio(route, optarg); break;
		case ARG_SCOPE: parse_scope(route, optarg); break;
		case ARG_PROTOCOL: parse_protocol(route, optarg); break;
		case ARG_TYPE: parse_type(route, optarg); break;
		}
	}

	route_cache = nlt_alloc_route_cache(sock,
				print_cache ? ROUTE_CACHE_CONTENT : 0);

	nl_cache_dump_filter(route_cache, &params, OBJ_CAST(route));

	return 0;
}
