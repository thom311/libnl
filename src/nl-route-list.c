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
	"Usage: nl-route-list [OPTION]...\n"
	"\n"
	"Options\n"
	" -f, --family=FAMILY	address family\n"
	" -d, --dst=ADDR        destination prefix, e.g. 10.10.0.0/16\n"
	" -n, --nh=NEXTHOP      nexthop configuration:\n"
	"                         dev=DEV         route via device\n"
	"                         weight=WEIGHT   weight of nexthop\n"
	"                         flags=FLAGS\n"
	"                         via=GATEWAY     route via other node\n"
	"                         realms=REALMS\n"
	"                         e.g. dev=eth0,via=192.168.1.12\n"
	" -s, --src=ADDR        source prefix\n"
	" -i, --iif=DEV         incomming interface\n"
	" -P, --pref-src=ADDR   preferred source address\n"
	" -t, --table=TABLE     routing table\n"
	" -m, --metric=OPTS     metrics\n"
	" -p, --prio=NUM        priotity\n"
	" -S, --scope=SCOPE     scope\n"
	" -x, --proto=PROTO     protocol\n"
	" -T, --type=TYPE       routing type\n"
	" -D, --dumptype=TYPE   { brief | detailed | stats | env }\n"
	" -h, --help            show this help\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nl_handle *nlh;
	struct nl_cache *link_cache, *route_cache;
	struct rtnl_route *route;
	struct nl_dump_params params = {
		.dp_fd = stdout,
		.dp_type = NL_DUMP_BRIEF
	};
	int err = 1;

	nlh = nltool_alloc_handle();
	nltool_connect(nlh, NETLINK_ROUTE);
	link_cache = nltool_alloc_link_cache(nlh);
	route_cache = nltool_alloc_route_cache(nlh);

	route = rtnl_route_alloc();
	if (!route)
		goto errout;

	for (;;) {
		int c, optidx = 0;
		static struct option long_opts[] = {
			{ "family", 1, 0, 'f' },
			{ "dst", 1, 0, 'd' },
			{ "src", 1, 0, 's' },
			{ "iif", 1, 0, 'i' },
			{ "nh", 1, 0, 'n' },
			{ "pref-src", 1, 0, 'P' },
			{ "table", 1, 0, 't' },
			{ "metric", 1, 0, 'm' },
			{ "prio", 1, 0, 'p' },
			{ "scope", 1, 0, 'S' },
			{ "proto", 1, 0, 'x' },
			{ "type", 1, 0, 'T' },
			{ "dumptype", 1, 0, 'D' },
			{ "help", 0, 0, 'h' },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "f:d:s:i:n:P:t:m:p:S:x:T:D:h",
				long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'f': parse_family(route, optarg); break;
		case 'd': parse_dst(route, optarg); break;
		case 's': parse_src(route, optarg); break;
		case 'i': parse_iif(route, optarg, link_cache); break;
		case 'n': parse_nexthop(route, optarg, link_cache); break;
		case 'P': parse_pref_src(route, optarg); break;
		case 't': parse_table(route, optarg); break;
		case 'm': parse_metric(route, optarg); break;
		case 'p': parse_prio(route, optarg); break;
		case 'S': parse_scope(route, optarg); break;
		case 'x': parse_protocol(route, optarg); break;
		case 'T': parse_type(route, optarg); break;
		case 'D': params.dp_type = nltool_parse_dumptype(optarg); break;
		case 'h': print_usage(); break;
		}
	}

	nl_cache_dump_filter(route_cache, &params, OBJ_CAST(route));

	err = 0;

	rtnl_route_put(route);
errout:
	nl_cache_free(route_cache);
	nl_cache_free(link_cache);
	nl_close(nlh);
	nl_handle_destroy(nlh);

	return err;
}
