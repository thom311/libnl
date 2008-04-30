/*
 * src/nl-route-delete.c     Delete Routes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "route-utils.h"

static int interactive = 0, default_yes = 0, quiet = 0;
static int deleted = 0;
static struct nl_handle *nlh;

static void print_version(void)
{
	fprintf(stderr, "%s\n", LIBNL_STRING);
	exit(0);
}

static void print_usage(void)
{
	printf(
	"Usage: nl-route-delete [OPTION]... [ROUTE]\n"
	"\n"
	"Options\n"
	" -i, --interactive     Run interactively\n"
	"     --yes             Set default answer to yes\n"
	" -q, --quiet		Do not print informal notifications\n"
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

static void delete_cb(struct nl_object *obj, void *arg)
{
	struct rtnl_route *route = (struct rtnl_route *) obj;
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_ONELINE,
		.dp_fd = stdout,
	};
	int err;

	if (interactive) {
		int answer;

		nl_object_dump(obj, &dp);
		printf("Delete? (%c/%c) ",
			default_yes ? 'Y' : 'y',
			default_yes ? 'n' : 'N');

		do {
			answer = tolower(getchar());
			if (answer == '\n')
				answer = default_yes ? 'y' : 'n';
		} while (answer != 'y' && answer != 'n');

		if (answer == 'n')
			return;
	}

	if ((err = rtnl_route_delete(nlh, route, 0)) < 0)
		fatal(err, "rtnl_route_del failed: %s\n", nl_geterror());

	if (!quiet) {
		printf("Deleted ");
		nl_object_dump(obj, &dp);
	}

	deleted++;
}

int main(int argc, char *argv[])
{
	struct nl_cache *link_cache, *route_cache;
	struct rtnl_route *route;
	int err = 1, nf = 0;

	nlh = nltool_alloc_handle();
	nltool_connect(nlh, NETLINK_ROUTE);
	link_cache = nltool_alloc_link_cache(nlh);
	route_cache = nltool_alloc_route_cache(nlh);

	route = rtnl_route_alloc();
	if (!route)
		goto errout;

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
			ARG_YES,
		};
		static struct option long_opts[] = {
			{ "interactive", 0, 0, 'i' },
			{ "yes", 0, 0, ARG_YES },
			{ "quiet", 0, 0, 'q' },
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

		c = getopt_long(argc, argv, "iqhvd:n:t:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'i': interactive = 1; break;
		case ARG_YES: default_yes = 1; break;
		case 'q': quiet = 1; break;
		case 'h': print_usage(); break;
		case 'v': print_version(); break;
		case 'd': nf++; parse_dst(route, optarg); break;
		case 'n': nf++; parse_nexthop(route, optarg, link_cache); break;
		case 't': nf++; parse_table(route, optarg); break;
		case ARG_FAMILY: nf++; parse_family(route, optarg); break;
		case ARG_SRC: nf++; parse_src(route, optarg); break;
		case ARG_IIF: nf++; parse_iif(route, optarg, link_cache); break;
		case ARG_PREF_SRC: nf++; parse_pref_src(route, optarg); break;
		case ARG_METRICS: nf++; parse_metric(route, optarg); break;
		case ARG_PRIORITY: nf++; parse_prio(route, optarg); break;
		case ARG_SCOPE: nf++; parse_scope(route, optarg); break;
		case ARG_PROTOCOL: nf++; parse_protocol(route, optarg); break;
		case ARG_TYPE: nf++; parse_type(route, optarg); break;
		}
	}

	if (nf == 0 && !interactive && !default_yes) {
		fprintf(stderr, "You attempted to delete all routes in "
			"non-interactive mode, aborting.\n");
		exit(0);
	}

	nl_cache_foreach_filter(route_cache, OBJ_CAST(route), delete_cb, NULL);

	if (!quiet)
		printf("Deleted %d routes\n", deleted);

	err = 0;

	rtnl_route_put(route);
errout:
	nl_cache_free(route_cache);
	nl_cache_free(link_cache);
	nl_close(nlh);
	nl_handle_destroy(nlh);

	return err;
}
