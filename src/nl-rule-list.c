/*
 * src/nl-rule-dump.c     Dump rule attributes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "rule-utils.h"

static void print_usage(void)
{
	printf(
	"Usage: nl-rule-list [OPTION]... [ROUTE]\n"
	"\n"
	"Options\n"
	" -c, --cache           List the contents of the route cache\n"
	" -f, --format=TYPE	Output format { brief | details | stats }\n"
	" -h, --help            Show this help\n"
	" -v, --version		Show versioning information\n"
	"\n"
	"Rule Options\n"
	"     --family          Address family\n"
	);
	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct rtnl_rule *rule;
	struct nl_cache *link_cache, *rule_cache;
	struct nl_dump_params params = {
		.dp_fd = stdout,
		.dp_type = NL_DUMP_BRIEF
	};

	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);
	rule_cache = nlt_alloc_rule_cache(sock);
	rule = nlt_alloc_rule();

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_FAMILY = 257,
		};
		static struct option long_opts[] = {
			{ "format", 1, 0, 'f' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "family", 1, 0, ARG_FAMILY },
			{ 0, 0, 0, 0 }
		};

		c = getopt_long(argc, argv, "f:hv", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'f': params.dp_type = nlt_parse_dumptype(optarg); break;
		case 'h': print_usage(); break;
		case 'v': nlt_print_version(); break;
		case ARG_FAMILY: parse_family(rule, optarg); break;
		}
	}

	nl_cache_dump_filter(rule_cache, &params, OBJ_CAST(rule));

	return 0;
}
