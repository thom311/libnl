/*
 * src/lib/bfifo.c     	bfifo module for CLI lib
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2010 Thomas Graf <tgraf@suug.ch>
 */

#include <netlink/cli/utils.h>
#include <netlink/cli/qdisc.h>
#include <netlink/route/sch/fifo.h>

static void print_usage(void)
{
	printf(
"Usage: nl-qdisc-add [...] bfifo [OPTIONS]...\n"
"\n"
"OPTIONS\n"
"     --help                Show this help text.\n"
"     --limit=LIMIT         Maximum queue length in number of bytes.\n"
"\n"
"EXAMPLE"
"    # Attach bfifo with a 4KB bytes limit to eth1\n"
"    nl-qdisc-add --dev=eth1 --parent=root bfifo --limit=4096\n");
}

static void bfifo_parse_argv(struct rtnl_qdisc *qdisc, int argc, char **argv)
{
	int limit;

	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_LIMIT = 257,
		};
		static struct option long_opts[] = {
			{ "help", 0, 0, 'h' },
			{ "limit", 1, 0, ARG_LIMIT },
			{ 0, 0, 0, 0 }
		};
	
		c = getopt_long(argc, argv, "h", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			return;

		case ARG_LIMIT:
			limit = nl_size2int(optarg);
			if (limit < 0) {
				nl_cli_fatal(limit, "Unable to parse bfifo limit "
					"\"%s\": Invalid format.", optarg);
			}

			rtnl_qdisc_fifo_set_limit(qdisc, limit);
			break;
		}
 	}
}

static struct nl_cli_qdisc_module bfifo_module =
{
	.qm_name		= "bfifo",
	.qm_parse_qdisc_argv	= bfifo_parse_argv,
};

static void __init bfifo_init(void)
{
	nl_cli_qdisc_register(&bfifo_module);
}

static void __exit bfifo_exit(void)
{
	nl_cli_qdisc_unregister(&bfifo_module);
}
