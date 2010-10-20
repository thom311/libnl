
/*
 * src/lib/pfifo.c     	pfifo module for CLI lib
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
"Usage: nl-qdisc-add [...] pfifo [OPTIONS]...\n"
"\n"
"OPTIONS\n"
"     --help                Show this help text.\n"
"     --limit=LIMIT         Maximum queue length in number of packets.\n"
"\n"
"EXAMPLE"
"    # Attach pfifo with a 32 packet limit to eth1\n"
"    nl-qdisc-add --dev=eth1 --parent=root pfifo --limit=32\n");
}

static void pfifo_parse_argv(struct rtnl_qdisc *qdisc, int argc, char **argv)
{
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
			rtnl_qdisc_fifo_set_limit(qdisc, nl_cli_parse_u32(optarg));
			break;
		}
 	}
}

static struct nl_cli_qdisc_module pfifo_module =
{
	.qm_name		= "pfifo",
	.qm_parse_qdisc_argv	= pfifo_parse_argv,
};

static void __init pfifo_init(void)
{
	nl_cli_qdisc_register(&pfifo_module);
}

static void __exit pfifo_exit(void)
{
	nl_cli_qdisc_unregister(&pfifo_module);
}
