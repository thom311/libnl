/*
 * src/lib/htb.c     	HTB module for CLI lib
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

static void print_usage(void)
{
	printf(
"Usage: nl-qdisc-add [...] htb [OPTIONS]...\n"
"\n"
"OPTIONS\n"
"     --help                Show this help text.\n"
"     --r2q=DIV             Rate to quantum divisor (default: 10)\n"
"     --default=ID          Default class for unclassified traffic.\n"
"\n"
"EXAMPLE"
"    # Create htb root qdisc 1: and direct unclassified traffic to class 1:10\n"
"    nl-qdisc-add --dev=eth1 --parent=root --handle=1: htb --default=10\n");
}

static void htb_parse_argv(struct rtnl_qdisc *qdisc, int argc, char **argv)
{
	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_R2Q = 257,
			ARG_DEFAULT = 258,
		};
		static struct option long_opts[] = {
			{ "help", 0, 0, 'h' },
			{ "r2q", 1, 0, ARG_R2Q },
			{ "default", 1, 0, ARG_DEFAULT },
			{ 0, 0, 0, 0 }
		};
	
		c = getopt_long(argc, argv, "hv", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_usage();
			return;

		case ARG_R2Q:
			rtnl_htb_set_rate2quantum(qdisc, nl_cli_parse_u32(optarg));
			break;

		case ARG_DEFAULT:
			rtnl_htb_set_defcls(qdisc, nl_cli_parse_u32(optarg));
			break;
		}
 	}
}

static struct nl_cli_qdisc_module htb_module =
{
	.qm_name	= "htb",
	.qm_parse_argv	= htb_parse_argv,
};

static void __init htb_init(void)
{
	nl_cli_qdisc_register(&htb_module);
}

static void __exit htb_exit(void)
{
	nl_cli_qdisc_unregister(&htb_module);
}
