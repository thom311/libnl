/*
 * src/genl-ctrl-dump.c	Dump Generic Netlink Controller
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

#include "utils.h"

static void print_usage(void)
{
	printf(
	"Usage: genl-ctrl-dump <mode> [<filter>]\n"
	"  mode := { brief | detailed | stats }\n"
	"  filter := \n");
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nl_handle *nlh;
	struct nl_cache *family_cache;
	struct nl_dump_params params = {
		.dp_fd = stdout,
		.dp_type = NL_DUMP_BRIEF
	};
	int err = 1;

	if (nltool_init(argc, argv) < 0)
		return -1;

	if (argc < 2 || !strcmp(argv[1], "-h"))
		print_usage();

	nlh = nltool_alloc_handle();
	if (!nlh)
		return -1;

	if (genl_connect(nlh) < 0) {
		fprintf(stderr, "Unable to connect generic netlink socket%s\n",
			nl_geterror());
		goto errout;
	}

	family_cache = nltool_alloc_genl_family_cache(nlh);
	if (!family_cache)
		goto errout;

	params.dp_type = nltool_parse_dumptype(argv[1]);
	if (params.dp_type < 0)
		goto errout;

	//get_filter(link, argc, argv, 2, link_cache);
	nl_cache_dump(family_cache, &params);
	nl_cache_free(family_cache);
	err = 0;
errout:
	nl_close(nlh);
	nl_handle_destroy(nlh);
	return err;
}
