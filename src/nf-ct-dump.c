/*
 * src/nf-ct-dump.c     Dump conntrack attributes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2007 Philip Craig <philipc@snapgear.com>
 * Copyright (c) 2007 Secure Computing Corporation
 */

#include "utils.h"
#include <netlink/netfilter/ct.h>
#include <linux/netfilter/nf_conntrack_common.h>

#include "f_ct.c"

static void print_usage(void)
{
	printf(
	"Usage: nf-ct-dump <mode> [<filter>]\n"
	"  mode := { brief | detailed | stats | xml }\n"
	"  filter := [family FAMILY] [proto PROTO] [tcpstate TCPSTATE]\n"
	"            [status STATUS] [timeout TIMEOUT] [mark MARK] [use USE] [id ID]\n"
	"            [origsrc ADDR] [origdst ADDR] [origsrcport PORT] [origdstport PORT]\n"
	"            [origicmpid ID] [origicmptype TYPE] [origicmpcode CODE]\n"
	"            [origpackets PACKETS] [origbytes BYTES]\n"
	"            [replysrc ADDR] [replydst ADDR] [replysrcport PORT] [replydstport PORT]\n"
	"            [replyicmpid ID] [replyicmptype TYPE] [replyicmpcode CODE]\n"
	"            [replypackets PACKETS] [replybytes BYTES]\n"
	"            [{ replied | unreplied }] [{ assured | unassured }]\n"
	);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct nl_handle *nlh;
	struct nl_cache *ct_cache;
	struct nfnl_ct *ct;
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

	ct = nfnl_ct_alloc();
	if (!ct)
		goto errout;

	if (nltool_connect(nlh, NETLINK_NETFILTER) < 0)
		goto errout_free;

	ct_cache = nfnl_ct_alloc_cache(nlh);
        if (!ct_cache) {
		fprintf(stderr, "Unable to retrieve ct cache: %s\n",
			nl_geterror());
		goto errout_close;
	}
	nl_cache_mngt_provide(ct_cache);

	params.dp_type = nltool_parse_dumptype(argv[1]);
	if (params.dp_type < 0)
		goto errout_ct_cache;

	get_filter(ct, argc, argv, 2);
	nl_cache_dump_filter(ct_cache, &params, (struct nl_object *) ct);

	err = 0;

errout_ct_cache:
	nl_cache_free(ct_cache);
errout_close:
	nl_close(nlh);
errout_free:
	nfnl_ct_put(ct);
errout:
	return err;
}
