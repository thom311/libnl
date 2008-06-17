/*
 * src/nl-addr-add.c     Add addresses
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License as
 *	published by the Free Software Foundation version 2 of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 */

#include "addr-utils.h"

static int quiet = 0;

static void print_usage(void)
{
	printf(
"Usage: nl-addr-add [OPTION]... [ADDRESS]\n"
"\n"
"Options\n"
"     --replace             Replace the address if it exists.\n"
" -q, --quiet               Do not print informal notifications.\n"
" -h, --help                Show this help.\n"
" -v, --version             Show versioning information.\n"
"\n"
"Address Options\n"
" -a, --local=ADDR          Address to be considered local.\n"
" -d, --dev=DEV             Device the address should be assigned to.\n"
"     --family=FAMILY       Address family (normally autodetected).\n"
"     --broadcast=ADDR      Broadcast address of network (IPv4).\n"
"     --peer=ADDR           Peer address (IPv4).\n"
"     --label=STRING        Additional address label (IPv4).\n"
"     --scope=SCOPE         Scope of local address (IPv4).\n"
"     --preferred=TIME      Preferred lifetime (IPv6).\n"
"     --valid=TIME          Valid lifetime (IPv6).\n"
	);

	exit(0);
}

int main(int argc, char *argv[])
{
	struct nl_sock *sock;
	struct rtnl_addr *addr;
	struct nl_cache *link_cache;
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_LINE,
		.dp_fd = stdout,
	};
	int err, nlflags = NLM_F_CREATE;
 
	sock = nlt_alloc_socket();
	nlt_connect(sock, NETLINK_ROUTE);
	link_cache = nlt_alloc_link_cache(sock);
 	addr = nlt_alloc_addr();
 
	for (;;) {
		int c, optidx = 0;
		enum {
			ARG_FAMILY = 257,
			ARG_LABEL = 258,
			ARG_PEER,
			ARG_SCOPE,
			ARG_BROADCAST,
			ARG_REPLACE,
			ARG_PREFERRED,
			ARG_VALID,
		};
		static struct option long_opts[] = {
			{ "replace", 0, 0, ARG_REPLACE },
			{ "quiet", 0, 0, 'q' },
			{ "help", 0, 0, 'h' },
			{ "version", 0, 0, 'v' },
			{ "local", 1, 0, 'a' },
			{ "dev", 1, 0, 'd' },
			{ "family", 1, 0, ARG_FAMILY },
			{ "label", 1, 0, ARG_LABEL },
			{ "peer", 1, 0, ARG_PEER },
			{ "scope", 1, 0, ARG_SCOPE },
			{ "broadcast", 1, 0, ARG_BROADCAST },
			{ "preferred", 1, 0, ARG_PREFERRED },
			{ "valid", 1, 0, ARG_VALID },
			{ 0, 0, 0, 0 }
		};
	
		c = getopt_long(argc, argv, "qhva:d:", long_opts, &optidx);
		if (c == -1)
			break;

		switch (c) {
		case '?': exit(NLE_INVAL);
		case ARG_REPLACE: nlflags |= NLM_F_REPLACE; break;
		case 'q': quiet = 1; break;
		case 'h': print_usage(); break;
		case 'v': nlt_print_version(); break;
		case 'a': parse_local(addr, optarg); break;
		case 'd': parse_dev(addr, link_cache, optarg); break;
		case ARG_FAMILY: parse_family(addr, optarg); break;
		case ARG_LABEL: parse_label(addr, optarg); break;
		case ARG_PEER: parse_peer(addr, optarg); break;
		case ARG_SCOPE: parse_scope(addr, optarg); break;
		case ARG_BROADCAST: parse_broadcast(addr, optarg); break;
		case ARG_PREFERRED: parse_preferred(addr, optarg); break;
		case ARG_VALID: parse_valid(addr, optarg); break;
		}
 	}

	if ((err = rtnl_addr_add(sock, addr, nlflags)) < 0)
		fatal(err, "Unable to add address: %s", nl_geterror(err));

	if (!quiet) {
		printf("Added ");
		nl_object_dump(OBJ_CAST(addr), &dp);
 	}

	return 0;
}
