/*
 * src/f_ct.c     	Conntrack Filter
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

static void get_filter(struct nfnl_ct *ct, int argc, char **argv, int idx)
{
	struct nl_addr *a;

	while (argc > idx) {
		if (arg_match("family")) {
			if (argc > ++idx) {
				int family = nl_str2af(argv[idx++]);
				if (family == AF_UNSPEC)
					goto err_invaf;
				nfnl_ct_set_family(ct, family);
			}
		} else if (arg_match("proto")) {
			if (argc > ++idx) {
				int proto = nl_str2ip_proto(argv[idx++]);
				if (proto < 0)
					goto err_invproto;
				nfnl_ct_set_proto(ct, proto);
			}
		} else if (arg_match("tcpstate")) {
			if (argc > ++idx) {
				int state = nfnl_ct_str2tcp_state(argv[idx++]);
				if (state < 0)
					goto err_invtcpstate;
				nfnl_ct_set_tcp_state(ct, state);
			}
		} else if (arg_match("status")) {
			if (argc > ++idx)
				nfnl_ct_set_status(ct, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("timeout")) {
			if (argc > ++idx)
				nfnl_ct_set_timeout(ct, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("mark")) {
			if (argc > ++idx)
				nfnl_ct_set_mark(ct, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("use")) {
			if (argc > ++idx)
				nfnl_ct_set_use(ct, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("id")) {
			if (argc > ++idx)
				nfnl_ct_set_id(ct, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origsrc")) {
			if (argc > ++idx) {
				a = nl_addr_parse(argv[idx++],
						  nfnl_ct_get_family(ct));
				if (!a)
					goto err_invaddr;
				nfnl_ct_set_src(ct, 0, a);
				nl_addr_put(a);
			}
		} else if (arg_match("origdst")) {
			if (argc > ++idx) {
				a = nl_addr_parse(argv[idx++],
						  nfnl_ct_get_family(ct));
				if (!a)
					goto err_invaddr;
				nfnl_ct_set_dst(ct, 0, a);
				nl_addr_put(a);
			}
		} else if (arg_match("origsrcport")) {
			if (argc > ++idx)
				nfnl_ct_set_src_port(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origdstport")) {
			if (argc > ++idx)
				nfnl_ct_set_dst_port(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origicmpid")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_id(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origicmptype")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_type(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origicmpcode")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_code(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origpackets")) {
			if (argc > ++idx)
				nfnl_ct_set_packets(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origbytes")) {
			if (argc > ++idx)
				nfnl_ct_set_bytes(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replysrc")) {
			if (argc > ++idx) {
				a = nl_addr_parse(argv[idx++],
						  nfnl_ct_get_family(ct));
				if (!a)
					goto err_invaddr;
				nfnl_ct_set_src(ct, 1, a);
				nl_addr_put(a);
			}
		} else if (arg_match("replydst")) {
			if (argc > ++idx) {
				a = nl_addr_parse(argv[idx++],
						  nfnl_ct_get_family(ct));
				if (!a)
					goto err_invaddr;
				nfnl_ct_set_dst(ct, 1, a);
				nl_addr_put(a);
			}
		} else if (arg_match("replysrcport")) {
			if (argc > ++idx)
				nfnl_ct_set_src_port(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replydstport")) {
			if (argc > ++idx)
				nfnl_ct_set_dst_port(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replyicmpid")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_id(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replyicmptype")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_type(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replyicmpcode")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_code(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replypackets")) {
			if (argc > ++idx)
				nfnl_ct_set_packets(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replybytes")) {
			if (argc > ++idx)
				nfnl_ct_set_bytes(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else {
			fprintf(stderr, "What is '%s'?\n", argv[idx]);
			exit(1);
		}
	}

	return;

err_invproto:
	fprintf(stderr, "Invalid IP protocol \"%s\".\n", argv[idx-1]);
	exit(1);
err_invtcpstate:
	fprintf(stderr, "Invalid TCP state \"%s\".\n", argv[idx-1]);
	exit(1);
err_invaf:
	fprintf(stderr, "Invalid address family \"%s\"\n", argv[idx-1]);
	exit(1);
err_invaddr:
	fprintf(stderr, "Invalid address \"%s\": %s\n", argv[idx-1], nl_geterror());
	exit(1);
}
