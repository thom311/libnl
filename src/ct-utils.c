/*
 * src/ct-utils.c		Conntrack Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2008 Thomas Graf <tgraf@suug.ch>
 */

#include "ct-utils.h"

struct nfnl_ct *nlt_alloc_ct(void)
{
	struct nfnl_ct *ct;

	ct = nfnl_ct_alloc();
	if (!ct)
		fatal(ENOMEM, "Unable to allocate conntrack object");

	return ct;
}

struct nl_cache *nlt_alloc_ct_cache(struct nl_sock *sk)
{
	return alloc_cache(sk, "conntrack", nfnl_ct_alloc_cache);
}

void parse_family(struct nfnl_ct *ct, char *arg)
{
	int family;

	if ((family = nl_str2af(arg)) == AF_UNSPEC)
		fatal(EINVAL, "Unable to parse family \"%s\": %s",
		      arg, nl_geterror(NLE_INVAL));

	nfnl_ct_set_family(ct, family);
}

void parse_protocol(struct nfnl_ct *ct, char *arg)
{
	int proto;

	if ((proto = nl_str2ip_proto(arg)) < 0)
		fatal(proto, "Unable to parse protocol \"%s\": %s",
		      arg, nl_geterror(proto));

	nfnl_ct_set_proto(ct, proto);
}

void parse_mark(struct nfnl_ct *ct, char *arg)
{
	uint32_t mark = parse_u32(arg);
	nfnl_ct_set_mark(ct, mark);
}

void parse_timeout(struct nfnl_ct *ct, char *arg)
{
	uint32_t timeout = parse_u32(arg);
	nfnl_ct_set_timeout(ct, timeout);
}

void parse_id(struct nfnl_ct *ct, char *arg)
{
	uint32_t id = parse_u32(arg);
	nfnl_ct_set_id(ct, id);
}

void parse_use(struct nfnl_ct *ct, char *arg)
{
	uint32_t use = parse_u32(arg);
	nfnl_ct_set_use(ct, use);
}

void parse_src(struct nfnl_ct *ct, int reply, char *arg)
{
	int err;
	struct nl_addr *a = nlt_addr_parse(arg, nfnl_ct_get_family(ct));
	if ((err = nfnl_ct_set_src(ct, reply, a)) < 0)
		fatal(err, "Unable to set source address: %s",
		      nl_geterror(err));
}

void parse_dst(struct nfnl_ct *ct, int reply, char *arg)
{
	int err;
	struct nl_addr *a = nlt_addr_parse(arg, nfnl_ct_get_family(ct));
	if ((err = nfnl_ct_set_dst(ct, reply, a)) < 0)
		fatal(err, "Unable to set destination address: %s",
		      nl_geterror(err));
}

void parse_src_port(struct nfnl_ct *ct, int reply, char *arg)
{
	uint32_t port = parse_u32(arg);
	nfnl_ct_set_src_port(ct, reply, port);
}

void parse_dst_port(struct nfnl_ct *ct, int reply, char *arg)
{
	uint32_t port = parse_u32(arg);
	nfnl_ct_set_dst_port(ct, reply, port);
}

void parse_tcp_state(struct nfnl_ct *ct, char *arg)
{
	int state;

	if ((state = nfnl_ct_str2tcp_state(arg)) < 0)
		fatal(state, "Unable to parse tcp state \"%s\": %s",
		      arg, nl_geterror(state));

	nfnl_ct_set_tcp_state(ct, state);
}

void parse_status(struct nfnl_ct *ct, char *arg)
{
	int status;

	if ((status = nfnl_ct_str2status(arg)) < 0)
		fatal(status, "Unable to parse flags \"%s\": %s",
		      arg, nl_geterror(status));

	nfnl_ct_set_status(ct, status);
}

#if 0
		} else if (arg_match("origicmpid")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_id(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origicmptype")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_type(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("origicmpcode")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_code(ct, 0, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replyicmpid")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_id(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replyicmptype")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_type(ct, 1, strtoul(argv[idx++], NULL, 0));
		} else if (arg_match("replyicmpcode")) {
			if (argc > ++idx)
				nfnl_ct_set_icmp_code(ct, 1, strtoul(argv[idx++], NULL, 0));
		}
#endif
