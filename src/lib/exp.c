/*
 * src/lib/exp.c		CLI Expectation Helpers
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 20012 Rich Fought <Rich.Fought@watchguard.com>
 */

/**
 * @ingroup cli
 * @defgroup cli_exp Expectation Tracking
 *
 * @{
 */

#include <netlink/cli/utils.h>
#include <netlink/cli/exp.h>

struct nfnl_exp *nl_cli_exp_alloc(void)
{
	struct nfnl_exp *exp;

	exp = nfnl_exp_alloc();
	if (!exp)
		nl_cli_fatal(ENOMEM, "Unable to allocate expectation object");

	return exp;
}

struct nl_cache *nl_cli_exp_alloc_cache(struct nl_sock *sk)
{
	return nl_cli_alloc_cache(sk, "expectation", nfnl_exp_alloc_cache);
}

void nl_cli_exp_parse_family(struct nfnl_exp *exp, char *arg)
{
	int family;

	if ((family = nl_str2af(arg)) == AF_UNSPEC)
		nl_cli_fatal(EINVAL,
			     "Unable to nl_cli_exp_parse family \"%s\": %s",
			     arg, nl_geterror(NLE_INVAL));

	nfnl_exp_set_family(exp, family);
}

void nl_cli_exp_parse_timeout(struct nfnl_exp *exp, char *arg)
{
	uint32_t timeout = nl_cli_parse_u32(arg);
	nfnl_exp_set_timeout(exp, timeout);
}

void nl_cli_exp_parse_id(struct nfnl_exp *exp, char *arg)
{
	uint32_t id = nl_cli_parse_u32(arg);
	nfnl_exp_set_id(exp, id);
}

void nl_cli_exp_parse_src(struct nfnl_exp *exp, int tuple, char *arg)
{
	int err;
	struct nl_addr *a = nl_cli_addr_parse(arg, nfnl_exp_get_family(exp));
	if ((err = nfnl_exp_set_src(exp, tuple, a)) < 0)
		nl_cli_fatal(err, "Unable to set source address: %s",
			     nl_geterror(err));
}

void nl_cli_exp_parse_dst(struct nfnl_exp *exp, int tuple, char *arg)
{
	int err;
	struct nl_addr *a = nl_cli_addr_parse(arg, nfnl_exp_get_family(exp));
	if ((err = nfnl_exp_set_dst(exp, tuple, a)) < 0)
		nl_cli_fatal(err, "Unable to set destination address: %s",
			     nl_geterror(err));
}

void nl_cli_exp_parse_l4protonum(struct nfnl_exp *exp, int tuple, char *arg)
{
    int l4protonum;

    if ((l4protonum = nl_str2ip_proto(arg)) < 0)
        nl_cli_fatal(l4protonum,
                 "Unable to nl_cli_exp_parse protocol \"%s\": %s",
                 arg, nl_geterror(l4protonum));

    nfnl_exp_set_l4protonum(exp, tuple, l4protonum);
}

void nl_cli_exp_parse_src_port(struct nfnl_exp *exp, int tuple, char *arg)
{
	uint32_t sport = nl_cli_parse_u32(arg);
	nfnl_exp_set_ports(exp, tuple, sport, 0);
}

void nl_cli_exp_parse_dst_port(struct nfnl_exp *exp, int tuple, char *arg)
{
	uint32_t dport = nl_cli_parse_u32(arg);
	uint32_t sport = nfnl_exp_get_src_port(exp, tuple);
	nfnl_exp_set_ports(exp, tuple, sport, dport);
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

/** @} */
