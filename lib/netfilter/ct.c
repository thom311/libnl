/*
 * lib/netfilter/ct.c	Conntrack
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

/**
 * @ingroup nfnl
 * @defgroup ct Conntrack
 * @brief
 * @{
 */

#include <byteswap.h>
#include <sys/types.h>
#include <linux/netfilter/nfnetlink_conntrack.h>

#include <netlink-local.h>
#include <netlink/attr.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/ct.h>

static struct nl_cache_ops nfnl_ct_ops;

#if __BYTE_ORDER == __BIG_ENDIAN
static uint64_t ntohll(uint64_t x)
{
	return x;
}
#elif __BYTE_ORDER == __LITTLE_ENDIAN
static uint64_t ntohll(uint64_t x)
{
	return __bswap_64(x);
}
#endif

static struct nla_policy ct_policy[CTA_MAX+1] = {
	[CTA_TUPLE_ORIG]	= { .type = NLA_NESTED },
	[CTA_TUPLE_REPLY]	= { .type = NLA_NESTED },
	[CTA_STATUS]		= { .type = NLA_U32 },
	[CTA_PROTOINFO]		= { .type = NLA_NESTED },
	//[CTA_HELP]
	//[CTA_NAT_SRC]
	[CTA_TIMEOUT]		= { .type = NLA_U32 },
	[CTA_MARK]		= { .type = NLA_U32 },
	[CTA_COUNTERS_ORIG]	= { .type = NLA_NESTED },
	[CTA_COUNTERS_REPLY]	= { .type = NLA_NESTED },
	[CTA_USE]		= { .type = NLA_U32 },
	[CTA_ID]		= { .type = NLA_U32 },
	//[CTA_NAT_DST]
};

static struct nla_policy ct_tuple_policy[CTA_TUPLE_MAX+1] = {
	[CTA_TUPLE_IP]		= { .type = NLA_NESTED },
	[CTA_TUPLE_PROTO]	= { .type = NLA_NESTED },
};

static struct nla_policy ct_ip_policy[CTA_IP_MAX+1] = {
	[CTA_IP_V4_SRC]		= { .type = NLA_U32 },
	[CTA_IP_V4_DST]		= { .type = NLA_U32 },
	[CTA_IP_V6_SRC]		= { .minlen = 16 },
	[CTA_IP_V6_DST]		= { .minlen = 16 },
};

static struct nla_policy ct_proto_policy[CTA_PROTO_MAX+1] = {
	[CTA_PROTO_NUM]		= { .type = NLA_U8 },
	[CTA_PROTO_SRC_PORT]	= { .type = NLA_U16 },
	[CTA_PROTO_DST_PORT]	= { .type = NLA_U16 },
	[CTA_PROTO_ICMP_ID]	= { .type = NLA_U16 },
	[CTA_PROTO_ICMP_TYPE]	= { .type = NLA_U8 },
	[CTA_PROTO_ICMP_CODE]	= { .type = NLA_U8 },
	[CTA_PROTO_ICMPV6_ID]	= { .type = NLA_U16 },
	[CTA_PROTO_ICMPV6_TYPE]	= { .type = NLA_U8 },
	[CTA_PROTO_ICMPV6_CODE]	= { .type = NLA_U8 },
};

static struct nla_policy ct_protoinfo_policy[CTA_PROTOINFO_MAX+1] = {
	[CTA_PROTOINFO_TCP]	= { .type = NLA_NESTED },
};

static struct nla_policy ct_protoinfo_tcp_policy[CTA_PROTOINFO_TCP_MAX+1] = {
	[CTA_PROTOINFO_TCP_STATE]		= { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL]	= { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_WSCALE_REPLY]	= { .type = NLA_U8 },
	[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]	= { .minlen = 2 },
	[CTA_PROTOINFO_TCP_FLAGS_REPLY]		= { .minlen = 2 },

};

static struct nla_policy ct_counters_policy[CTA_COUNTERS_MAX+1] = {
	[CTA_COUNTERS_PACKETS]	= { .type = NLA_U64 },
	[CTA_COUNTERS_BYTES]	= { .type = NLA_U64 },
	[CTA_COUNTERS32_PACKETS]= { .type = NLA_U32 },
	[CTA_COUNTERS32_BYTES]	= { .type = NLA_U32 },
};

static int ct_parse_ip(struct nfnl_ct *ct, int repl, struct nlattr *attr)
{
	struct nlattr *tb[CTA_IP_MAX+1];
	struct nl_addr *addr;
	int err;

        err = nla_parse_nested(tb, CTA_IP_MAX, attr, ct_ip_policy);
	if (err < 0)
		goto errout;

	if (tb[CTA_IP_V4_SRC]) {
		addr = nla_get_addr(tb[CTA_IP_V4_SRC], AF_INET);
		if (addr == NULL)
			goto errout_errno;
		err = nfnl_ct_set_src(ct, repl, addr);
		nl_addr_put(addr);
		if (err < 0)
			goto errout;
	}
	if (tb[CTA_IP_V4_DST]) {
		addr = nla_get_addr(tb[CTA_IP_V4_DST], AF_INET);
		if (addr == NULL)
			goto errout_errno;
		err = nfnl_ct_set_dst(ct, repl, addr);
		nl_addr_put(addr);
		if (err < 0)
			goto errout;
	}
	if (tb[CTA_IP_V6_SRC]) {
		addr = nla_get_addr(tb[CTA_IP_V6_SRC], AF_INET6);
		if (addr == NULL)
			goto errout_errno;
		err = nfnl_ct_set_src(ct, repl, addr);
		nl_addr_put(addr);
		if (err < 0)
			goto errout;
	}
	if (tb[CTA_IP_V6_DST]) {
		addr = nla_get_addr(tb[CTA_IP_V6_DST], AF_INET6);
		if (addr == NULL)
			goto errout_errno;
		err = nfnl_ct_set_dst(ct, repl, addr);
		nl_addr_put(addr);
		if (err < 0)
			goto errout;
	}

	return 0;

errout_errno:
	return nl_get_errno();
errout:
	return err;
}

static int ct_parse_proto(struct nfnl_ct *ct, int repl, struct nlattr *attr)
{
	struct nlattr *tb[CTA_PROTO_MAX+1];
	int err;

	err = nla_parse_nested(tb, CTA_PROTO_MAX, attr, ct_proto_policy);
	if (err < 0)
		return err;

	if (!repl && tb[CTA_PROTO_NUM])
		nfnl_ct_set_proto(ct, nla_get_u8(tb[CTA_PROTO_NUM]));
	if (tb[CTA_PROTO_SRC_PORT])
		nfnl_ct_set_src_port(ct, repl,
				nla_get_u16(tb[CTA_PROTO_SRC_PORT]));
	if (tb[CTA_PROTO_DST_PORT])
		nfnl_ct_set_dst_port(ct, repl,
				nla_get_u16(tb[CTA_PROTO_DST_PORT]));
	if (tb[CTA_PROTO_ICMP_ID])
		nfnl_ct_set_icmp_id(ct, repl,
				nla_get_u16(tb[CTA_PROTO_ICMP_ID]));
	if (tb[CTA_PROTO_ICMP_TYPE])
		nfnl_ct_set_icmp_type(ct, repl,
				nla_get_u8(tb[CTA_PROTO_ICMP_TYPE]));
	if (tb[CTA_PROTO_ICMP_CODE])
		nfnl_ct_set_icmp_code(ct, repl,
				nla_get_u8(tb[CTA_PROTO_ICMP_CODE]));

	return 0;
}

static int ct_parse_tuple(struct nfnl_ct *ct, int repl, struct nlattr *attr)
{
	struct nlattr *tb[CTA_TUPLE_MAX+1];
	int err;

	err = nla_parse_nested(tb, CTA_TUPLE_MAX, attr, ct_tuple_policy);
	if (err < 0)
		return err;

	if (tb[CTA_TUPLE_IP]) {
		err = ct_parse_ip(ct, repl, tb[CTA_TUPLE_IP]);
		if (err < 0)
			return err;
	}

	if (tb[CTA_TUPLE_PROTO]) {
		err = ct_parse_proto(ct, repl, tb[CTA_TUPLE_PROTO]);
		if (err < 0)
			return err;
	}

	return 0;
}

static int ct_parse_protoinfo_tcp(struct nfnl_ct *ct, struct nlattr *attr)
{
	struct nlattr *tb[CTA_PROTOINFO_TCP_MAX+1];
	int err;

	err = nla_parse_nested(tb, CTA_PROTOINFO_TCP_MAX, attr,
			       ct_protoinfo_tcp_policy);
	if (err < 0)
		return err;

	if (tb[CTA_PROTOINFO_TCP_STATE])
		nfnl_ct_set_tcp_state(ct,
				nla_get_u8(tb[CTA_PROTOINFO_TCP_STATE]));

	return 0;
}

static int ct_parse_protoinfo(struct nfnl_ct *ct, struct nlattr *attr)
{
	struct nlattr *tb[CTA_PROTOINFO_MAX+1];
	int err;

	err = nla_parse_nested(tb, CTA_PROTOINFO_MAX, attr,
			       ct_protoinfo_policy);
	if (err < 0)
		return err;

	if (tb[CTA_PROTOINFO_TCP]) {
		err = ct_parse_protoinfo_tcp(ct, tb[CTA_PROTOINFO_TCP]);
		if (err < 0)
			return err;
	}

	return 0;
}

static int ct_parse_counters(struct nfnl_ct *ct, int repl, struct nlattr *attr)
{
	struct nlattr *tb[CTA_COUNTERS_MAX+1];
	int err;

	err = nla_parse_nested(tb, CTA_COUNTERS_MAX, attr, ct_counters_policy);
	if (err < 0)
		return err;

	if (tb[CTA_COUNTERS_PACKETS])
		nfnl_ct_set_packets(ct, repl,
			ntohll(nla_get_u64(tb[CTA_COUNTERS_PACKETS])));
	if (tb[CTA_COUNTERS32_PACKETS])
		nfnl_ct_set_packets(ct, repl,
			ntohl(nla_get_u32(tb[CTA_COUNTERS32_PACKETS])));
	if (tb[CTA_COUNTERS_BYTES])
		nfnl_ct_set_bytes(ct, repl,
			ntohll(nla_get_u64(tb[CTA_COUNTERS_BYTES])));
	if (tb[CTA_COUNTERS32_BYTES])
		nfnl_ct_set_bytes(ct, repl,
			ntohl(nla_get_u32(tb[CTA_COUNTERS32_BYTES])));

	return 0;
}

int nfnlmsg_ct_group(struct nlmsghdr *nlh)
{
	switch (nfnlmsg_subtype(nlh)) {
	case IPCTNL_MSG_CT_NEW:
		if (nlh->nlmsg_flags & (NLM_F_CREATE|NLM_F_EXCL))
			return NFNLGRP_CONNTRACK_NEW;
		else
			return NFNLGRP_CONNTRACK_UPDATE;
	case IPCTNL_MSG_CT_DELETE:
		return NFNLGRP_CONNTRACK_DESTROY;
	default:
		return NFNLGRP_NONE;
	}
}

struct nfnl_ct *nfnlmsg_ct_parse(struct nlmsghdr *nlh)
{
	struct nfnl_ct *ct;
	struct nlattr *tb[CTA_MAX+1];
	int err;

	ct = nfnl_ct_alloc();
	if (!ct)
		return NULL;

	ct->ce_msgtype = nlh->nlmsg_type;

	err = nlmsg_parse(nlh, sizeof(struct nfgenmsg), tb, CTA_MAX,
			  ct_policy);
	if (err < 0)
		goto errout;

	nfnl_ct_set_family(ct, nfnlmsg_family(nlh));

	if (tb[CTA_TUPLE_ORIG]) {
		err = ct_parse_tuple(ct, 0, tb[CTA_TUPLE_ORIG]);
		if (err < 0)
			goto errout;
	}
	if (tb[CTA_TUPLE_REPLY]) {
		err = ct_parse_tuple(ct, 1, tb[CTA_TUPLE_REPLY]);
		if (err < 0)
			goto errout;
	}

	if (tb[CTA_PROTOINFO]) {
		err = ct_parse_protoinfo(ct, tb[CTA_PROTOINFO]);
		if (err < 0)
			goto errout;
	}

	if (tb[CTA_STATUS])
		nfnl_ct_set_status(ct, ntohl(nla_get_u32(tb[CTA_STATUS])));
	if (tb[CTA_TIMEOUT])
		nfnl_ct_set_timeout(ct, ntohl(nla_get_u32(tb[CTA_TIMEOUT])));
	if (tb[CTA_MARK])
		nfnl_ct_set_mark(ct, ntohl(nla_get_u32(tb[CTA_MARK])));
	if (tb[CTA_USE])
		nfnl_ct_set_use(ct, ntohl(nla_get_u32(tb[CTA_USE])));
	if (tb[CTA_ID])
		nfnl_ct_set_id(ct, ntohl(nla_get_u32(tb[CTA_ID])));

	if (tb[CTA_COUNTERS_ORIG]) {
		err = ct_parse_counters(ct, 0, tb[CTA_COUNTERS_ORIG]);
		if (err < 0)
			goto errout;
	}

	if (tb[CTA_COUNTERS_REPLY]) {
		err = ct_parse_counters(ct, 1, tb[CTA_COUNTERS_REPLY]);
		if (err < 0)
			goto errout;
	}

	return ct;

errout:
	nfnl_ct_put(ct);
	return NULL;
}

static int ct_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			 struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	struct nfnl_ct *ct;
	int err;

	ct = nfnlmsg_ct_parse(nlh);
	if (ct == NULL)
		goto errout_errno;

	err = pp->pp_cb((struct nl_object *) ct, pp);
	if (err < 0)
		goto errout;

	err = P_ACCEPT;

errout:
	nfnl_ct_put(ct);
	return err;

errout_errno:
	err = nl_get_errno();
	goto errout;
}

int nfnl_ct_dump_request(struct nl_handle *h)
{
	return nfnl_send_simple(h, NFNL_SUBSYS_CTNETLINK, IPCTNL_MSG_CT_GET,
				NLM_F_DUMP, AF_UNSPEC, 0);
}

static int ct_request_update(struct nl_cache *c, struct nl_handle *h)
{
	return nfnl_ct_dump_request(h);
}

/**
 * @name Cache Management
 * @{
 */

/**
 * Build a conntrack cache holding all conntrack currently in the kernel
 * @arg handle		netlink handle
 *
 * Allocates a new cache, initializes it properly and updates it to
 * contain all conntracks currently in the kernel.
 *
 * @note The caller is responsible for destroying and freeing the
 *       cache after using it.
 * @return The cache or NULL if an error has occured.
 */
struct nl_cache *nfnl_ct_alloc_cache(struct nl_handle *handle)
{
	struct nl_cache *cache;

	cache = nl_cache_alloc(&nfnl_ct_ops);
	if (!cache)
		return NULL;

	if (handle && nl_cache_refill(handle, cache) < 0) {
		free(cache);
		return NULL;
	}

	return cache;
}

/** @} */

/**
 * @name Conntrack Addition
 * @{
 */

/** @} */

static struct nl_af_group ct_groups[] = {
	{ AF_UNSPEC, NFNLGRP_CONNTRACK_NEW },
	{ AF_UNSPEC, NFNLGRP_CONNTRACK_UPDATE },
	{ AF_UNSPEC, NFNLGRP_CONNTRACK_DESTROY },
	{ END_OF_GROUP_LIST },
};

#define NFNLMSG_CT_TYPE(type) NFNLMSG_TYPE(NFNL_SUBSYS_CTNETLINK, (type))
static struct nl_cache_ops nfnl_ct_ops = {
	.co_name		= "netfilter/ct",
	.co_hdrsize		= NFNL_HDRLEN,
	.co_msgtypes		= {
		{ NFNLMSG_CT_TYPE(IPCTNL_MSG_CT_NEW), NL_ACT_NEW, "new" },
		{ NFNLMSG_CT_TYPE(IPCTNL_MSG_CT_GET), NL_ACT_GET, "get" },
		{ NFNLMSG_CT_TYPE(IPCTNL_MSG_CT_DELETE), NL_ACT_DEL, "del" },
		END_OF_MSGTYPES_LIST,
	},
	.co_protocol		= NETLINK_NETFILTER,
	.co_groups		= ct_groups,
	.co_request_update	= ct_request_update,
	.co_msg_parser		= ct_msg_parser,
	.co_obj_ops		= &ct_obj_ops,
};

static void __init ct_init(void)
{
	nl_cache_mngt_register(&nfnl_ct_ops);
}

static void __exit ct_exit(void)
{
	nl_cache_mngt_unregister(&nfnl_ct_ops);
}

/** @} */
