/*
 * lib/route/route.c	Routes
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup rtnl
 * @defgroup route Routing
 * @brief
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/utils.h>
#include <netlink/data.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/route.h>
#include <netlink/route/link.h>

static struct nl_cache_ops rtnl_route_ops;

static struct nla_policy route_policy[RTA_MAX+1] = {
	[RTA_IIF]	= { .type = NLA_STRING,
			    .maxlen = IFNAMSIZ, },
	[RTA_OIF]	= { .type = NLA_U32 },
	[RTA_PRIORITY]	= { .type = NLA_U32 },
	[RTA_FLOW]	= { .type = NLA_U32 },
	[RTA_MP_ALGO]	= { .type = NLA_U32 },
	[RTA_CACHEINFO]	= { .minlen = sizeof(struct rta_cacheinfo) },
	[RTA_METRICS]	= { .type = NLA_NESTED },
	[RTA_MULTIPATH]	= { .type = NLA_NESTED },
};

static void copy_cacheinfo_into_route(struct rta_cacheinfo *ci,
				      struct rtnl_route *route)
{
	struct rtnl_rtcacheinfo nci = {
		.rtci_clntref  = ci->rta_clntref,
		.rtci_last_use = ci->rta_lastuse,
		.rtci_expires  = ci->rta_expires,
		.rtci_error    = ci->rta_error,
		.rtci_used     = ci->rta_used,
		.rtci_id       = ci->rta_id,
		.rtci_ts       = ci->rta_ts,
		.rtci_tsage    = ci->rta_tsage,
	};

	rtnl_route_set_cacheinfo(route, &nci);
}

static int route_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			    struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	struct rtmsg *rtm;
	struct rtnl_route *route;
	struct nlattr *tb[RTA_MAX + 1];
	struct nl_addr *src = NULL, *dst = NULL, *addr;
	int err;

	route = rtnl_route_alloc();
	if (!route) {
		err = nl_errno(ENOMEM);
		goto errout;
	}

	route->ce_msgtype = nlh->nlmsg_type;

	err = nlmsg_parse(nlh, sizeof(struct rtmsg), tb, RTA_MAX,
			  route_policy);
	if (err < 0)
		goto errout;

	rtm = nlmsg_data(nlh);
	rtnl_route_set_family(route, rtm->rtm_family);
	rtnl_route_set_tos(route, rtm->rtm_tos);
	rtnl_route_set_table(route, rtm->rtm_table);
	rtnl_route_set_type(route, rtm->rtm_type);
	rtnl_route_set_scope(route, rtm->rtm_scope);
	rtnl_route_set_protocol(route, rtm->rtm_protocol);
	rtnl_route_set_flags(route, rtm->rtm_flags);

	if (tb[RTA_DST]) {
		dst = nla_get_addr(tb[RTA_DST], rtm->rtm_family);
		if (dst == NULL)
			goto errout_errno;
	} else {
		dst = nl_addr_alloc(0);
		nl_addr_set_family(dst, rtm->rtm_family);
	}

	nl_addr_set_prefixlen(dst, rtm->rtm_dst_len);
	err = rtnl_route_set_dst(route, dst);
	if (err < 0)
		goto errout;

	nl_addr_put(dst);

	if (tb[RTA_SRC]) {
		src = nla_get_addr(tb[RTA_SRC], rtm->rtm_family);
		if (src == NULL)
			goto errout_errno;
	} else if (rtm->rtm_src_len)
		src = nl_addr_alloc(0);

	if (src) {
		nl_addr_set_prefixlen(src, rtm->rtm_src_len);
		rtnl_route_set_src(route, src);
		nl_addr_put(src);
	}

	if (tb[RTA_IIF])
		rtnl_route_set_iif(route, nla_get_string(tb[RTA_IIF]));

	if (tb[RTA_OIF])
		rtnl_route_set_oif(route, nla_get_u32(tb[RTA_OIF]));

	if (tb[RTA_GATEWAY]) {
		addr = nla_get_addr(tb[RTA_GATEWAY], route->rt_family);
		if (addr == NULL)
			goto errout_errno;
		rtnl_route_set_gateway(route, addr);
		nl_addr_put(addr);
	}

	if (tb[RTA_PRIORITY])
		rtnl_route_set_prio(route, nla_get_u32(tb[RTA_PRIORITY]));

	if (tb[RTA_PREFSRC]) {
		addr = nla_get_addr(tb[RTA_PREFSRC], route->rt_family);
		if (addr == NULL)
			goto errout_errno;
		rtnl_route_set_pref_src(route, addr);
		nl_addr_put(addr);
	}

	if (tb[RTA_METRICS]) {
		struct nlattr *mtb[RTAX_MAX + 1];
		int i;

		err = nla_parse_nested(mtb, RTAX_MAX, tb[RTA_METRICS], NULL);
		if (err < 0)
			goto errout;

		for (i = 1; i <= RTAX_MAX; i++) {
			if (mtb[i] && nla_len(mtb[i]) >= sizeof(uint32_t)) {
				uint32_t m = nla_get_u32(mtb[i]);
				if (rtnl_route_set_metric(route, i, m) < 0)
					goto errout_errno;
			}
		}
	}

	if (tb[RTA_MULTIPATH]) {
		struct rtnl_nexthop *nh;
		struct rtnexthop *rtnh = nla_data(tb[RTA_MULTIPATH]);
		size_t tlen = nla_len(tb[RTA_MULTIPATH]);

		while (tlen >= sizeof(*rtnh) && tlen >= rtnh->rtnh_len) {
			nh = rtnl_route_nh_alloc();
			if (!nh)
				goto errout;

			rtnl_route_nh_set_weight(nh, rtnh->rtnh_hops);
			rtnl_route_nh_set_ifindex(nh, rtnh->rtnh_ifindex);
			rtnl_route_nh_set_flags(nh, rtnh->rtnh_flags);

			if (rtnh->rtnh_len > sizeof(*rtnh)) {
				struct nlattr *ntb[RTA_MAX + 1];
				nla_parse(ntb, RTA_MAX, (struct nlattr *)
					  RTNH_DATA(rtnh),
					  rtnh->rtnh_len - sizeof(*rtnh),
					  route_policy);

				if (ntb[RTA_GATEWAY]) {
					nh->rtnh_gateway = nla_get_addr(
							ntb[RTA_GATEWAY],
							route->rt_family);
					nh->rtnh_mask = NEXTHOP_HAS_GATEWAY;
				}
			}

			rtnl_route_add_nexthop(route, nh);
			tlen -= RTNH_ALIGN(rtnh->rtnh_len);
			rtnh = RTNH_NEXT(rtnh);
		}
	}

	if (tb[RTA_FLOW])
		rtnl_route_set_realms(route, nla_get_u32(tb[RTA_FLOW]));

	if (tb[RTA_CACHEINFO])
		copy_cacheinfo_into_route(nla_data(tb[RTA_CACHEINFO]), route);

	if (tb[RTA_MP_ALGO])
		rtnl_route_set_mp_algo(route, nla_get_u32(tb[RTA_MP_ALGO]));

	err = pp->pp_cb((struct nl_object *) route, pp);
	if (err < 0)
		goto errout;

	err = P_ACCEPT;

errout:
	rtnl_route_put(route);
	return err;

errout_errno:
	err = nl_get_errno();
	goto errout;
}

static int route_request_update(struct nl_cache *c, struct nl_handle *h)
{
	return nl_rtgen_request(h, RTM_GETROUTE, AF_UNSPEC, NLM_F_DUMP);
}

/**
 * @name Cache Management
 * @{
 */

/**
 * Build a route cache holding all routes currently configured in the kernel
 * @arg handle		netlink handle
 *
 * Allocates a new cache, initializes it properly and updates it to
 * contain all routes currently configured in the kernel.
 *
 * @note The caller is responsible for destroying and freeing the
 *       cache after using it.
 * @return The cache or NULL if an error has occured.
 */
struct nl_cache *rtnl_route_alloc_cache(struct nl_handle *handle)
{
	struct nl_cache *cache;

	cache = nl_cache_alloc(&rtnl_route_ops);
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
 * @name Route Addition
 * @{
 */

static struct nl_msg *build_route_msg(struct rtnl_route *tmpl, int cmd,
				      int flags)
{
	struct nl_msg *msg;
	struct nl_addr *addr;
	int scope, i, oif, nmetrics = 0;
	struct nlattr *metrics;
	struct rtmsg rtmsg = {
		.rtm_family = rtnl_route_get_family(tmpl),
		.rtm_dst_len = rtnl_route_get_dst_len(tmpl),
		.rtm_src_len = rtnl_route_get_src_len(tmpl),
		.rtm_tos = rtnl_route_get_tos(tmpl),
		.rtm_table = rtnl_route_get_table(tmpl),
		.rtm_type = rtnl_route_get_type(tmpl),
		.rtm_protocol = rtnl_route_get_protocol(tmpl),
		.rtm_flags = rtnl_route_get_flags(tmpl),
	};

	if (rtmsg.rtm_family == AF_UNSPEC) {
		nl_error(EINVAL, "Cannot build route message, address " \
				 "family is unknown.");
		return NULL;
	}

	scope = rtnl_route_get_scope(tmpl);
	if (scope == RT_SCOPE_NOWHERE) {
		if (rtmsg.rtm_type == RTN_LOCAL)
			scope = RT_SCOPE_HOST;
		else {
			/* XXX Change to UNIVERSE if gw || nexthops */
			scope = RT_SCOPE_LINK;
		}
	}

	rtmsg.rtm_scope = scope;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (msg == NULL)
		return NULL;

	if (nlmsg_append(msg, &rtmsg, sizeof(rtmsg), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	addr = rtnl_route_get_dst(tmpl);
	if (addr)
		NLA_PUT_ADDR(msg, RTA_DST, addr);

	addr = rtnl_route_get_src(tmpl);
	if (addr)
		NLA_PUT_ADDR(msg, RTA_SRC, addr);

	addr = rtnl_route_get_gateway(tmpl);
	if (addr)
		NLA_PUT_ADDR(msg, RTA_GATEWAY, addr);

	addr = rtnl_route_get_pref_src(tmpl);
	if (addr)
		NLA_PUT_ADDR(msg, RTA_PREFSRC, addr);

	NLA_PUT_U32(msg, RTA_PRIORITY, rtnl_route_get_prio(tmpl));

	oif = rtnl_route_get_oif(tmpl);
	if (oif != RTNL_LINK_NOT_FOUND)
		NLA_PUT_U32(msg, RTA_OIF, oif);

	for (i = 1; i <= RTAX_MAX; i++)
		if (rtnl_route_get_metric(tmpl, i) != UINT_MAX)
			nmetrics++;

	if (nmetrics > 0) {
		unsigned int val;

		metrics = nla_nest_start(msg, RTA_METRICS);
		if (metrics == NULL)
			goto nla_put_failure;

		for (i = 1; i <= RTAX_MAX; i++) {
			val = rtnl_route_get_metric(tmpl, i);
			if (val != UINT_MAX)
				NLA_PUT_U32(msg, i, val);
		}

		nla_nest_end(msg, metrics);
	}

#if 0
	RTA_IIF,
	RTA_MULTIPATH,
	RTA_PROTOINFO,
	RTA_FLOW,
	RTA_CACHEINFO,
	RTA_SESSION,
	RTA_MP_ALGO,
#endif

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

struct nl_msg *rtnl_route_build_add_request(struct rtnl_route *tmpl, int flags)
{
	return build_route_msg(tmpl, RTM_NEWROUTE, NLM_F_CREATE | flags);
}

int rtnl_route_add(struct nl_handle *handle, struct rtnl_route *route,
		   int flags)
{
	struct nl_msg *msg;
	int err;

	msg = rtnl_route_build_add_request(route, flags);
	if (!msg)
		return nl_get_errno();

	err = nl_send_auto_complete(handle, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(handle);
}

struct nl_msg *rtnl_route_build_del_request(struct rtnl_route *tmpl, int flags)
{
	return build_route_msg(tmpl, RTM_DELROUTE, flags);
}

int rtnl_route_del(struct nl_handle *handle, struct rtnl_route *route,
		   int flags)
{
	struct nl_msg *msg;
	int err;

	msg = rtnl_route_build_del_request(route, flags);
	if (!msg)
		return nl_get_errno();

	err = nl_send_auto_complete(handle, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(handle);
}

/** @} */

static struct nl_af_group route_groups[] = {
	{ AF_INET,	RTNLGRP_IPV4_ROUTE },
	{ AF_INET6,	RTNLGRP_IPV6_ROUTE },
	{ AF_DECnet,	RTNLGRP_DECnet_ROUTE },
	{ END_OF_GROUP_LIST },
};

static struct nl_cache_ops rtnl_route_ops = {
	.co_name		= "route/route",
	.co_hdrsize		= sizeof(struct rtmsg),
	.co_msgtypes		= {
					{ RTM_NEWROUTE, NL_ACT_NEW, "new" },
					{ RTM_DELROUTE, NL_ACT_DEL, "del" },
					{ RTM_GETROUTE, NL_ACT_GET, "get" },
					END_OF_MSGTYPES_LIST,
				  },
	.co_protocol		= NETLINK_ROUTE,
	.co_groups		= route_groups,
	.co_request_update	= route_request_update,
	.co_msg_parser		= route_msg_parser,
	.co_obj_ops		= &route_obj_ops,
};

static void __init route_init(void)
{
	nl_cache_mngt_register(&rtnl_route_ops);
}

static void __exit route_exit(void)
{
	nl_cache_mngt_unregister(&rtnl_route_ops);
}

/** @} */
