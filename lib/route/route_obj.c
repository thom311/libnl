/*
 * lib/route/route_obj.c	Route Object
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup route
 * @defgroup route_obj Route Object
 *
 * @par Attributes
 * @code
 * Name                                           Default
 * -------------------------------------------------------------
 * routing table                                  RT_TABLE_MAIN
 * scope                                          RT_SCOPE_NOWHERE
 * tos                                            0
 * realms                                         0
 * protocol                                       RTPROT_STATIC
 * prio                                           0
 * family                                         AF_UNSPEC
 * type                                           RTN_UNICAST
 * oif                                            RTNL_LINK_NOT_FOUND
 * iif                                            NULL
 * mpalgo                                         IP_MP_ALG_NONE
 * @endcode
 *
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

/** @cond SKIP */
#define ROUTE_ATTR_FAMILY    0x000001
#define ROUTE_ATTR_TOS       0x000002
#define ROUTE_ATTR_TABLE     0x000004
#define ROUTE_ATTR_PROTOCOL  0x000008
#define ROUTE_ATTR_SCOPE     0x000010
#define ROUTE_ATTR_TYPE      0x000020
#define ROUTE_ATTR_FLAGS     0x000040
#define ROUTE_ATTR_DST       0x000080
#define ROUTE_ATTR_SRC       0x000100
#define ROUTE_ATTR_IIF       0x000200
#define ROUTE_ATTR_OIF       0x000400
#define ROUTE_ATTR_GATEWAY   0x000800
#define ROUTE_ATTR_PRIO      0x001000
#define ROUTE_ATTR_PREF_SRC  0x002000
#define ROUTE_ATTR_METRICS   0x004000
#define ROUTE_ATTR_MULTIPATH 0x008000
#define ROUTE_ATTR_REALMS    0x010000
#define ROUTE_ATTR_CACHEINFO 0x020000
#define ROUTE_ATTR_MP_ALGO   0x040000
/** @endcond */

static int route_dump_brief(struct nl_object *a, struct nl_dump_params *p);

static void route_constructor(struct nl_object *c)
{
	struct rtnl_route *r = (struct rtnl_route *) c;

	nl_init_list_head(&r->rt_nexthops);
}

static void route_free_data(struct nl_object *c)
{
	struct rtnl_route *r = (struct rtnl_route *) c;
	struct rtnl_nexthop *nh, *tmp;

	if (r == NULL)
		return;

	nl_addr_put(r->rt_dst);
	nl_addr_put(r->rt_src);
	nl_addr_put(r->rt_gateway);
	nl_addr_put(r->rt_pref_src);

	nl_list_for_each_entry_safe(nh, tmp, &r->rt_nexthops, rtnh_list) {
		rtnl_route_remove_nexthop(nh);
		rtnl_route_nh_free(nh);
	}
}

static int route_clone(struct nl_object *_dst, struct nl_object *_src)
{
	struct rtnl_route *dst = (struct rtnl_route *) _dst;
	struct rtnl_route *src = (struct rtnl_route *) _src;
	struct rtnl_nexthop *nh, *new;

	if (src->rt_dst)
		if (!(dst->rt_dst = nl_addr_clone(src->rt_dst)))
			goto errout;

	if (src->rt_src)
		if (!(dst->rt_src = nl_addr_clone(src->rt_src)))
			goto errout;

	if (src->rt_gateway)
		if (!(dst->rt_gateway = nl_addr_clone(src->rt_gateway)))
			goto errout;
	
	if (src->rt_pref_src)
		if (!(dst->rt_pref_src = nl_addr_clone(src->rt_pref_src)))
			goto errout;

	nl_init_list_head(&dst->rt_nexthops);
	nl_list_for_each_entry(nh, &src->rt_nexthops, rtnh_list) {
		new = rtnl_route_nh_clone(nh);
		if (!new)
			goto errout;

		rtnl_route_add_nexthop(dst, new);
	}

	return 0;
errout:
	return nl_get_errno();
}

static int route_dump_brief(struct nl_object *a, struct nl_dump_params *p)
{
	struct rtnl_route *r = (struct rtnl_route *) a;
	struct nl_cache *link_cache;
	char buf[64];

	link_cache = nl_cache_mngt_require("route/link");

	if (!(r->ce_mask & ROUTE_ATTR_DST) ||
	    nl_addr_get_len(r->rt_dst) == 0)
		dp_dump(p, "default ");
	else
		dp_dump(p, "%s ", nl_addr2str(r->rt_dst, buf, sizeof(buf)));

	if (r->ce_mask & ROUTE_ATTR_OIF) {
		if (link_cache)
			dp_dump(p, "dev %s ",
				rtnl_link_i2name(link_cache, r->rt_oif,
						 buf, sizeof(buf)));
		else
			dp_dump(p, "dev %d ", r->rt_oif);
	}

	if (r->ce_mask & ROUTE_ATTR_GATEWAY)
		dp_dump(p, "via %s ", nl_addr2str(r->rt_gateway, buf,
						  sizeof(buf)));
	else if (r->ce_mask & ROUTE_ATTR_MULTIPATH)
		dp_dump(p, "via nexthops ");

	if (r->ce_mask & ROUTE_ATTR_SCOPE)
		dp_dump(p, "scope %s ",
			rtnl_scope2str(r->rt_scope, buf, sizeof(buf)));

	if (r->ce_mask & ROUTE_ATTR_FLAGS && r->rt_flags) {
		int flags = r->rt_flags;

		dp_dump(p, "<");
		
#define PRINT_FLAG(f) if (flags & RTNH_F_##f) { \
		flags &= ~RTNH_F_##f; dp_dump(p, #f "%s", flags ? "," : ""); }
		PRINT_FLAG(DEAD);
		PRINT_FLAG(ONLINK);
		PRINT_FLAG(PERVASIVE);
#undef PRINT_FLAG

#define PRINT_FLAG(f) if (flags & RTM_F_##f) { \
		flags &= ~RTM_F_##f; dp_dump(p, #f "%s", flags ? "," : ""); }
		PRINT_FLAG(NOTIFY);
		PRINT_FLAG(CLONED);
		PRINT_FLAG(EQUALIZE);
		PRINT_FLAG(PREFIX);
#undef PRINT_FLAG

		dp_dump(p, ">");
	}

	dp_dump(p, "\n");

	return 1;
}

static int route_dump_full(struct nl_object *a, struct nl_dump_params *p)
{
	struct rtnl_route *r = (struct rtnl_route *) a;
	struct nl_cache *link_cache;
	char buf[128];
	int i, line;

	link_cache = nl_cache_mngt_require("route/link");
	line = route_dump_brief(a, p);

	if (r->ce_mask & ROUTE_ATTR_MULTIPATH) {
		struct rtnl_nexthop *nh;

		nl_list_for_each_entry(nh, &r->rt_nexthops, rtnh_list) {
			dp_dump_line(p, line++, "  via ");

			if (nh->rtnh_mask & NEXTHOP_HAS_GATEWAY)
				dp_dump(p, "%s ",
					nl_addr2str(nh->rtnh_gateway,
						    buf, sizeof(buf)));
			if (link_cache) {
				dp_dump(p, "dev %s ",
					rtnl_link_i2name(link_cache,
							 nh->rtnh_ifindex,
							 buf, sizeof(buf)));
			} else
				dp_dump(p, "dev %d ", nh->rtnh_ifindex);

			dp_dump(p, "weight %u <%s>\n", nh->rtnh_weight,
				rtnl_route_nh_flags2str(nh->rtnh_flags,
							buf, sizeof(buf)));
		}
	}

	dp_dump_line(p, line++, "  ");

	if (r->ce_mask & ROUTE_ATTR_PREF_SRC)
		dp_dump(p, "preferred-src %s ",
			nl_addr2str(r->rt_pref_src, buf, sizeof(buf)));

	if (r->ce_mask & ROUTE_ATTR_TABLE)
		dp_dump(p, "table %s ",
			rtnl_route_table2str(r->rt_table, buf, sizeof(buf)));

	if (r->ce_mask & ROUTE_ATTR_TYPE)
		dp_dump(p, "type %s ",
			nl_rtntype2str(r->rt_type, buf, sizeof(buf)));

	if (r->ce_mask & ROUTE_ATTR_PRIO)
		dp_dump(p, "metric %#x ", r->rt_prio);

	if (r->ce_mask & ROUTE_ATTR_FAMILY)
		dp_dump(p, "family %s ",
			nl_af2str(r->rt_family, buf, sizeof(buf)));

	if (r->ce_mask & ROUTE_ATTR_PROTOCOL)
		dp_dump(p, "protocol %s ",
			rtnl_route_proto2str(r->rt_protocol, buf, sizeof(buf)));

	dp_dump(p, "\n");

	if ((r->ce_mask & (ROUTE_ATTR_IIF | ROUTE_ATTR_SRC | ROUTE_ATTR_TOS |
			   ROUTE_ATTR_REALMS)) || 
	    ((r->ce_mask & ROUTE_ATTR_CACHEINFO) &&
	     r->rt_cacheinfo.rtci_error)) {
		dp_dump_line(p, line++, "  ");

		if (r->ce_mask & ROUTE_ATTR_IIF)
			dp_dump(p, "iif %s ", r->rt_iif);

		if (r->ce_mask & ROUTE_ATTR_SRC)
			dp_dump(p, "src %s ",
				nl_addr2str(r->rt_src, buf, sizeof(buf)));

		if (r->ce_mask & ROUTE_ATTR_TOS)
			dp_dump(p, "tos %#x ", r->rt_tos);

		if (r->ce_mask & ROUTE_ATTR_REALMS)
			dp_dump(p, "realm %04x:%04x ",
				RTNL_REALM_FROM(r->rt_realms),
				RTNL_REALM_TO(r->rt_realms));

		if ((r->ce_mask & ROUTE_ATTR_CACHEINFO) &&
		    r->rt_cacheinfo.rtci_error)
			dp_dump(p, "error %d (%s) ", r->rt_cacheinfo.rtci_error,
				strerror(-r->rt_cacheinfo.rtci_error));

		dp_dump(p, "\n");
	}

	if (r->ce_mask & ROUTE_ATTR_METRICS) {
		dp_dump_line(p, line++, "  ");
		for (i = 0; i < RTAX_MAX; i++)
			if (r->rt_metrics_mask & (1 << i))
				dp_dump(p, "%s %u ",
					rtnl_route_metric2str(i+1,
							      buf, sizeof(buf)),
					r->rt_metrics[i]);
		dp_dump(p, "\n");
	}

	return line;
}

static int route_dump_stats(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_route *route = (struct rtnl_route *) obj;
	int line;

	line = route_dump_full(obj, p);

	if (route->ce_mask & ROUTE_ATTR_CACHEINFO) {
		struct rtnl_rtcacheinfo *ci = &route->rt_cacheinfo;
		dp_dump_line(p, line++, "  used %u refcnt %u ",
			     ci->rtci_used, ci->rtci_clntref);
		dp_dump_line(p, line++, "last-use %us expires %us\n",
			     ci->rtci_last_use / nl_get_hz(),
			     ci->rtci_expires / nl_get_hz());
	}

	return line;
}

static int route_dump_xml(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_route *route = (struct rtnl_route *) obj;
	char buf[128];
	int line = 0;
	
	dp_dump_line(p, line++, "<route>\n");
	dp_dump_line(p, line++, "  <family>%s</family>\n",
		     nl_af2str(route->rt_family, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_DST)
		dp_dump_line(p, line++, "  <dst>%s</dst>\n",
			     nl_addr2str(route->rt_dst, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_SRC)
		dp_dump_line(p, line++, "  <src>%s</src>\n",
			     nl_addr2str(route->rt_src, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_GATEWAY)
		dp_dump_line(p, line++, "  <gateway>%s</gateway>\n",
			     nl_addr2str(route->rt_gateway, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_PREF_SRC)
		dp_dump_line(p, line++, "  <prefsrc>%s</prefsrc>\n",
			     nl_addr2str(route->rt_pref_src, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_IIF)
		dp_dump_line(p, line++, "  <iif>%s</iif>\n", route->rt_iif);

	if (route->ce_mask & ROUTE_ATTR_REALMS)
		dp_dump_line(p, line++, "  <realms>%u</realms>\n",
			     route->rt_realms);

	if (route->ce_mask & ROUTE_ATTR_TOS)
		dp_dump_line(p, line++, "  <tos>%u</tos>\n", route->rt_tos);

	if (route->ce_mask & ROUTE_ATTR_TABLE)
		dp_dump_line(p, line++, "  <table>%u</table>\n",
			     route->rt_table);

	if (route->ce_mask & ROUTE_ATTR_SCOPE)
		dp_dump_line(p, line++, "  <scope>%s</scope>\n",
			     rtnl_scope2str(route->rt_scope, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_PRIO)
		dp_dump_line(p, line++, "  <metric>%u</metric>\n",
			     route->rt_prio);

	if (route->ce_mask & ROUTE_ATTR_OIF) {
		struct nl_cache *link_cache;
	
		link_cache = nl_cache_mngt_require("route/link");
		if (link_cache)
			dp_dump_line(p, line++, "  <oif>%s</oif>\n",
				     rtnl_link_i2name(link_cache,
						      route->rt_oif,
						      buf, sizeof(buf)));
		else
			dp_dump_line(p, line++, "  <oif>%u</oif>\n",
				     route->rt_oif);
	}

	if (route->ce_mask & ROUTE_ATTR_TYPE)
		dp_dump_line(p, line++, "  <type>%s</type>\n",
			     nl_rtntype2str(route->rt_type, buf, sizeof(buf)));

	dp_dump_line(p, line++, "</route>\n");

#if 0
	uint8_t			rt_protocol;
	uint32_t		rt_flags;
	uint32_t		rt_metrics[RTAX_MAX];
	uint32_t		rt_metrics_mask;
	struct rtnl_nexthop *	rt_nexthops;
	struct rtnl_rtcacheinfo	rt_cacheinfo;
	uint32_t		rt_mp_algo;

#endif

	return line;
}

static int route_dump_env(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_route *route = (struct rtnl_route *) obj;
	char buf[128];
	int line = 0;

	dp_dump_line(p, line++, "ROUTE_FAMILY=%s\n",
		     nl_af2str(route->rt_family, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_DST)
		dp_dump_line(p, line++, "ROUTE_DST=%s\n",
			     nl_addr2str(route->rt_dst, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_SRC)
		dp_dump_line(p, line++, "ROUTE_SRC=%s\n",
			     nl_addr2str(route->rt_src, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_GATEWAY)
		dp_dump_line(p, line++, "ROUTE_GATEWAY=%s\n",
			     nl_addr2str(route->rt_gateway, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_PREF_SRC)
		dp_dump_line(p, line++, "ROUTE_PREFSRC=%s\n",
			     nl_addr2str(route->rt_pref_src, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_IIF)
		dp_dump_line(p, line++, "ROUTE_IIF=%s\n", route->rt_iif);

	if (route->ce_mask & ROUTE_ATTR_REALMS)
		dp_dump_line(p, line++, "ROUTE_REALM=%u\n",
			     route->rt_realms);

	if (route->ce_mask & ROUTE_ATTR_TOS)
		dp_dump_line(p, line++, "ROUTE_TOS=%u\n", route->rt_tos);

	if (route->ce_mask & ROUTE_ATTR_TABLE)
		dp_dump_line(p, line++, "ROUTE_TABLE=%u\n",
			     route->rt_table);

	if (route->ce_mask & ROUTE_ATTR_SCOPE)
		dp_dump_line(p, line++, "ROUTE_SCOPE=%s\n",
			     rtnl_scope2str(route->rt_scope, buf, sizeof(buf)));

	if (route->ce_mask & ROUTE_ATTR_PRIO)
		dp_dump_line(p, line++, "ROUTE_METRIC=%u\n",
			     route->rt_prio);

	if (route->ce_mask & ROUTE_ATTR_OIF) {
		struct nl_cache *link_cache;

		dp_dump_line(p, line++, "ROUTE_OIF_IFINDEX=%u\n",
			     route->rt_oif);

		link_cache = nl_cache_mngt_require("route/link");
		if (link_cache)
			dp_dump_line(p, line++, "ROUTE_OIF_IFNAME=%s\n",
				     rtnl_link_i2name(link_cache,
						      route->rt_oif,
						      buf, sizeof(buf)));
	}

	if (route->ce_mask & ROUTE_ATTR_TYPE)
		dp_dump_line(p, line++, "ROUTE_TYPE=%s\n",
			     nl_rtntype2str(route->rt_type, buf, sizeof(buf)));

	return line;
}

static int route_compare(struct nl_object *_a, struct nl_object *_b,
			uint32_t attrs, int flags)
{
	struct rtnl_route *a = (struct rtnl_route *) _a;
	struct rtnl_route *b = (struct rtnl_route *) _b;
	int diff = 0;

#define ROUTE_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, ROUTE_ATTR_##ATTR, a, b, EXPR)

	diff |= ROUTE_DIFF(FAMILY,	a->rt_family != b->rt_family);
	diff |= ROUTE_DIFF(TOS,		a->rt_tos != b->rt_tos);
	diff |= ROUTE_DIFF(TABLE,	a->rt_table != b->rt_table);
	diff |= ROUTE_DIFF(PROTOCOL,	a->rt_protocol != b->rt_protocol);
	diff |= ROUTE_DIFF(SCOPE,	a->rt_scope != b->rt_scope);
	diff |= ROUTE_DIFF(TYPE,	a->rt_type != b->rt_type);
	diff |= ROUTE_DIFF(OIF,		a->rt_oif != b->rt_oif);
	diff |= ROUTE_DIFF(PRIO,	a->rt_prio != b->rt_prio);
	diff |= ROUTE_DIFF(REALMS,	a->rt_realms != b->rt_realms);
	diff |= ROUTE_DIFF(MP_ALGO,	a->rt_mp_algo != b->rt_mp_algo);
	diff |= ROUTE_DIFF(DST,		nl_addr_cmp(a->rt_dst, b->rt_dst));
	diff |= ROUTE_DIFF(SRC,		nl_addr_cmp(a->rt_src, b->rt_src));
	diff |= ROUTE_DIFF(IIF,		strcmp(a->rt_iif, b->rt_iif));
	diff |= ROUTE_DIFF(PREF_SRC,	nl_addr_cmp(a->rt_pref_src,
						    b->rt_pref_src));
	diff |= ROUTE_DIFF(GATEWAY,	nl_addr_cmp(a->rt_gateway,
						    b->rt_gateway));

	/* FIXME: Compare metrics, multipath config */

	if (flags & LOOSE_FLAG_COMPARISON)
		diff |= ROUTE_DIFF(FLAGS,
			  (a->rt_flags ^ b->rt_flags) & b->rt_flag_mask);
	else
		diff |= ROUTE_DIFF(FLAGS, a->rt_flags != b->rt_flags);
	
#undef ROUTE_DIFF

	return diff;
}

static struct trans_tbl route_attrs[] = {
	__ADD(ROUTE_ATTR_FAMILY, family)
	__ADD(ROUTE_ATTR_TOS, tos)
	__ADD(ROUTE_ATTR_TABLE, table)
	__ADD(ROUTE_ATTR_PROTOCOL, protocol)
	__ADD(ROUTE_ATTR_SCOPE, scope)
	__ADD(ROUTE_ATTR_TYPE, type)
	__ADD(ROUTE_ATTR_FLAGS, flags)
	__ADD(ROUTE_ATTR_DST, dst)
	__ADD(ROUTE_ATTR_SRC, src)
	__ADD(ROUTE_ATTR_IIF, iif)
	__ADD(ROUTE_ATTR_OIF, oif)
	__ADD(ROUTE_ATTR_GATEWAY, gateway)
	__ADD(ROUTE_ATTR_PRIO, prio)
	__ADD(ROUTE_ATTR_PREF_SRC, pref_src)
	__ADD(ROUTE_ATTR_METRICS, metrics)
	__ADD(ROUTE_ATTR_MULTIPATH, multipath)
	__ADD(ROUTE_ATTR_REALMS, realms)
	__ADD(ROUTE_ATTR_CACHEINFO, cacheinfo)
	__ADD(ROUTE_ATTR_MP_ALGO, mp_algo)
};

static char *route_attrs2str(int attrs, char *buf, size_t len)
{
	return __flags2str(attrs, buf, len, route_attrs,
			   ARRAY_SIZE(route_attrs));
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct rtnl_route *rtnl_route_alloc(void)
{
	return (struct rtnl_route *) nl_object_alloc(&route_obj_ops);
}

void rtnl_route_get(struct rtnl_route *route)
{
	nl_object_get((struct nl_object *) route);
}

void rtnl_route_put(struct rtnl_route *route)
{
	nl_object_put((struct nl_object *) route);
}

/** @} */

/**
 * @name Attributes
 * @{
 */

void rtnl_route_set_table(struct rtnl_route *route, int table)
{
	route->rt_table = table;
	route->ce_mask |= ROUTE_ATTR_TABLE;
}

int rtnl_route_get_table(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_TABLE)
		return route->rt_table;
	else
		return RT_TABLE_MAIN;
}

void rtnl_route_set_scope(struct rtnl_route *route, int scope)
{
	route->rt_scope = scope;
	route->ce_mask |= ROUTE_ATTR_SCOPE;
}

int rtnl_route_get_scope(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_SCOPE)
		return route->rt_scope;
	else
		return RT_SCOPE_NOWHERE;
}

void rtnl_route_set_tos(struct rtnl_route *route, int tos)
{
	route->rt_tos = tos;
	route->ce_mask |= ROUTE_ATTR_TOS;
}

int rtnl_route_get_tos(struct rtnl_route *route)
{
	return route->rt_tos;
}

void rtnl_route_set_realms(struct rtnl_route *route, realm_t realms)
{
	route->rt_realms = realms;
	route->ce_mask |= ROUTE_ATTR_REALMS;
}

realm_t rtnl_route_get_realms(struct rtnl_route *route)
{
	return route->rt_realms;
}

void rtnl_route_set_protocol(struct rtnl_route *route, int proto)
{
	route->rt_protocol = proto;
	route->ce_mask |= ROUTE_ATTR_PROTOCOL;
}

int rtnl_route_get_protocol(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_PROTOCOL)
		return route->rt_protocol;
	else
		return RTPROT_STATIC;
}

void rtnl_route_set_prio(struct rtnl_route *route, int prio)
{
	route->rt_prio = prio;
	route->ce_mask |= ROUTE_ATTR_PRIO;
}

int rtnl_route_get_prio(struct rtnl_route *route)
{
	return route->rt_prio;
}

void rtnl_route_set_family(struct rtnl_route *route, int family)
{
	route->rt_family = family;
	route->ce_mask |= ROUTE_ATTR_FAMILY;
}

int rtnl_route_get_family(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_FAMILY)
		return route->rt_family;
	else
		return AF_UNSPEC;
}

int rtnl_route_set_dst(struct rtnl_route *route, struct nl_addr *addr)
{
	if (route->ce_mask & ROUTE_ATTR_FAMILY) {
		if (addr->a_family != route->rt_family)
			return nl_error(EINVAL, "Address family mismatch");
	} else
		route->rt_family = addr->a_family;

	if (route->rt_dst)
		nl_addr_put(route->rt_dst);

	nl_addr_get(addr);
	route->rt_dst = addr;
	
	route->ce_mask |= (ROUTE_ATTR_DST | ROUTE_ATTR_FAMILY);

	return 0;
}

struct nl_addr *rtnl_route_get_dst(struct rtnl_route *route)
{
	return route->rt_dst;
}

int rtnl_route_get_dst_len(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_DST)
		return nl_addr_get_prefixlen(route->rt_dst);
	else
		return 0;
}

int rtnl_route_set_src(struct rtnl_route *route, struct nl_addr *addr)
{
	if (route->ce_mask & ROUTE_ATTR_FAMILY) {
		if (addr->a_family != route->rt_family)
			return nl_error(EINVAL, "Address family mismatch");
	} else
		route->rt_family = addr->a_family;

	if (route->rt_src)
		nl_addr_put(route->rt_src);

	nl_addr_get(addr);
	route->rt_src = addr;
	route->ce_mask |= (ROUTE_ATTR_SRC | ROUTE_ATTR_FAMILY);

	return 0;
}

struct nl_addr *rtnl_route_get_src(struct rtnl_route *route)
{
	return route->rt_src;
}

int rtnl_route_get_src_len(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_SRC)
		return nl_addr_get_prefixlen(route->rt_src);
	else
		return 0;
}

int rtnl_route_set_gateway(struct rtnl_route *route, struct nl_addr *addr)
{
	if (route->ce_mask & ROUTE_ATTR_FAMILY) {
		if (addr->a_family != route->rt_family)
			return nl_error(EINVAL, "Address family mismatch");
	} else
		route->rt_family = addr->a_family;

	if (route->rt_gateway)
		nl_addr_put(route->rt_gateway);

	nl_addr_get(addr);
	route->rt_gateway = addr;
	route->ce_mask |= (ROUTE_ATTR_GATEWAY | ROUTE_ATTR_FAMILY);

	return 0;
}

struct nl_addr *rtnl_route_get_gateway(struct rtnl_route *route)
{
	return route->rt_gateway;
}

void rtnl_route_set_type(struct rtnl_route *route, int type)
{
	route->rt_type = type;
	route->ce_mask |= ROUTE_ATTR_TYPE;
}

int rtnl_route_get_type(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_TYPE)
		return route->rt_type;
	else
		return RTN_UNICAST;
}

void rtnl_route_set_flags(struct rtnl_route *route, unsigned int flags)
{
	route->rt_flag_mask |= flags;
	route->rt_flags |= flags;
	route->ce_mask |= ROUTE_ATTR_FLAGS;
}

void rtnl_route_unset_flags(struct rtnl_route *route, unsigned int flags)
{
	route->rt_flag_mask |= flags;
	route->rt_flags &= ~flags;
	route->ce_mask |= ROUTE_ATTR_FLAGS;
}

unsigned int rtnl_route_get_flags(struct rtnl_route *route)
{
	return route->rt_flags;
}

int rtnl_route_set_metric(struct rtnl_route *route, int metric, uint32_t value)
{
	if (metric > RTAX_MAX || metric < 1)
		return nl_error(EINVAL, "Metric out of range (1..%d)",
		    RTAX_MAX);

	route->rt_metrics[metric - 1] = value;
	route->rt_metrics_mask |= (1 << (metric - 1));

	return 0;
}

int rtnl_route_unset_metric(struct rtnl_route *route, int metric)
{
	if (metric > RTAX_MAX || metric < 1)
		return nl_error(EINVAL, "Metric out of range (1..%d)",
		    RTAX_MAX);

	route->rt_metrics_mask &= ~(1 << (metric - 1));

	return 0;
}

unsigned int rtnl_route_get_metric(struct rtnl_route *route, int metric)
{
	if (metric > RTAX_MAX || metric < 1)
		return UINT_MAX;

	if (!(route->rt_metrics_mask & (1 << (metric - 1))))
		return UINT_MAX;

	return route->rt_metrics[metric - 1];
}

int rtnl_route_set_pref_src(struct rtnl_route *route, struct nl_addr *addr)
{
	if (route->ce_mask & ROUTE_ATTR_FAMILY) {
		if (addr->a_family != route->rt_family)
			return nl_error(EINVAL, "Address family mismatch");
	} else
		route->rt_family = addr->a_family;

	if (route->rt_pref_src)
		nl_addr_put(route->rt_pref_src);

	nl_addr_get(addr);
	route->rt_pref_src = addr;
	route->ce_mask |= (ROUTE_ATTR_PREF_SRC | ROUTE_ATTR_FAMILY);

	return 0;
}

struct nl_addr *rtnl_route_get_pref_src(struct rtnl_route *route)
{
	return route->rt_pref_src;
}

void rtnl_route_set_oif(struct rtnl_route *route, int ifindex)
{
	route->rt_oif = ifindex;
	route->ce_mask |= ROUTE_ATTR_OIF;
}

int rtnl_route_get_oif(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_OIF)
		return route->rt_oif;
	else
		return RTNL_LINK_NOT_FOUND;
}

void rtnl_route_set_iif(struct rtnl_route *route, const char *name)
{
	strncpy(route->rt_iif, name, sizeof(route->rt_iif) - 1);
	route->ce_mask |= ROUTE_ATTR_IIF;
}

char *rtnl_route_get_iif(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_IIF)
		return route->rt_iif;
	else
		return NULL;
}

void rtnl_route_add_nexthop(struct rtnl_route *route, struct rtnl_nexthop *nh)
{
	nl_list_add_tail(&nh->rtnh_list, &route->rt_nexthops);
	route->ce_mask |= ROUTE_ATTR_MULTIPATH;
}

void rtnl_route_remove_nexthop(struct rtnl_nexthop *nh)
{
	nl_list_del(&nh->rtnh_list);
}

struct nl_list_head *rtnl_route_get_nexthops(struct rtnl_route *route)
{
	return &route->rt_nexthops;
}

void rtnl_route_set_cacheinfo(struct rtnl_route *route,
			      struct rtnl_rtcacheinfo *ci)
{
	memcpy(&route->rt_cacheinfo, ci, sizeof(*ci));
	route->ce_mask |= ROUTE_ATTR_CACHEINFO;
}

uint32_t rtnl_route_get_mp_algo(struct rtnl_route *route)
{
	if (route->ce_mask & ROUTE_ATTR_MP_ALGO)
		return route->rt_mp_algo;
	else
		return IP_MP_ALG_NONE;
}

void rtnl_route_set_mp_algo(struct rtnl_route *route, uint32_t algo)
{
	route->rt_mp_algo = algo;
	route->ce_mask |= ROUTE_ATTR_MP_ALGO;
}

/** @} */

struct nl_object_ops route_obj_ops = {
	.oo_name		= "route/route",
	.oo_size		= sizeof(struct rtnl_route),
	.oo_constructor		= route_constructor,
	.oo_free_data		= route_free_data,
	.oo_clone		= route_clone,
	.oo_dump[NL_DUMP_BRIEF]	= route_dump_brief,
	.oo_dump[NL_DUMP_FULL]	= route_dump_full,
	.oo_dump[NL_DUMP_STATS]	= route_dump_stats,
	.oo_dump[NL_DUMP_XML]	= route_dump_xml,
	.oo_dump[NL_DUMP_ENV]	= route_dump_env,
	.oo_compare		= route_compare,
	.oo_attrs2str		= route_attrs2str,
	.oo_id_attrs		= (ROUTE_ATTR_FAMILY | ROUTE_ATTR_TOS |
				   ROUTE_ATTR_TABLE | ROUTE_ATTR_DST),
};

/** @} */
