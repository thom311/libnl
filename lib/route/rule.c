/*
 * lib/route/rule.c          Routing Rules
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
 * @defgroup rule Routing Rules
 * @brief
 * @{
 */

#include <netlink-local.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/rtnl.h>
#include <netlink/route/rule.h>
#include <inttypes.h>

/** @cond SKIP */
#define RULE_ATTR_FAMILY	0x0001
#define RULE_ATTR_PRIO		0x0002
#define RULE_ATTR_MARK		0x0004
#define RULE_ATTR_IIF		0x0008
#define RULE_ATTR_REALMS	0x0010
#define RULE_ATTR_SRC		0x0020
#define RULE_ATTR_DST		0x0040
#define RULE_ATTR_DSFIELD	0x0080
#define RULE_ATTR_TABLE		0x0100
#define RULE_ATTR_TYPE		0x0200
#define RULE_ATTR_SRC_LEN	0x0400
#define RULE_ATTR_DST_LEN	0x0800
#define RULE_ATTR_SRCMAP	0x1000

static struct nl_cache_ops rtnl_rule_ops;
static struct nl_object_ops rule_obj_ops;
/** @endcond */

static void rule_free_data(struct nl_object *c)
{
	struct rtnl_rule *rule = nl_object_priv(c);

	if (!rule)
		return;

	nl_addr_put(rule->r_src);
	nl_addr_put(rule->r_dst);
}

static int rule_clone(struct nl_object *_dst, struct nl_object *_src)
{
	struct rtnl_rule *dst = nl_object_priv(_dst);
	struct rtnl_rule *src = nl_object_priv(_src);

	if (src->r_src)
		if (!(dst->r_src = nl_addr_clone(src->r_src)))
			goto errout;

	if (src->r_dst)
		if (!(dst->r_dst = nl_addr_clone(src->r_dst)))
			goto errout;

	return 0;
errout:
	return nl_get_errno();
}

static struct nla_policy rule_policy[RTA_MAX+1] = {
	[RTA_PRIORITY]	= { .type = NLA_U32 },
	[RTA_FLOW]	= { .type = NLA_U32 },
	[RTA_PROTOINFO]	= { .type = NLA_U32 },
	[RTA_IIF]	= { .type = NLA_STRING,
			    .maxlen = IFNAMSIZ, },
};

static int rule_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			   struct nlmsghdr *n, struct nl_parser_param *pp)
{
	struct rtnl_rule *rule;
	struct rtmsg *r;
	struct nlattr *tb[RTA_MAX+1];
	int err = 1;

	rule = rtnl_rule_alloc();
	if (!rule) {
		err = nl_errno(ENOMEM);
		goto errout;
	}

	rule->ce_msgtype = n->nlmsg_type;
	r = nlmsg_data(n);

	err = nlmsg_parse(n, sizeof(*r), tb, RTA_MAX, rule_policy);
	if (err < 0)
		goto errout;

	rule->r_family = r->rtm_family;
	rule->r_type = r->rtm_type;
	rule->r_dsfield = r->rtm_tos;
	rule->r_src_len = r->rtm_src_len;
	rule->r_dst_len = r->rtm_dst_len;
	rule->r_table = r->rtm_table;
	rule->ce_mask = (RULE_ATTR_FAMILY | RULE_ATTR_TYPE | RULE_ATTR_DSFIELD |
			 RULE_ATTR_SRC_LEN | RULE_ATTR_DST_LEN |RULE_ATTR_TYPE);

	if (tb[RTA_PRIORITY]) {
		rule->r_prio = nla_get_u32(tb[RTA_PRIORITY]);
		rule->ce_mask |= RULE_ATTR_PRIO;
	}

	if (tb[RTA_SRC]) {
		rule->r_src = nla_get_addr(tb[RTA_SRC], r->rtm_family);
		if (!rule->r_src) {
			err = nl_errno(ENOMEM);
			goto errout;
		}
		nl_addr_set_prefixlen(rule->r_src, r->rtm_src_len);
		rule->ce_mask |= RULE_ATTR_SRC;
	}

	if (tb[RTA_DST]) {
		rule->r_dst = nla_get_addr(tb[RTA_DST], r->rtm_family);
		if (!rule->r_dst) {
			err = nl_errno(ENOMEM);
			goto errout;
		}
		nl_addr_set_prefixlen(rule->r_dst, r->rtm_dst_len);
		rule->ce_mask |= RULE_ATTR_DST;
	}

	if (tb[RTA_PROTOINFO]) {
		rule->r_mark = nla_get_u32(tb[RTA_PROTOINFO]);
		rule->ce_mask |= RULE_ATTR_MARK;
	}

	if (tb[RTA_IIF]) {
		nla_strlcpy(rule->r_iif, tb[RTA_IIF], IFNAMSIZ);
		rule->ce_mask |= RULE_ATTR_IIF;
	}

	if (tb[RTA_FLOW]) {
		rule->r_realms = nla_get_u32(tb[RTA_FLOW]);
		rule->ce_mask |= RULE_ATTR_REALMS;
	}

	if (tb[RTA_GATEWAY]) {
		rule->r_srcmap = nla_get_addr(tb[RTA_GATEWAY], r->rtm_family);
		if (!rule->r_srcmap) {
			err = nl_errno(ENOMEM);
			goto errout;
		}
		rule->ce_mask |= RULE_ATTR_SRCMAP;
	}

	err = pp->pp_cb((struct nl_object *) rule, pp);
	if (err < 0)
		goto errout;

	err = P_ACCEPT;

errout:
	rtnl_rule_put(rule);
	return err;
}

static int rule_request_update(struct nl_cache *c, struct nl_handle *h)
{
	return nl_rtgen_request(h, RTM_GETRULE, AF_UNSPEC, NLM_F_DUMP);
}

static int rule_dump_brief(struct nl_object *o, struct nl_dump_params *p)
{
	struct rtnl_rule *r = (struct rtnl_rule *) o;
	char buf[128];

	if (r->ce_mask & RULE_ATTR_PRIO)
		dp_dump(p, "%d:\t", r->r_prio);
	else
		dp_dump(p, "0:\t");

	if (r->ce_mask & RULE_ATTR_SRC)
		dp_dump(p, "from %s ",
			nl_addr2str(r->r_src, buf, sizeof(buf)));
	else if (r->ce_mask & RULE_ATTR_SRC_LEN && r->r_src_len)
		dp_dump(p, "from 0/%d ", r->r_src_len);

	if (r->ce_mask & RULE_ATTR_DST)
		dp_dump(p, "to %s ",
			nl_addr2str(r->r_dst, buf, sizeof(buf)));
	else if (r->ce_mask & RULE_ATTR_DST_LEN && r->r_dst_len)
		dp_dump(p, "to 0/%d ", r->r_dst_len);

	if (r->ce_mask & RULE_ATTR_DSFIELD && r->r_dsfield)
		dp_dump(p, "tos %d ", r->r_dsfield);

	if (r->ce_mask & RULE_ATTR_MARK)
		dp_dump(p, "mark %" PRIx64 , r->r_mark);

	if (r->ce_mask & RULE_ATTR_IIF)
		dp_dump(p, "iif %s ", r->r_iif);

	if (r->ce_mask & RULE_ATTR_TABLE)
		dp_dump(p, "lookup %s ",
			rtnl_route_table2str(r->r_table, buf, sizeof(buf)));

	if (r->ce_mask & RULE_ATTR_REALMS)
		dp_dump(p, "realms %s ",
			rtnl_realms2str(r->r_realms, buf, sizeof(buf)));

	dp_dump(p, "action %s\n",
		nl_rtntype2str(r->r_type, buf, sizeof(buf)));

	return 1;
}

static int rule_dump_full(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_rule *rule = (struct rtnl_rule *) obj;
	char buf[128];
	int line;

	line = rule_dump_brief(obj, p);

	dp_dump_line(p, line++, "  family %s",
		     nl_af2str(rule->r_family, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_SRCMAP)
		dp_dump(p, " srcmap %s",
			nl_addr2str(rule->r_srcmap, buf, sizeof(buf)));

	dp_dump(p, "\n");

	return line;
}

static int rule_dump_stats(struct nl_object *obj, struct nl_dump_params *p)
{
	return rule_dump_full(obj, p);
}

static int rule_dump_xml(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_rule *rule = (struct rtnl_rule *) obj;
	char buf[128];
	int line = 0;
	
	dp_dump_line(p, line++, "<rule>\n");

	dp_dump_line(p, line++, "  <priority>%u</priority>\n",
		     rule->r_prio);
	dp_dump_line(p, line++, "  <family>%s</family>\n",
		     nl_af2str(rule->r_family, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_DST)
		dp_dump_line(p, line++, "  <dst>%s</dst>\n",
			     nl_addr2str(rule->r_dst, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_DST_LEN)
		dp_dump_line(p, line++, "  <dstlen>%u</dstlen>\n",
			     rule->r_dst_len);

	if (rule->ce_mask & RULE_ATTR_SRC)
		dp_dump_line(p, line++, "  <src>%s</src>\n",
			     nl_addr2str(rule->r_src, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_SRC_LEN)
		dp_dump_line(p, line++, "  <srclen>%u</srclen>\n",
			     rule->r_src_len);

	if (rule->ce_mask & RULE_ATTR_IIF)
		dp_dump_line(p, line++, "  <iif>%s</iif>\n", rule->r_iif);

	if (rule->ce_mask & RULE_ATTR_TABLE)
		dp_dump_line(p, line++, "  <table>%u</table>\n",
			     rule->r_table);

	if (rule->ce_mask & RULE_ATTR_REALMS)
		dp_dump_line(p, line++, "  <realms>%u</realms>\n",
			     rule->r_realms);

	if (rule->ce_mask & RULE_ATTR_MARK)
		dp_dump_line(p, line++, "  <mark>%" PRIx64 "</mark>\n",
			     rule->r_mark);

	if (rule->ce_mask & RULE_ATTR_DSFIELD)
		dp_dump_line(p, line++, "  <dsfield>%u</dsfield>\n",
			     rule->r_dsfield);

	if (rule->ce_mask & RULE_ATTR_TYPE)
		dp_dump_line(p, line++, "<type>%s</type>\n",
			     nl_rtntype2str(rule->r_type, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_SRCMAP)
		dp_dump_line(p, line++, "<srcmap>%s</srcmap>\n",
			     nl_addr2str(rule->r_srcmap, buf, sizeof(buf)));

	dp_dump_line(p, line++, "</rule>\n");

	return line;
}

static int rule_dump_env(struct nl_object *obj, struct nl_dump_params *p)
{
	struct rtnl_rule *rule = (struct rtnl_rule *) obj;
	char buf[128];
	int line = 0;

	dp_dump_line(p, line++, "RULE_PRIORITY=%u\n",
		     rule->r_prio);
	dp_dump_line(p, line++, "RULE_FAMILY=%s\n",
		     nl_af2str(rule->r_family, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_DST)
		dp_dump_line(p, line++, "RULE_DST=%s\n",
			     nl_addr2str(rule->r_dst, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_DST_LEN)
		dp_dump_line(p, line++, "RULE_DSTLEN=%u\n",
			     rule->r_dst_len);

	if (rule->ce_mask & RULE_ATTR_SRC)
		dp_dump_line(p, line++, "RULE_SRC=%s\n",
			     nl_addr2str(rule->r_src, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_SRC_LEN)
		dp_dump_line(p, line++, "RULE_SRCLEN=%u\n",
			     rule->r_src_len);

	if (rule->ce_mask & RULE_ATTR_IIF)
		dp_dump_line(p, line++, "RULE_IIF=%s\n", rule->r_iif);

	if (rule->ce_mask & RULE_ATTR_TABLE)
		dp_dump_line(p, line++, "RULE_TABLE=%u\n",
			     rule->r_table);

	if (rule->ce_mask & RULE_ATTR_REALMS)
		dp_dump_line(p, line++, "RULE_REALM=%u\n",
			     rule->r_realms);

	if (rule->ce_mask & RULE_ATTR_MARK)
		dp_dump_line(p, line++, "RULE_MARK=0x%" PRIx64 "\n",
			     rule->r_mark);

	if (rule->ce_mask & RULE_ATTR_DSFIELD)
		dp_dump_line(p, line++, "RULE_DSFIELD=%u\n",
			     rule->r_dsfield);

	if (rule->ce_mask & RULE_ATTR_TYPE)
		dp_dump_line(p, line++, "RULE_TYPE=%s\n",
			     nl_rtntype2str(rule->r_type, buf, sizeof(buf)));

	if (rule->ce_mask & RULE_ATTR_SRCMAP)
		dp_dump_line(p, line++, "RULE_SRCMAP=%s\n",
			     nl_addr2str(rule->r_srcmap, buf, sizeof(buf)));

	return line;
}

static int rule_compare(struct nl_object *_a, struct nl_object *_b,
			uint32_t attrs, int flags)
{
	struct rtnl_rule *a = (struct rtnl_rule *) _a;
	struct rtnl_rule *b = (struct rtnl_rule *) _b;
	int diff = 0;

#define RULE_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, RULE_ATTR_##ATTR, a, b, EXPR)

	diff |= RULE_DIFF(FAMILY,	a->r_family != b->r_family);
	diff |= RULE_DIFF(TABLE,	a->r_table != b->r_table);
	diff |= RULE_DIFF(REALMS,	a->r_realms != b->r_realms);
	diff |= RULE_DIFF(DSFIELD,	a->r_dsfield != b->r_dsfield);
	diff |= RULE_DIFF(TYPE,		a->r_type != b->r_type);
	diff |= RULE_DIFF(PRIO,		a->r_prio != b->r_prio);
	diff |= RULE_DIFF(MARK,		a->r_mark != b->r_mark);
	diff |= RULE_DIFF(SRC_LEN,	a->r_src_len != b->r_src_len);
	diff |= RULE_DIFF(DST_LEN,	a->r_dst_len != b->r_dst_len);
	diff |= RULE_DIFF(SRC,		nl_addr_cmp(a->r_src, b->r_src));
	diff |= RULE_DIFF(DST,		nl_addr_cmp(a->r_dst, b->r_dst));
	diff |= RULE_DIFF(IIF,		strcmp(a->r_iif, b->r_iif));
	
#undef RULE_DIFF

	return diff;
}

static struct trans_tbl rule_attrs[] = {
	__ADD(RULE_ATTR_FAMILY, family)
	__ADD(RULE_ATTR_PRIO, prio)
	__ADD(RULE_ATTR_MARK, mark)
	__ADD(RULE_ATTR_IIF, iif)
	__ADD(RULE_ATTR_REALMS, realms)
	__ADD(RULE_ATTR_SRC, src)
	__ADD(RULE_ATTR_DST, dst)
	__ADD(RULE_ATTR_DSFIELD, dsfield)
	__ADD(RULE_ATTR_TABLE, table)
	__ADD(RULE_ATTR_TYPE, type)
	__ADD(RULE_ATTR_SRC_LEN, src_len)
	__ADD(RULE_ATTR_DST_LEN, dst_len)
	__ADD(RULE_ATTR_SRCMAP, srcmap)
};

static char *rule_attrs2str(int attrs, char *buf, size_t len)
{
	return __flags2str(attrs, buf, len, rule_attrs,
			   ARRAY_SIZE(rule_attrs));
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct rtnl_rule *rtnl_rule_alloc(void)
{
	return (struct rtnl_rule *) nl_object_alloc(&rule_obj_ops);
}

void rtnl_rule_put(struct rtnl_rule *rule)
{
	nl_object_put((struct nl_object *) rule);
}

/** @} */

/**
 * @name Cache Management
 * @{
 */

/**
 * Build a rule cache including all rules of the specified family currently configured in the kernel.
 * @arg handle		netlink handle
 * @arg family		address family
 *
 * Allocates a new rule cache, initializes it properly and updates it
 * to include all rules of the specified address family currently
 * configured in the kernel.
 *
 * @note The caller is responsible for destroying and freeing the
 *       cache after using it. (nl_cache_destroy_and_free())
 * @return The new cache or NULL if an error occured.
 */
struct nl_cache * rtnl_rule_alloc_cache_by_family(struct nl_handle *handle,
						  int family)
{
	struct nl_cache * cache;

	cache = nl_cache_alloc(&rtnl_rule_ops);
	if (cache == NULL)
		return NULL;

	/* XXX RULE_CACHE_FAMILY(cache) = family; */

	if (handle && nl_cache_refill(handle, cache) < 0) {
		free(cache);
		return NULL;
	}

	return cache;
}

/**
 * Build a rule cache including all rules currently configured in the kernel.
 * @arg handle		netlink handle
 *
 * Allocates a new rule cache, initializes it properly and updates it
 * to include all rules currently configured in the kernel.
 *
 * @note The caller is responsible for destroying and freeing the
 *       cache after using it. (nl_cache_destroy_and_free())
 * @return The new cache or NULL if an error occured.
 */
struct nl_cache * rtnl_rule_alloc_cache(struct nl_handle *handle)
{
	return rtnl_rule_alloc_cache_by_family(handle, AF_UNSPEC);
}

/** @} */

/**
 * @name Rule Addition
 * @{
 */

static struct nl_msg *build_rule_msg(struct rtnl_rule *tmpl, int cmd, int flags)
{
	struct nl_msg *msg;
	struct rtmsg rtm = {
		.rtm_type = RTN_UNSPEC
	};

	if (cmd == RTM_NEWRULE)
		rtm.rtm_type = RTN_UNICAST;
		
	if (tmpl->ce_mask & RULE_ATTR_FAMILY)
		rtm.rtm_family = tmpl->r_family;

	if (tmpl->ce_mask & RULE_ATTR_TABLE)
		rtm.rtm_table = tmpl->r_table;

	if (tmpl->ce_mask & RULE_ATTR_DSFIELD)
		rtm.rtm_tos = tmpl->r_dsfield;

	if (tmpl->ce_mask & RULE_ATTR_TYPE)
		rtm.rtm_type = tmpl->r_type;

	if (tmpl->ce_mask & RULE_ATTR_SRC_LEN)
		rtm.rtm_src_len = tmpl->r_src_len;

	if (tmpl->ce_mask & RULE_ATTR_DST_LEN)
		rtm.rtm_dst_len = tmpl->r_dst_len;

	msg = nlmsg_alloc_simple(cmd, flags);
	if (!msg)
		goto nla_put_failure;

	if (nlmsg_append(msg, &rtm, sizeof(rtm), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure;

	if (tmpl->ce_mask & RULE_ATTR_SRC)
		NLA_PUT_ADDR(msg, RTA_SRC, tmpl->r_src);

	if (tmpl->ce_mask & RULE_ATTR_DST)
		NLA_PUT_ADDR(msg, RTA_DST, tmpl->r_dst);

	if (tmpl->ce_mask & RULE_ATTR_PRIO)
		NLA_PUT_U32(msg, RTA_PRIORITY, tmpl->r_prio);

	if (tmpl->ce_mask & RULE_ATTR_MARK)
		NLA_PUT_U32(msg, RTA_PROTOINFO, tmpl->r_mark);

	if (tmpl->ce_mask & RULE_ATTR_REALMS)
		NLA_PUT_U32(msg, RTA_FLOW, tmpl->r_realms);

	if (tmpl->ce_mask & RULE_ATTR_IIF)
		NLA_PUT_STRING(msg, RTA_IIF, tmpl->r_iif);

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

/**
 * Build netlink request message to add a new rule
 * @arg tmpl		template with data of new rule
 * @arg flags		additional netlink message flags
 *
 * Builds a new netlink message requesting a addition of a new
 * rule. The netlink message header isn't fully equipped with
 * all relevant fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed. \a tmpl must contain the attributes of the new
 * address set via \c rtnl_rule_set_* functions.
 * 
 * @return The netlink message
 */
struct nl_msg *rtnl_rule_build_add_request(struct rtnl_rule *tmpl, int flags)
{
	return build_rule_msg(tmpl, RTM_NEWRULE, NLM_F_CREATE | flags);
}

/**
 * Add a new rule
 * @arg handle		netlink handle
 * @arg tmpl		template with requested changes
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_rule_build_add_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been fullfilled.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_rule_add(struct nl_handle *handle, struct rtnl_rule *tmpl, int flags)
{
	int err;
	struct nl_msg *msg;
	
	msg = rtnl_rule_build_add_request(tmpl, flags);
	if (!msg)
		return nl_errno(ENOMEM);

	err = nl_send_auto_complete(handle, msg);
	if (err < 0)
		return err;

	nlmsg_free(msg);
	return nl_wait_for_ack(handle);
}

/** @} */

/**
 * @name Rule Deletion
 * @{
 */

/**
 * Build a netlink request message to delete a rule
 * @arg rule		rule to delete
 * @arg flags		additional netlink message flags
 *
 * Builds a new netlink message requesting a deletion of a rule.
 * The netlink message header isn't fully equipped with all relevant
 * fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed. \a rule must point to an existing
 * address.
 *
 * @return The netlink message
 */
struct nl_msg *rtnl_rule_build_delete_request(struct rtnl_rule *rule, int flags)
{
	return build_rule_msg(rule, RTM_DELRULE, flags);
}

/**
 * Delete a rule
 * @arg handle		netlink handle
 * @arg rule		rule to delete
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_rule_build_delete_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been fullfilled.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_rule_delete(struct nl_handle *handle, struct rtnl_rule *rule,
		     int flags)
{
	int err;
	struct nl_msg *msg;
	
	msg = rtnl_rule_build_delete_request(rule, flags);
	if (!msg)
		return nl_errno(ENOMEM);

	err = nl_send_auto_complete(handle, msg);
	if (err < 0)
		return err;

	nlmsg_free(msg);
	return nl_wait_for_ack(handle);
}

/** @} */

/**
 * @name Attribute Modification
 * @{
 */

void rtnl_rule_set_family(struct rtnl_rule *rule, int family)
{
	rule->r_family = family;
	rule->ce_mask |= RULE_ATTR_FAMILY;
}

int rtnl_rule_get_family(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_FAMILY)
		return rule->r_family;
	else
		return AF_UNSPEC;
}

void rtnl_rule_set_prio(struct rtnl_rule *rule, int prio)
{
	rule->r_prio = prio;
	rule->ce_mask |= RULE_ATTR_PRIO;
}

int rtnl_rule_get_prio(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_PRIO)
		return rule->r_prio;
	else
		return -1;
}

void rtnl_rule_set_mark(struct rtnl_rule *rule, uint64_t mark)
{
	rule->r_mark = mark;
	rule->ce_mask |= RULE_ATTR_MARK;
}

uint64_t rtnl_rule_get_mark(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_MARK)
		return rule->r_mark;
	else
		return UINT_LEAST64_MAX;
}

void rtnl_rule_set_table(struct rtnl_rule *rule, int table)
{
	rule->r_table = table;
	rule->ce_mask |= RULE_ATTR_TABLE;
}

int rtnl_rule_get_table(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_TABLE)
		return rule->r_table;
	else
		return -1;
}

void rtnl_rule_set_dsfield(struct rtnl_rule *rule, int dsfield)
{
	rule->r_dsfield = dsfield;
	rule->ce_mask |= RULE_ATTR_DSFIELD;
}

int rtnl_rule_get_dsfield(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_DSFIELD)
		return rule->r_dsfield;
	else
		return -1;
}

void rtnl_rule_set_src_len(struct rtnl_rule *rule, int len)
{
	rule->r_src_len = len;
	if (rule->ce_mask & RULE_ATTR_SRC)
		nl_addr_set_prefixlen(rule->r_src, len);
	rule->ce_mask |= RULE_ATTR_SRC_LEN;
}

int rtnl_rule_get_src_len(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_SRC_LEN)
		return rule->r_src_len;
	else
		return -1;
}

void rtnl_rule_set_dst_len(struct rtnl_rule *rule, int len)
{
	rule->r_dst_len = len;
	if (rule->ce_mask & RULE_ATTR_DST)
		nl_addr_set_prefixlen(rule->r_dst, len);
	rule->ce_mask |= RULE_ATTR_DST_LEN;
}

int rtnl_rule_get_dst_len(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_DST_LEN)
		return rule->r_dst_len;
	else
		return -1;
}

static inline int __assign_addr(struct rtnl_rule *rule, struct nl_addr **pos,
			        struct nl_addr *new, uint8_t *len, int flag)
{
	if (rule->ce_mask & RULE_ATTR_FAMILY) {
		if (new->a_family != rule->r_family)
			return nl_error(EINVAL, "Address family mismatch");
	} else
		rule->r_family = new->a_family;

	if (*pos)
		nl_addr_put(*pos);

	nl_addr_get(new);
	*pos = new;
	*len = nl_addr_get_prefixlen(new);

	rule->ce_mask |= (flag | RULE_ATTR_FAMILY);

	return 0;
}

int rtnl_rule_set_src(struct rtnl_rule *rule, struct nl_addr *src)
{
	return __assign_addr(rule, &rule->r_src, src, &rule->r_src_len,
			     RULE_ATTR_SRC | RULE_ATTR_SRC_LEN);
}

struct nl_addr *rtnl_rule_get_src(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_SRC)
		return rule->r_src;
	else
		return NULL;
}

int rtnl_rule_set_dst(struct rtnl_rule *rule, struct nl_addr *dst)
{
	return __assign_addr(rule, &rule->r_dst, dst, &rule->r_dst_len,
			     RULE_ATTR_DST | RULE_ATTR_DST_LEN);
}

struct nl_addr *rtnl_rule_get_dst(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_DST)
		return rule->r_dst;
	else
		return NULL;
}

int rtnl_rule_set_iif(struct rtnl_rule *rule, const char *dev)
{
	if (strlen(dev) > IFNAMSIZ-1)
		return nl_errno(ERANGE);

	strcpy(rule->r_iif, dev);
	rule->ce_mask |= RULE_ATTR_IIF;
	return 0;
}

char *rtnl_rule_get_iif(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_IIF)
		return rule->r_iif;
	else
		return NULL;
}

void rtnl_rule_set_action(struct rtnl_rule *rule, int type)
{
	rule->r_type = type;
	rule->ce_mask |= RULE_ATTR_TYPE;
}

int rtnl_rule_get_action(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_TYPE)
		return rule->r_type;
	else
		return nl_errno(ENOENT);
}

void rtnl_rule_set_realms(struct rtnl_rule *rule, realm_t realms)
{
	rule->r_realms = realms;
	rule->ce_mask |= RULE_ATTR_REALMS;
}

realm_t rtnl_rule_get_realms(struct rtnl_rule *rule)
{
	if (rule->ce_mask & RULE_ATTR_REALMS)
		return rule->r_realms;
	else
		return 0;
}

/** @} */

static struct nl_object_ops rule_obj_ops = {
	.oo_name		= "route/rule",
	.oo_size		= sizeof(struct rtnl_rule),
	.oo_free_data		= rule_free_data,
	.oo_clone		= rule_clone,
	.oo_dump[NL_DUMP_BRIEF]	= rule_dump_brief,
	.oo_dump[NL_DUMP_FULL]	= rule_dump_full,
	.oo_dump[NL_DUMP_STATS]	= rule_dump_stats,
	.oo_dump[NL_DUMP_XML]	= rule_dump_xml,
	.oo_dump[NL_DUMP_ENV]	= rule_dump_env,
	.oo_compare		= rule_compare,
	.oo_attrs2str		= rule_attrs2str,
	.oo_id_attrs		= ~0,
};

static struct nl_cache_ops rtnl_rule_ops = {
	.co_name		= "route/rule",
	.co_hdrsize		= sizeof(struct rtmsg),
	.co_msgtypes		= {
					{ RTM_NEWRULE, NL_ACT_NEW, "new" },
					{ RTM_DELRULE, NL_ACT_DEL, "del" },
					{ RTM_GETRULE, NL_ACT_GET, "get" },
					END_OF_MSGTYPES_LIST,
				  },
	.co_protocol		= NETLINK_ROUTE,
	.co_request_update	= rule_request_update,
	.co_msg_parser		= rule_msg_parser,
	.co_obj_ops		= &rule_obj_ops,
};

static void __init rule_init(void)
{
	nl_cache_mngt_register(&rtnl_rule_ops);
}

static void __exit rule_exit(void)
{
	nl_cache_mngt_unregister(&rtnl_rule_ops);
}

/** @} */
