/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * lib/route/br_vlan.c		Bridge VLAN
 */

/**
 * @ingroup rtnl
 * @defgroup br_vlan Bridge VLAN
 * @brief
 * @{
 */

#include "netlink/attr.h"
#include "netlink/msg.h"
#include "nl-aux-route/nl-route.h"
#include "nl-default.h"

#include "nl-priv-dynamic-core/cache-api.h"
#include <linux/if_bridge.h>

#include <netlink/netlink.h>
#include <netlink/route/br_vlan.h>
#include <netlink/utils.h>
#include <netlink/route/rtnl.h>
#include <netlink/errno.h>
#include <netlink/list.h>

#include <stdint.h>
#include <sys/socket.h>

#include "nl-route.h"
#include "nl-priv-dynamic-core/nl-core.h"
#include "nl-priv-dynamic-core/object-api.h"

/** @cond SKIP */

/* clang-format off */
#define BR_VLAN_ATTR_IFINDEX				(1ul <<  0)

#define BR_VLAN_ATTR_GOPTS_ID				(1ul <<  0)
#define BR_VLAN_ATTR_GOPTS_RANGE			(1ul <<  1)
#define BR_VLAN_ATTR_GOPTS_MCAST_SNOOPING		(1ul <<  2)
#define BR_VLAN_ATTR_GOPTS_MCAST_IGMP_VERSION		(1ul <<  3)
#define BR_VLAN_ATTR_GOPTS_MCAST_MLD_VERSION		(1ul <<  4)
#define BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_CNT	(1ul <<  5)
#define BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_CNT	(1ul <<  6)
#define BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_INTVL	(1ul <<  7)
#define BR_VLAN_ATTR_GOPTS_MCAST_MEMBERSHIP_INTVL	(1ul <<  8)
#define BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_INTVL		(1ul <<  9)
#define BR_VLAN_ATTR_GOPTS_MCAST_QUERY_INTVL		(1ul << 10)
#define BR_VLAN_ATTR_GOPTS_MCAST_QUERY_RESPONSE_INTVL	(1ul << 11)
#define BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_INTVL	(1ul << 12)
#define BR_VLAN_ATTR_GOPTS_MCAST_QUERIER		(1ul << 13)
#define BR_VLAN_ATTR_GOPTS_MSTI				(1ul << 14)
/* clang-format on */

/** @endcond */

/**
 * Bridge VLAN info
 *
 * @ingroup br_vlan
 */
struct rtnl_br_vlan {
	NLHDR_COMMON
	uint32_t ifindex;

	// struct nl_list_head entry_list;
	struct nl_list_head gopts_list;
};

/**
 * Bridge VLAN global options for a single VLAN
 * @ingroup br_vlan
 */
struct rtnl_br_vlan_gopts_entry {
	struct nl_list_head list_node;
	uint64_t mask;
	uint16_t o_id;
	uint16_t o_range;
	uint8_t o_mcast_snooping;
	uint8_t o_mcast_igmp_version;
	uint8_t o_mcast_mld_version;
	uint32_t o_mcast_last_member_cnt;
	uint32_t o_mcast_startup_query_cnt;
	uint64_t o_mcast_last_member_intvl;
	uint64_t o_mcast_membership_intvl;
	uint64_t o_mcast_querier_intvl;
	uint64_t o_mcast_query_intvl;
	uint64_t o_mcast_query_response_intvl;
	uint64_t o_mcast_startup_query_intvl;
	uint8_t o_mcast_querier;
	uint16_t o_msti;
	// NOTE: members missing for: (sent from kernel but not to kernel)
	// - BR_VLAN_ATTR_GOPTS_MCAST_ROUTER_PORTS
	// - BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_STATE
};

static struct rtnl_br_vlan_gopts_entry *rtnl_br_vlan_gopts_entry_alloc(void);
static void
rtnl_br_vlan_gopts_entry_free(struct rtnl_br_vlan_gopts_entry *gopts_entry);

static struct nl_cache_ops rtnl_br_vlan_ops;
static struct nl_object_ops br_vlan_obj_ops;
static struct nl_object_ops br_vlan_gopts_obj_ops;

/**
 * @name Allocation/Freeing
 * @{
 */

struct rtnl_br_vlan *rtnl_br_vlan_alloc(void)
{
	return (struct rtnl_br_vlan *)nl_object_alloc(&br_vlan_obj_ops);
}

void rtnl_br_vlan_put(struct rtnl_br_vlan *br_vlan)
{
	nl_object_put((struct nl_object *)br_vlan);
}

struct rtnl_br_vlan_gopts_entry *rtnl_br_vlan_gopts_entry_alloc(void)
{
	struct rtnl_br_vlan_gopts_entry *entry;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return NULL;

	nl_init_list_head(&entry->list_node);

	return entry;
}

void rtnl_br_vlan_gopts_entry_free(struct rtnl_br_vlan_gopts_entry *entry)
{
	nl_list_del(&entry->list_node);
	free(entry);
}

/** @} */

/**
 * @name Bridge VLAN Global Option Modifications
 * @{
 */

int rtnl_br_vlan_gopts_list_build_set_request(struct rtnl_br_vlan *opts_list,
					      struct nl_msg **result)
{
	struct br_vlan_msg bvm = {};
	struct nl_msg *msg;
	struct nlattr *attr = NULL;
	struct rtnl_br_vlan_gopts_entry *opts;
	int err;

	if (opts_list == NULL || result == NULL ||
	    !(opts_list->ce_mask & BR_VLAN_ATTR_IFINDEX))
		return -NLE_INVAL;

	msg = nlmsg_alloc_simple(RTM_NEWVLAN, NLM_F_REQUEST);
	if (msg == NULL)
		return -NLE_NOMEM;

	bvm.ifindex = opts_list->ifindex;
	bvm.family = AF_BRIDGE;

	err = nlmsg_append(msg, &bvm, sizeof(bvm), NLMSG_ALIGNTO);
	if (err < 0)
		goto free_msg;

	nl_list_for_each_entry(opts, &opts_list->gopts_list, list_node) {
		attr = nla_nest_start(msg, BRIDGE_VLANDB_GLOBAL_OPTIONS);
		if (!attr) {
			goto free_msg;
		}

		if (opts->mask & BR_VLAN_ATTR_GOPTS_ID)
			NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_ID, opts->o_id);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_RANGE)
			NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_RANGE,
				    opts->o_range);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_SNOOPING)
			NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING,
				   opts->o_mcast_snooping);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_IGMP_VERSION)
			NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION,
				   opts->o_mcast_igmp_version);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_MLD_VERSION)
			NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION,
				   opts->o_mcast_mld_version);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_CNT)
			NLA_PUT_U32(msg,
				    BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT,
				    opts->o_mcast_last_member_cnt);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_CNT)
			NLA_PUT_U32(msg,
				    BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT,
				    opts->o_mcast_startup_query_cnt);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_INTVL)
			NLA_PUT_U64(msg,
				    BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL,
				    opts->o_mcast_last_member_intvl);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_MEMBERSHIP_INTVL)
			NLA_PUT_U64(msg,
				    BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL,
				    opts->o_mcast_membership_intvl);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_INTVL)
			NLA_PUT_U64(msg,
				    BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL,
				    opts->o_mcast_querier_intvl);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERY_INTVL)
			NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL,
				    opts->o_mcast_query_intvl);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERY_RESPONSE_INTVL)
			NLA_PUT_U64(
				msg,
				BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL,
				opts->o_mcast_query_response_intvl);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_INTVL)
			NLA_PUT_U64(
				msg,
				BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL,
				opts->o_mcast_startup_query_intvl);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERIER)
			NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERIER,
				   opts->o_mcast_querier);
		if (opts->mask & BR_VLAN_ATTR_GOPTS_MSTI)
			NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_MSTI,
				    opts->o_msti);

		nla_nest_end(msg, attr);
	}

	*result = msg;
	return 0;

nla_put_failure:
	nla_nest_cancel(msg, attr);

free_msg:
	nlmsg_free(msg);
	return -EMSGSIZE;
}

// int rtnl_br_vlan_gopts_build_change_request(
// 	struct rtnl_br_vlan_gopts_entry *old,
// 	struct rtnl_br_vlan_gopts_entry *tmpl, struct nl_msg **result)
// {
// 	struct br_vlan_msg bvm = {};
// 	struct nl_msg *msg;
// 	struct nlattr *attr = NULL;
// 	int err;
//
// 	if (old == NULL || tmpl == NULL || result == NULL ||
// 	    !(old->ce_mask & BR_VLAN_ATTR_IFINDEX))
// 		return -NLE_INVAL;
//
// 	/* Changing the ifindex is disallowed */
// 	if ((tmpl->ce_mask & BR_VLAN_ATTR_IFINDEX) &&
// 	    tmpl->ifindex != old->ifindex)
// 		return -NLE_INVAL;
//
// 	msg = nlmsg_alloc_simple(RTM_NEWVLAN, NLM_F_REQUEST);
// 	if (msg == NULL)
// 		return -NLE_NOMEM;
//
// 	bvm.ifindex = old->ifindex;
// 	bvm.family = AF_BRIDGE;
//
// 	err = nlmsg_append(msg, &bvm, sizeof(bvm), NLMSG_ALIGNTO);
// 	if (err < 0)
// 		goto free_msg;
//
// 	attr = nla_nest_start(msg, BRIDGE_VLANDB_GLOBAL_OPTIONS);
// 	if (!attr) {
// 		goto free_msg;
// 	}
//
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_ID)
// 		NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_ID, tmpl->o_id);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_RANGE)
// 		NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_RANGE, tmpl->o_range);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_SNOOPING)
// 		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING,
// 			   tmpl->o_mcast_snooping);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_IGMP_VERSION)
// 		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION,
// 			   tmpl->o_mcast_igmp_version);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_MLD_VERSION)
// 		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION,
// 			   tmpl->o_mcast_mld_version);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_CNT)
// 		NLA_PUT_U32(msg, BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT,
// 			    tmpl->o_mcast_last_member_cnt);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_CNT)
// 		NLA_PUT_U32(msg, BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT,
// 			    tmpl->o_mcast_startup_query_cnt);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_INTVL)
// 		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL,
// 			    tmpl->o_mcast_last_member_intvl);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_MEMBERSHIP_INTVL)
// 		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL,
// 			    tmpl->o_mcast_membership_intvl);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_INTVL)
// 		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL,
// 			    tmpl->o_mcast_querier_intvl);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERY_INTVL)
// 		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL,
// 			    tmpl->o_mcast_query_intvl);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERY_RESPONSE_INTVL)
// 		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL,
// 			    tmpl->o_mcast_query_response_intvl);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_INTVL)
// 		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL,
// 			    tmpl->o_mcast_startup_query_intvl);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERIER)
// 		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERIER,
// 			   tmpl->o_mcast_querier);
// 	if (tmpl->ce_mask & BR_VLAN_ATTR_GOPTS_MSTI)
// 		NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_MSTI, tmpl->o_msti);
//
// 	nla_nest_end(msg, attr);
//
// 	*result = msg;
// 	return 0;
//
// nla_put_failure:
// 	nla_nest_cancel(msg, attr);
//
// free_msg:
// 	nlmsg_free(msg);
// 	return -EMSGSIZE;
// }

// use 'change' instead?
int rtnl_br_vlan_gopts_list_set(struct nl_sock *sk,
				struct rtnl_br_vlan *opts_list)
{
	struct nl_msg *msg = NULL;
	int err;

	err = rtnl_br_vlan_gopts_list_build_set_request(opts_list, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return wait_for_ack(sk);
}

/** @} */

/**
 * @name Attribute Modification
 * @{
 */

int rtnl_br_vlan_set_ifindex(struct rtnl_br_vlan *br_vlan, uint32_t value)
{
	if (br_vlan == NULL)
		return -NLE_INVAL;

	br_vlan->ifindex = value;
	br_vlan->ce_mask |= BR_VLAN_ATTR_IFINDEX;

	return 0;
}

int rtnl_br_vlan_get_ifindex(struct rtnl_br_vlan *br_vlan, uint32_t *out)
{
	if (br_vlan == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(br_vlan->ce_mask & BR_VLAN_ATTR_IFINDEX))
		return -NLE_NOATTR;

	*out = br_vlan->ifindex;

	return 0;
}

void rtnl_br_vlan_add_gopts_entry(struct rtnl_br_vlan *br_vlan,
				  struct rtnl_br_vlan_gopts_entry *entry)
{
	nl_list_add_tail(&entry->list_node, &br_vlan->gopts_list);
}

void rtnl_br_vlan_foreach_gopts_entry(
	struct rtnl_br_vlan *br_vlan,
	void (*cb)(struct rtnl_br_vlan_gopts_entry *, void *), void *arg)
{
	struct rtnl_br_vlan_gopts_entry *entry;

	nl_list_for_each_entry(entry, &br_vlan->gopts_list, list_node) {
		cb(entry, arg);
	}
}

int rtnl_br_vlan_gopts_entry_set_id(struct rtnl_br_vlan_gopts_entry *opts,
				    uint16_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_id = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_ID;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_id(struct rtnl_br_vlan_gopts_entry *opts,
				    uint16_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_ID))
		return -NLE_NOATTR;

	*out = opts->o_id;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_range(struct rtnl_br_vlan_gopts_entry *opts,
				       uint16_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_range = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_RANGE;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_range(struct rtnl_br_vlan_gopts_entry *opts,
				       uint16_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_RANGE))
		return -NLE_NOATTR;

	*out = opts->o_range;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_snooping = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_SNOOPING;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_SNOOPING))
		return -NLE_NOATTR;

	*out = opts->o_mcast_snooping;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_igmp_version = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_IGMP_VERSION;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_IGMP_VERSION))
		return -NLE_NOATTR;

	*out = opts->o_mcast_igmp_version;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_mld_version = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_MLD_VERSION;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_MLD_VERSION))
		return -NLE_NOATTR;

	*out = opts->o_mcast_mld_version;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_last_member_cnt = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_CNT;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_CNT))
		return -NLE_NOATTR;

	*out = opts->o_mcast_last_member_cnt;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_startup_query_cnt = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_CNT;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_CNT))
		return -NLE_NOATTR;

	*out = opts->o_mcast_startup_query_cnt;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_last_member_intvl = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_INTVL;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_INTVL))
		return -NLE_NOATTR;

	*out = opts->o_mcast_last_member_intvl;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_membership_intvl = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_MEMBERSHIP_INTVL;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_MEMBERSHIP_INTVL))
		return -NLE_NOATTR;

	*out = opts->o_mcast_membership_intvl;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_querier_intvl = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_INTVL;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_INTVL))
		return -NLE_NOATTR;

	*out = opts->o_mcast_querier_intvl;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_query_intvl = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_QUERY_INTVL;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERY_INTVL))
		return -NLE_NOATTR;

	*out = opts->o_mcast_query_intvl;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_query_response_intvl = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_QUERY_RESPONSE_INTVL;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERY_RESPONSE_INTVL))
		return -NLE_NOATTR;

	*out = opts->o_mcast_query_response_intvl;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_startup_query_intvl = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_INTVL;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_INTVL))
		return -NLE_NOATTR;

	*out = opts->o_mcast_startup_query_intvl;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_mcast_querier = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MCAST_QUERIER;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MCAST_QUERIER))
		return -NLE_NOATTR;

	*out = opts->o_mcast_querier;

	return 0;
}

int rtnl_br_vlan_gopts_entry_set_msti(struct rtnl_br_vlan_gopts_entry *opts,
				      uint16_t value)
{
	if (opts == NULL)
		return -NLE_INVAL;

	opts->o_msti = value;
	opts->mask |= BR_VLAN_ATTR_GOPTS_MSTI;

	return 0;
}

int rtnl_br_vlan_gopts_entry_get_msti(struct rtnl_br_vlan_gopts_entry *opts,
				      uint16_t *out)
{
	if (opts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(opts->mask & BR_VLAN_ATTR_GOPTS_MSTI))
		return -NLE_NOATTR;

	*out = opts->o_msti;

	return 0;
}

/** @} */

static void br_vlan_constructor(struct nl_object *obj)
{
	struct rtnl_br_vlan *_br_vlan = (struct rtnl_br_vlan *)obj;

	nl_init_list_head(&_br_vlan->gopts_list);
}

static void br_vlan_free_data(struct nl_object *obj)
{
	struct rtnl_br_vlan *br_vlan = (struct rtnl_br_vlan *)obj;
	struct rtnl_br_vlan_gopts_entry *br_vlan_gopts_entry;
	struct rtnl_br_vlan_gopts_entry *br_vlan_gopts_entry_safe;

	nl_list_for_each_entry_safe(br_vlan_gopts_entry,
				    br_vlan_gopts_entry_safe,
				    &br_vlan->gopts_list, list_node)
		rtnl_br_vlan_gopts_entry_free(br_vlan_gopts_entry);
}

static void
rtnl_br_vlan_gopts_entry_free(struct rtnl_br_vlan_gopts_entry *gopts_entry)
{
	nl_list_del(&gopts_entry->list_node);
	free(gopts_entry);
}

static uint64_t br_vlan_compare(struct nl_object *_a, struct nl_object *_b,
				uint64_t attrs, int flags)
{
	struct rtnl_br_vlan *a = (struct rtnl_br_vlan *)_a;
	struct rtnl_br_vlan *b = (struct rtnl_br_vlan *)_b;
	struct rtnl_br_vlan_gopts_entry *a_entry, *b_entry;
	uint64_t diff = 0;

#define _DIFF(ATTR, EXPR) ATTR_DIFF(attrs, ATTR, a, b, EXPR)
	diff |= _DIFF(BR_VLAN_ATTR_IFINDEX, a->ifindex != b->ifindex);

	// TODO: figure out what to do about this
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_ID, a->o_id != b->o_id);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_RANGE, a->o_range != b->o_range);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_SNOOPING,
	// 	      a->o_mcast_snooping != b->o_mcast_snooping);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_IGMP_VERSION,
	// 	      a->o_mcast_igmp_version != b->o_mcast_igmp_version);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_MLD_VERSION,
	// 	      a->o_mcast_mld_version != b->o_mcast_mld_version);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_CNT,
	// 	      a->o_mcast_last_member_cnt != b->o_mcast_last_member_cnt);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_CNT,
	// 	      a->o_mcast_startup_query_cnt !=
	// 		      b->o_mcast_startup_query_cnt);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_INTVL,
	// 	      a->o_mcast_last_member_intvl !=
	// 		      b->o_mcast_last_member_intvl);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_MEMBERSHIP_INTVL,
	// 	      a->o_mcast_membership_intvl !=
	// 		      b->o_mcast_membership_intvl);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_INTVL,
	// 	      a->o_mcast_querier_intvl != b->o_mcast_querier_intvl);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_QUERY_INTVL,
	// 	      a->o_mcast_query_intvl != b->o_mcast_query_intvl);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_QUERY_RESPONSE_INTVL,
	// 	      a->o_mcast_query_response_intvl !=
	// 		      b->o_mcast_query_response_intvl);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_INTVL,
	// 	      a->o_mcast_startup_query_intvl !=
	// 		      b->o_mcast_startup_query_intvl);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MCAST_QUERIER,
	// 	      a->o_mcast_querier != b->o_mcast_querier);
	// diff |= _DIFF(BR_VLAN_ATTR_GOPTS_MSTI, a->o_msti != b->o_msti);
#undef _DIFF

	return diff;
}

static bool br_vlan_gopts_equal(struct rtnl_br_vlan_gopts_entry *a,
				struct rtnl_br_vlan_gopts_entry *b)
{
	/* clang-format off */
	return     a->o_id == b->o_id
		&& a->o_range == b->o_range
		&& a->o_mcast_snooping == b->o_mcast_snooping
		&& a->o_mcast_igmp_version == b->o_mcast_igmp_version
		&& a->o_mcast_mld_version == b->o_mcast_mld_version
		&& a->o_mcast_last_member_cnt == b->o_mcast_last_member_cnt
		&& a->o_mcast_startup_query_cnt == b->o_mcast_startup_query_cnt
		&& a->o_mcast_last_member_intvl == b->o_mcast_last_member_intvl
		&& a->o_mcast_membership_intvl == b->o_mcast_membership_intvl
		&& a->o_mcast_querier_intvl == b->o_mcast_querier_intvl
		&& a->o_mcast_query_intvl == b->o_mcast_query_intvl
		&& a->o_mcast_query_response_intvl == b->o_mcast_query_response_intvl
		&& a->o_mcast_startup_query_intvl == b->o_mcast_startup_query_intvl
		&& a->o_mcast_querier == b->o_mcast_querier
		&& a->o_msti == b->o_msti;
	/* clang-format on */
	return 0;
}

static struct nl_object_ops br_vlan_obj_ops = {
	.oo_name = "route/br_vlan",
	.oo_size = sizeof(struct rtnl_br_vlan),
	.oo_constructor = br_vlan_constructor,
	.oo_free_data = br_vlan_free_data,
	.oo_dump = {
	            // [NL_DUMP_LINE]    = br_vlan_dump_line,
	            // [NL_DUMP_DETAILS] = br_vlan_dump_details,
	            // [NL_DUMP_STATS]   = br_vlan_dump_stats,
	},
	.oo_compare = br_vlan_compare,
};

static struct nla_policy br_vlan_policy[BRIDGE_VLANDB_MAX + 1] = {
	[BRIDGE_VLANDB_GLOBAL_OPTIONS] = { .type = NLA_NESTED },
};

// WIP
static int br_vlan_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			      struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	int err = 0;
	int rem = 0;
	struct br_vlan_msg *bvm;
	struct nlattr *nla;
	_nl_auto_rtnl_br_vlan struct rtnl_br_vlan *br_vlan =
		rtnl_br_vlan_alloc();

	if (!br_vlan)
		return -NLE_NOMEM;

	err = nlmsg_parse(nlh, sizeof(struct br_vlan_msg), NULL,
			  BRIDGE_VLANDB_MAX, NULL);
	if (err < 0)
		return err;

	br_vlan->ce_msgtype = nlh->nlmsg_type;

	bvm = nlmsg_data(nlh);
	br_vlan->ifindex = bvm->ifindex;
	br_vlan->ce_mask |= BR_VLAN_ATTR_IFINDEX;

	nlmsg_for_each_attr(nla, nlh, sizeof(*bvm), rem) {
		switch (nla_type(nla)) {
		case BRIDGE_VLANDB_ENTRY:
			// unimplemented
			break;
		case BRIDGE_VLANDB_GLOBAL_OPTIONS:
			// TODO: process global options here
			break;
		default:
			continue;
		}
	}

	return pp->pp_cb((struct nl_object *)br_vlan, pp);
}

static int br_vlan_request_update(struct nl_cache *cache, struct nl_sock *sk)
{
	// TODO:
	return nl_rtgen_request(sk, RTM_GETVLAN, AF_BRIDGE, NLM_F_DUMP);
}

// FIXME: come back to this and make sure it's right
static struct nl_af_group br_vlan_groups[] = {
	{ AF_UNSPEC, RTNLGRP_BRVLAN },
	{ AF_BRIDGE, RTNLGRP_BRVLAN },
	{ AF_INET6, RTNLGRP_IPV6_IFINFO },
	{ END_OF_GROUP_LIST },
};

static struct nl_cache_ops rtnl_br_vlan_ops = {
	.co_name = "route/br_vlan",
	.co_hdrsize = sizeof(struct br_vlan_msg),

	.co_msgtypes = {
	                { RTM_NEWVLAN, NL_ACT_NEW, "new"},
	                { RTM_DELVLAN, NL_ACT_DEL, "del"},
	                { RTM_GETVLAN, NL_ACT_GET, "get"},
	                END_OF_MSGTYPES_LIST,
	                },
	.co_protocol = NETLINK_ROUTE,
	.co_groups = br_vlan_groups,
	.co_request_update = br_vlan_request_update,
	.co_msg_parser = br_vlan_msg_parser,
	.co_obj_ops = &br_vlan_obj_ops,
};

static void _nl_init br_vlan_gopts_init(void)
{
	nl_cache_mngt_register(&rtnl_br_vlan_ops);
}

static void _nl_exit br_vlan_gopts_exit(void)
{
	nl_cache_mngt_unregister(&rtnl_br_vlan_ops);
}

/** @} */

// Scratch area:
//
// Sizes: (excluding 2 unused)
// BRIDGE_VLANDB_GOPTS_ID 16
// BRIDGE_VLANDB_GOPTS_RANGE 16
// BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING 8
// BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION 8
// BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION 8
// BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT 32
// BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT 32
// BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL 64
// BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL 64
// BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL 64
// BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL 64
// BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL 64
// BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL 64
// BRIDGE_VLANDB_GOPTS_MCAST_QUERIER 8
// BRIDGE_VLANDB_GOPTS_MSTI 16

// BRIDGE_VLANDB_GOPTS_ID                         BR_VLAN_ATTR_GOPTS_ID                         uint16_t o_id
// BRIDGE_VLANDB_GOPTS_RANGE                      BR_VLAN_ATTR_GOPTS_RANGE                      uint16_t o_range
// BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING             BR_VLAN_ATTR_GOPTS_MCAST_SNOOPING             uint8_t  o_mcast_snooping
// BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION         BR_VLAN_ATTR_GOPTS_MCAST_IGMP_VERSION         uint8_t  o_mcast_igmp_version
// BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION          BR_VLAN_ATTR_GOPTS_MCAST_MLD_VERSION          uint8_t  o_mcast_mld_version
// BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT      BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_CNT      uint32_t o_mcast_last_member_cnt
// BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT    BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_CNT    uint32_t o_mcast_startup_query_cnt
// BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL    BR_VLAN_ATTR_GOPTS_MCAST_LAST_MEMBER_INTVL    uint64_t o_mcast_last_member_intvl
// BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL     BR_VLAN_ATTR_GOPTS_MCAST_MEMBERSHIP_INTVL     uint64_t o_mcast_membership_intvl
// BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL        BR_VLAN_ATTR_GOPTS_MCAST_QUERIER_INTVL        uint64_t o_mcast_querier_intvl
// BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL          BR_VLAN_ATTR_GOPTS_MCAST_QUERY_INTVL          uint64_t o_mcast_query_intvl
// BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL BR_VLAN_ATTR_GOPTS_MCAST_QUERY_RESPONSE_INTVL uint64_t o_mcast_query_response_intvl
// BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL  BR_VLAN_ATTR_GOPTS_MCAST_STARTUP_QUERY_INTVL  uint64_t o_mcast_startup_query_intvl
// BRIDGE_VLANDB_GOPTS_MCAST_QUERIER              BR_VLAN_ATTR_GOPTS_MCAST_QUERIER              uint8_t  o_mcast_querier
// BRIDGE_VLANDB_GOPTS_MSTI                       BR_VLAN_ATTR_GOPTS_MSTI                       uint16_t o_msti
