/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * lib/route/br_vlan/global_opts.c	Bridge VLAN global options
 */

/**
 * @ingroup rtnl
 * @defgroup br_vlan_global_opts Bridge VLAN global options
 * @brief
 * Allows configuration of global VLAN options of bridge master interfaces.
 * @{
 */

#include "nl-default.h"

#include <linux/netlink.h>
#include <linux/if_bridge.h>
#include <sys/socket.h>

#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/errno.h>
#include <netlink/list.h>
#include <netlink/attr.h>
#include <netlink/msg.h>
#include <netlink/route/br_vlan/global_opts.h>

#include "nl-aux-core/nl-core.h"
#include "nl-aux-route/nl-route.h"
#include "nl-priv-dynamic-core/nl-core.h"
#include "nl-priv-dynamic-core/cache-api.h"
#include "nl-priv-dynamic-core/object-api.h"

/** @cond SKIP */

/* clang-format off */
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */

#define BR_VLAN_GOPTS_ATTR_IFINDEX				(1UL <<  0)
#define BR_VLAN_GOPTS_ATTR_ENTRIES				(1UL <<  1)

#define BR_VLAN_GOPTS_ATTR_ENTRY_VID				(1UL <<  0)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_SNOOPING			(1UL <<  1)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_IGMP_VERSION		(1UL <<  2)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MLD_VERSION		(1UL <<  3)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_CNT		(1UL <<  4)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_CNT	(1UL <<  5)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_INTVL	(1UL <<  6)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MEMBERSHIP_INTVL		(1UL <<  7)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER_INTVL		(1UL <<  8)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_INTVL		(1UL <<  9)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_RESPONSE_INTVL	(1UL << 10)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_INTVL	(1UL << 11)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER			(1UL << 12)
#define BR_VLAN_GOPTS_ATTR_ENTRY_MSTI				(1UL << 13)
/* clang-format on */

/** @endcond */

/**
 * Bridge VLAN global options for a bridge.
 * Contains per vlan global options.
 *
 * @ingroup br_vlan
 */
struct rtnl_br_vlan_gopts {
	NLHDR_COMMON
	uint32_t ifindex;

	struct nl_list_head gopts_list; /* Sorted by VID in ascending order.
					   Duplicate VIDs are not allowed. */
};

/**
 * Bridge VLAN global options for a single VLAN
 * @ingroup br_vlan
 */
struct rtnl_br_vlan_gopts_entry {
	struct nl_list_head list_node;
	uint64_t mask;
	uint16_t vid;
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
};

static struct nl_object_ops obj_ops;

/**
 * @name Allocation/Freeing
 * @{
 */

/**
 * Allocate a new gopts object.
 *
 * @see rtnl_br_vlan_gopts_put()
 *
 * @return New gopts object or NULL if allocation failed.
 */
struct rtnl_br_vlan_gopts *rtnl_br_vlan_gopts_alloc(void)
{
	return (struct rtnl_br_vlan_gopts *)nl_object_alloc(&obj_ops);
}

/**
 * Release a gopts object reference.
 * @arg gopts		gopts object.
 *
 * @see rtnl_br_vlan_gopts_alloc()
 */
void rtnl_br_vlan_gopts_put(struct rtnl_br_vlan_gopts *gopts)
{
	nl_object_put((struct nl_object *)gopts);
}

static int gopts_clone(struct nl_object *_dst, struct nl_object *_src)
{
	struct rtnl_br_vlan_gopts *dst = nl_object_priv(_dst);
	struct rtnl_br_vlan_gopts *src = nl_object_priv(_src);
	struct rtnl_br_vlan_gopts_entry *entry;

	nl_init_list_head(&dst->gopts_list);

	nl_list_for_each_entry(entry, &src->gopts_list, list_node) {
		struct rtnl_br_vlan_gopts_entry *entry_clone;

		entry_clone = rtnl_br_vlan_gopts_entry_clone(entry);
		if (entry_clone == NULL)
			return -NLE_NOMEM;

		nl_list_add_tail(&entry_clone->list_node, &dst->gopts_list);
	}

	return NLE_SUCCESS;
}

/**
 * Allocate a new gopts entry object.
 *
 * The returned object is standalone, not being part of a gopts object.
 * Note that unlike gopts objects, gopts entries are not reference counted.
 *
 * @see rtnl_br_vlan_gopts_entry_free()
 *
 * @return New gopts entry object or NULL if allocation failed.
 */
struct rtnl_br_vlan_gopts_entry *rtnl_br_vlan_gopts_entry_alloc(void)
{
	struct rtnl_br_vlan_gopts_entry *entry;

	entry = calloc(1, sizeof(*entry));
	if (!entry)
		return NULL;

	nl_init_list_head(&entry->list_node);

	return entry;
}

/**
 * Free a gopts entry object.
 * @arg entry		gopts entry object.
 *
 * @see rtnl_br_vlan_gopts_entry_alloc()
 */
void rtnl_br_vlan_gopts_entry_free(struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return;

	/* Also remove from the list it is a member of. Has no effect when the
	 * entry is standalone (not part of a list). */
	nl_list_del(&entry->list_node);

	free(entry);
}

/**
 * Clone a gopts entry.
 * @arg entry		gopts entry to clone.
 *
 * The new entry will be standalone and not part of a gopts object even if it
 * was before.
 *
 * @see rtnl_br_vlan_gopts_entry_free()
 *
 * @return New gopts entry object or NULL if allocation failed or entry was
 *	   NULL.
 */
struct rtnl_br_vlan_gopts_entry *
rtnl_br_vlan_gopts_entry_clone(const struct rtnl_br_vlan_gopts_entry *entry)
{
	struct rtnl_br_vlan_gopts_entry *new_entry;

	if (entry == NULL)
		return NULL;

	new_entry = calloc(1, sizeof(*new_entry));
	if (!new_entry)
		return NULL;

	memcpy(new_entry, entry, sizeof(*new_entry));

	nl_init_list_head(&new_entry->list_node);

	return new_entry;
}

/** @} */

/**
 * @name Bridge VLAN Global Option Modifications
 * @{
 */

static bool gopts_entries_are_equal(struct rtnl_br_vlan_gopts_entry *entry_a,
				    struct rtnl_br_vlan_gopts_entry *entry_b,
				    bool check_vid)
{
#define GOPTS_CHECK(member, flag)                                            \
	do {                                                                 \
		if ((entry_a->mask & (flag)) != (entry_b->mask & (flag)) ||  \
		    ((entry_a->mask & (flag)) && (entry_b->mask & (flag)) && \
		     entry_a->member != entry_b->member)) {                  \
			return false;                                        \
		}                                                            \
	} while (0)

	if (check_vid)
		GOPTS_CHECK(vid, BR_VLAN_GOPTS_ATTR_ENTRY_VID);

	/* clang-format off */
	GOPTS_CHECK(o_mcast_snooping, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_SNOOPING);
	GOPTS_CHECK(o_mcast_igmp_version, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_IGMP_VERSION);
	GOPTS_CHECK(o_mcast_mld_version, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MLD_VERSION);
	GOPTS_CHECK(o_mcast_last_member_cnt, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_CNT);
	GOPTS_CHECK(o_mcast_startup_query_cnt, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_CNT);
	GOPTS_CHECK(o_mcast_last_member_intvl, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_INTVL);
	GOPTS_CHECK(o_mcast_membership_intvl, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MEMBERSHIP_INTVL);
	GOPTS_CHECK(o_mcast_querier_intvl, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER_INTVL);
	GOPTS_CHECK(o_mcast_query_intvl, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_INTVL);
	GOPTS_CHECK(o_mcast_query_response_intvl, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_RESPONSE_INTVL);
	GOPTS_CHECK(o_mcast_startup_query_intvl, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_INTVL);
	GOPTS_CHECK(o_mcast_querier, BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER);
	GOPTS_CHECK(o_msti, BR_VLAN_GOPTS_ATTR_ENTRY_MSTI);
	/* clang-format on */

#undef GOPTS_CHECK

	return true;
}

static int gopts_fill_entry(struct nl_msg *msg,
			    struct rtnl_br_vlan_gopts_entry *entry,
			    uint16_t range_end)
{
	struct nlattr *attr;

	attr = nla_nest_start(msg, BRIDGE_VLANDB_GLOBAL_OPTIONS);
	if (!attr)
		goto nla_put_failure;

	NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_ID, entry->vid);

	if (range_end > entry->vid)
		NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_RANGE, range_end);

	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_SNOOPING)
		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING,
			   entry->o_mcast_snooping);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_IGMP_VERSION)
		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION,
			   entry->o_mcast_igmp_version);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MLD_VERSION)
		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION,
			   entry->o_mcast_mld_version);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_CNT)
		NLA_PUT_U32(msg, BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT,
			    entry->o_mcast_last_member_cnt);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_CNT)
		NLA_PUT_U32(msg, BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT,
			    entry->o_mcast_startup_query_cnt);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_INTVL)
		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL,
			    entry->o_mcast_last_member_intvl);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MEMBERSHIP_INTVL)
		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL,
			    entry->o_mcast_membership_intvl);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER_INTVL)
		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL,
			    entry->o_mcast_querier_intvl);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_INTVL)
		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL,
			    entry->o_mcast_query_intvl);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_RESPONSE_INTVL)
		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL,
			    entry->o_mcast_query_response_intvl);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_INTVL)
		NLA_PUT_U64(msg, BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL,
			    entry->o_mcast_startup_query_intvl);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER)
		NLA_PUT_U8(msg, BRIDGE_VLANDB_GOPTS_MCAST_QUERIER,
			   entry->o_mcast_querier);
	if (entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MSTI)
		NLA_PUT_U16(msg, BRIDGE_VLANDB_GOPTS_MSTI, entry->o_msti);

	nla_nest_end(msg, attr);

	return NLE_SUCCESS;

nla_put_failure:
	return -NLE_MSGSIZE;
}

static int gopts_fill_entries_compressed(struct nl_msg *msg,
					 const struct nl_list_head *gopts_list)
{
	struct rtnl_br_vlan_gopts_entry *range_start_entry;
	int err;

	range_start_entry = nl_list_first_entry(
		gopts_list, struct rtnl_br_vlan_gopts_entry, list_node);

	/* Loop while we haven't reached the end of the list */
	while (&range_start_entry->list_node != gopts_list) {
		struct rtnl_br_vlan_gopts_entry *range_end_entry =
			range_start_entry;
		struct rtnl_br_vlan_gopts_entry *next_entry;
		bool found_range_end = false;

		while (!found_range_end) {
			bool is_valid_continuation;

			next_entry = nl_list_entry(
				range_end_entry->list_node.next,
				struct rtnl_br_vlan_gopts_entry, list_node);

			is_valid_continuation =
				&next_entry->list_node != gopts_list &&
				next_entry->vid == range_end_entry->vid + 1 &&
				gopts_entries_are_equal(range_end_entry,
							next_entry, false);

			if (!is_valid_continuation)
				found_range_end = true;
			else
				range_end_entry = next_entry;
		}

		err = gopts_fill_entry(msg, range_start_entry,
				       range_end_entry->vid);
		if (err)
			return err;

		range_start_entry = next_entry;
	}

	return NLE_SUCCESS;
}

/**
 * Build a netlink message requesting modifications to the gopts entries held by
 * the given gopts object.
 * @arg gopts		gopts object.
 * @arg result		pointer to store resulting netlink message.
 *
 * The behaviour of this function is identical to rtnl_br_vlan_gopts_modify()
 * with the exception that it will not send the message but return it in the
 * provided return pointer instead.
 *
 * @see rtnl_br_vlan_gopts_modify()
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_br_vlan_gopts_build_modify_request(
	const struct rtnl_br_vlan_gopts *gopts, struct nl_msg **result)
{
	_nl_auto_nl_msg struct nl_msg *msg = NULL;
	struct br_vlan_msg bvm = { 0 };

	if (gopts == NULL || result == NULL ||
	    !(gopts->ce_mask & BR_VLAN_GOPTS_ATTR_IFINDEX))
		return -NLE_INVAL;

	msg = nlmsg_alloc_simple(RTM_NEWVLAN, NLM_F_REQUEST);
	if (msg == NULL)
		return -NLE_NOMEM;

	bvm.ifindex = gopts->ifindex;
	bvm.family = AF_BRIDGE;

	_NL_RETURN_ON_PUT_ERR(
		nlmsg_append(msg, &bvm, sizeof(bvm), NLMSG_ALIGNTO));

	if (gopts_fill_entries_compressed(msg, &gopts->gopts_list) < 0)
		return -NLE_MSGSIZE;

	*result = _nl_steal_pointer(&msg);
	return NLE_SUCCESS;
}

/**
 * Modify global VLAN options for the entries held by the gopts object.
 * @arg sk		netlink socket.
 * @arg gopts		gopts object.
 *
 * Builds a \c RTM_NEWVLAN netlink message requesting the modification of the
 * global vlan options for a bridge master interface.
 *
 * After sending, the function will wait for the ACK or an eventual error
 * message to be received and will therefore block until the operation has been
 * completed.
 *
 * @copydoc auto_ack_warning
 *
 * @note If the gopts object has no entries set then the kernel will complain,
 *	 making this function return -NLE_INVAL.
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_br_vlan_gopts_modify(struct nl_sock *sk,
			      const struct rtnl_br_vlan_gopts *gopts)
{
	struct nl_msg *msg = NULL;
	int err;

	if (sk == NULL || gopts == NULL)
		return -NLE_INVAL;

	err = rtnl_br_vlan_gopts_build_modify_request(gopts, &msg);
	if (err < 0)
		return err;

	return nl_send_sync(sk, msg);
}

/* clang-format off */
static const struct nla_policy br_vlan_gopts_entry_policy[BRIDGE_VLANDB_GOPTS_MAX + 1] = {
	[BRIDGE_VLANDB_GOPTS_ID]			 = { .type = NLA_U16 },
	[BRIDGE_VLANDB_GOPTS_RANGE]			 = { .type = NLA_U16 },
	[BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING]		 = { .type = NLA_U8  },
	[BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION]	 = { .type = NLA_U8  },
	[BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION]		 = { .type = NLA_U8  },
	[BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT]	 = { .type = NLA_U32 },
	[BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT]	 = { .type = NLA_U32 },
	[BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL]	 = { .type = NLA_U64 },
	[BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL]	 = { .type = NLA_U64 },
	[BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL]	 = { .type = NLA_U64 },
	[BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL]		 = { .type = NLA_U64 },
	[BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL] = { .type = NLA_U64 },
	[BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL]	 = { .type = NLA_U64 },
	[BRIDGE_VLANDB_GOPTS_MCAST_QUERIER]		 = { .type = NLA_U8  },
	[BRIDGE_VLANDB_GOPTS_MCAST_ROUTER_PORTS]	 = { .type = NLA_NESTED },
	[BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_STATE]	 = { .type = NLA_NESTED },
	[BRIDGE_VLANDB_GOPTS_MSTI]			 = { .type = NLA_U16 },
};
/* clang-format on */

static void
gopts_parse_entry_info_attrs(struct nlattr *tb[BRIDGE_VLANDB_GOPTS_MAX + 1],
			     struct rtnl_br_vlan_gopts_entry *entry)
{
	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING]) {
		entry->o_mcast_snooping =
			nla_get_u8(tb[BRIDGE_VLANDB_GOPTS_MCAST_SNOOPING]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_SNOOPING;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION]) {
		entry->o_mcast_igmp_version =
			nla_get_u8(tb[BRIDGE_VLANDB_GOPTS_MCAST_IGMP_VERSION]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_IGMP_VERSION;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION]) {
		entry->o_mcast_mld_version =
			nla_get_u8(tb[BRIDGE_VLANDB_GOPTS_MCAST_MLD_VERSION]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MLD_VERSION;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT]) {
		entry->o_mcast_last_member_cnt = nla_get_u32(
			tb[BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_CNT]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_CNT;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT]) {
		entry->o_mcast_startup_query_cnt = nla_get_u32(
			tb[BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_CNT]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_CNT;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL]) {
		entry->o_mcast_last_member_intvl = nla_get_u64(
			tb[BRIDGE_VLANDB_GOPTS_MCAST_LAST_MEMBER_INTVL]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_INTVL;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL]) {
		entry->o_mcast_membership_intvl = nla_get_u64(
			tb[BRIDGE_VLANDB_GOPTS_MCAST_MEMBERSHIP_INTVL]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MEMBERSHIP_INTVL;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL]) {
		entry->o_mcast_querier_intvl = nla_get_u64(
			tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_INTVL]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER_INTVL;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL]) {
		entry->o_mcast_query_intvl =
			nla_get_u64(tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERY_INTVL]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_INTVL;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL]) {
		entry->o_mcast_query_response_intvl = nla_get_u64(
			tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERY_RESPONSE_INTVL]);
		entry->mask |=
			BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_RESPONSE_INTVL;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL]) {
		entry->o_mcast_startup_query_intvl = nla_get_u64(
			tb[BRIDGE_VLANDB_GOPTS_MCAST_STARTUP_QUERY_INTVL]);
		entry->mask |=
			BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_INTVL;
	}

	if (tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERIER]) {
		entry->o_mcast_querier =
			nla_get_u8(tb[BRIDGE_VLANDB_GOPTS_MCAST_QUERIER]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER;
	}

	/* TODO: Implement support for:
	 * - BRIDGE_VLANDB_GOPTS_MCAST_ROUTER_PORTS
	 * - BRIDGE_VLANDB_GOPTS_MCAST_QUERIER_STATE
	 * These are only sent from the kernel and are nested attributes.
	 */

	if (tb[BRIDGE_VLANDB_GOPTS_MSTI]) {
		entry->o_msti = nla_get_u16(tb[BRIDGE_VLANDB_GOPTS_MSTI]);
		entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MSTI;
	}
}

static int gopts_add_entry_no_clone(struct rtnl_br_vlan_gopts *gopts,
				    struct rtnl_br_vlan_gopts_entry *entry,
				    bool allow_replacement)
{
	struct rtnl_br_vlan_gopts_entry *pos;
	struct rtnl_br_vlan_gopts_entry *npos;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_VID))
		return -NLE_MISSING_ATTR;

	nl_list_for_each_entry_safe_reverse(pos, npos, &gopts->gopts_list,
					    list_node)
	{
		if (pos->vid < entry->vid)
			break;
		else if (pos->vid == entry->vid) {
			if (allow_replacement)
				rtnl_br_vlan_gopts_entry_free(pos);
			else
				return -NLE_EXIST;
		}
	}

	nl_list_insert_after(&entry->list_node, &pos->list_node);

	return NLE_SUCCESS;
}

static int gopts_parse_decompress_entry(struct nlattr *attr,
					struct rtnl_br_vlan_gopts *gopts)
{
	struct nlattr *tb[BRIDGE_VLANDB_GOPTS_MAX + 1];
	_nl_auto_rtnl_br_vlan_gopts_entry struct rtnl_br_vlan_gopts_entry
		*entry = NULL;
	struct rtnl_br_vlan_gopts_entry *entry_ref = NULL;
	uint16_t vid_start;
	uint16_t vid_end;
	int err;

	if (nla_type(attr) != BRIDGE_VLANDB_GLOBAL_OPTIONS)
		return -NLE_INVAL;

	if (nla_parse_nested(tb, BRIDGE_VLANDB_GOPTS_MAX, attr,
			     br_vlan_gopts_entry_policy) < 0)
		return -NLE_INVAL;

	if (!tb[BRIDGE_VLANDB_GOPTS_ID])
		return -NLE_INVAL;

	vid_start = nla_get_u16(tb[BRIDGE_VLANDB_GOPTS_ID]);

	if (tb[BRIDGE_VLANDB_GOPTS_RANGE])
		vid_end = nla_get_u16(tb[BRIDGE_VLANDB_GOPTS_RANGE]);
	else
		vid_end = vid_start;

	if (!(vid_start <= vid_end))
		return -NLE_INVAL;

	entry = rtnl_br_vlan_gopts_entry_alloc();
	if (entry == NULL)
		return -NLE_NOMEM;

	entry->vid = vid_start;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_VID;

	gopts_parse_entry_info_attrs(tb, entry);

	entry_ref = entry;

	err = gopts_add_entry_no_clone(gopts, entry, false);
	if (err < 0) {
		return -NLE_INVAL;
	}

	entry = NULL; /* Entry is consumed, don't allow auto-deallocation */

	/* Use uint32_t to ensure loop exits */
	for (uint32_t vid = (uint32_t)vid_start + 1; vid <= (uint32_t)vid_end;
	     vid++) {
		_nl_auto_rtnl_br_vlan_gopts_entry struct rtnl_br_vlan_gopts_entry
			*new_entry = NULL;

		new_entry = rtnl_br_vlan_gopts_entry_clone(entry_ref);
		if (new_entry == NULL)
			return -NLE_NOMEM;

		new_entry->vid = vid;

		err = gopts_add_entry_no_clone(gopts, new_entry, false);
		if (err < 0) {
			return -NLE_INVAL;
		}

		new_entry =
			NULL; /* Ensure consumed entry isn't auto-deallocated */
	}

	return NLE_SUCCESS;
}

static int gopts_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			    struct nlmsghdr *n, struct nl_parser_param *pp)
{
	_nl_auto_rtnl_br_vlan_gopts struct rtnl_br_vlan_gopts *gopts = NULL;
	struct br_vlan_msg *bvm;
	struct nlattr *attr;
	int remaining;
	int err;

	gopts = rtnl_br_vlan_gopts_alloc();
	if (gopts == NULL)
		return -NLE_NOMEM;

	if (n->nlmsg_type != RTM_NEWVLAN)
		return -NLE_PARSE_ERR;

	if (!nlmsg_valid_hdr(n, sizeof(*bvm)))
		return -NLE_MSG_TOOSHORT;

	bvm = nlmsg_data(n);

	if (bvm->family != AF_BRIDGE)
		return -NLE_PARSE_ERR;

	gopts->ifindex = bvm->ifindex;
	gopts->ce_mask = BR_VLAN_GOPTS_ATTR_IFINDEX;
	gopts->ce_msgtype = n->nlmsg_type;

	nlmsg_for_each_attr(attr, n, sizeof(*bvm), remaining) {
		if (nla_type(attr) == BRIDGE_VLANDB_GLOBAL_OPTIONS) {
			err = gopts_parse_decompress_entry(attr, gopts);
			if (err < 0)
				return err != -NLE_NOMEM ? -NLE_PARSE_ERR : err;
		}
	}

	return pp->pp_cb((struct nl_object *)gopts, pp);
}

/**
 * Construct RTM_GETVLAN netlink message to retrieve VLAN global options for a
 * single bridge master interface.
 * @arg ifindex		Interface index.
 * @arg result		Pointer to store resulting netlink message.
 *
 * The behaviour of this function is identical to
 * rtnl_br_vlan_gopts_get_kernel() with the exception that it will not send the
 * message but return it in the provided return pointer instead. The caller is
 * responsible for calling nlmsg_free() once it is done with the message.
 *
 * @see rtnl_br_vlan_gopts_get_kernel()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if ifindex is 0 or result is NULL.
 */
int rtnl_br_vlan_gopts_build_get_request(uint32_t ifindex,
					 struct nl_msg **result)
{
	_nl_auto_nl_msg struct nl_msg *msg = NULL;
	struct br_vlan_msg bvm = { 0 };
	uint32_t dump_flags = BRIDGE_VLANDB_DUMPF_GLOBAL;

	/* An ifindex of 0 would trigger a dump of all bridge master interfaces */
	if (ifindex == 0 || result == NULL)
		return -NLE_INVAL;

	msg = nlmsg_alloc_simple(RTM_GETVLAN, NLM_F_DUMP);
	if (msg == NULL)
		return -NLE_NOMEM;

	bvm.ifindex = ifindex;
	bvm.family = AF_BRIDGE;

	_NL_RETURN_ON_PUT_ERR(
		nlmsg_append(msg, &bvm, sizeof(bvm), NLMSG_ALIGNTO));

	_NL_RETURN_ON_PUT_ERR(
		nla_put_u32(msg, BRIDGE_VLANDB_DUMP_FLAGS, dump_flags));

	*result = _nl_steal_pointer(&msg);
	return NLE_SUCCESS;
}

/**
 * Get a gopts object directly from kernel.
 * @arg sk		Netlink socket.
 * @arg ifindex		Interface index.
 * @arg result		Pointer to store resulting link object.
 *
 * This function builds a \c RTM_GETVLAN netlink message to request global VLAN
 * options for all VLANs on a specific bridge master interface directly from the
 * kernel. The returned answer is parsed into a struct rtnl_br_vlan_gopts object
 * and returned via the result pointer.
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if sk or result is NULL, or ifindex is 0.
 */
int rtnl_br_vlan_gopts_get_kernel(struct nl_sock *sk, uint32_t ifindex,
				  struct rtnl_br_vlan_gopts **result)
{
	_nl_auto_rtnl_br_vlan_gopts struct rtnl_br_vlan_gopts *gopts = NULL;
	_nl_auto_nl_msg struct nl_msg *msg = NULL;
	int err;

	if (sk == NULL || result == NULL || ifindex == 0)
		return -NLE_INVAL;

	err = rtnl_br_vlan_gopts_build_get_request(ifindex, &msg);
	if (err < 0)
		return err;

	err = nl_send_auto(sk, msg);
	if (err < 0)
		return err;

	/* Global options information pertaining to a single bridge master
	 * device may be split across several messages, causing the parser
	 * function to be invoked multiple times. The oo_update function will
	 * be called in this case to merge partial objects into one. */
	err = nl_pickup(sk, gopts_msg_parser, (struct nl_object **)&gopts);
	if (err < 0)
		return err;

	/* An ack isn't sent, so don't wait for one */

	if (gopts && gopts->ifindex != ifindex)
		return -NLE_PARSE_ERR;

	if (gopts == NULL) {
		/* No entries returned, create empty gopts object.
		 * NOTE: ce_msgtype is not set in this case. */

		gopts = rtnl_br_vlan_gopts_alloc();
		if (gopts == NULL)
			return -NLE_NOMEM;

		rtnl_br_vlan_gopts_set_ifindex(gopts, ifindex);
	}

	*result = _nl_steal_pointer(&gopts);

	return NLE_SUCCESS;
}

/** @} */

/**
 * @name Attribute Modification
 * @{
 */

/**
 * Set the interface index for the given gopts object.
 * @arg gopts		gopts object.
 * @arg value		ifindex to set.
 *
 * The ifindex should correspond to an existing bridge master interface in the
 * kernel. An ifindex of 0 is not allowed.
 *
 * @see rtnl_br_vlan_gopts_get_ifindex()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts is NULL or value is 0.
 */
int rtnl_br_vlan_gopts_set_ifindex(struct rtnl_br_vlan_gopts *gopts,
				   uint32_t value)
{
	if (gopts == NULL || value == 0)
		return -NLE_INVAL;

	gopts->ifindex = value;
	gopts->ce_mask |= BR_VLAN_GOPTS_ATTR_IFINDEX;

	return NLE_SUCCESS;
}

/**
 * Get the interface index for the given gopts object.
 * @arg gopts		gopts object.
 * @arg out		Pointer to store answer.
 *
 * @see rtnl_br_vlan_gopts_set_ifindex()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts or out is NULL.
 * @return -NLE_NOATTR if the ifindex is not currently set.
 */
int rtnl_br_vlan_gopts_get_ifindex(const struct rtnl_br_vlan_gopts *gopts,
				   uint32_t *out)
{
	if (gopts == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(gopts->ce_mask & BR_VLAN_GOPTS_ATTR_IFINDEX))
		return -NLE_NOATTR;

	*out = gopts->ifindex;

	return NLE_SUCCESS;
}

static struct rtnl_br_vlan_gopts_entry *
gopts_list_find_entry_before(const struct nl_list_head *gopts_list,
			     uint16_t vid)
{
	struct rtnl_br_vlan_gopts_entry *pos;

	nl_list_for_each_entry_reverse(pos, gopts_list, list_node)
	{
		if (pos->vid < vid)
			break;
	}

	return pos;
}

static struct rtnl_br_vlan_gopts_entry *
gopts_list_get_entry_after(const struct nl_list_head *gopts_list,
			   const struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry->list_node.next == gopts_list)
		return NULL;

	return nl_list_entry(entry->list_node.next,
			     struct rtnl_br_vlan_gopts_entry, list_node);
}

static uint32_t
gopts_list_clear_smaller_eq_after(struct nl_list_head *gopts_list,
				  struct rtnl_br_vlan_gopts_entry *entry,
				  uint16_t vid)
{
	struct rtnl_br_vlan_gopts_entry *next_entry;
	uint32_t count = 0;

	while (next_entry = gopts_list_get_entry_after(gopts_list, entry),
	       next_entry && next_entry->vid <= vid) {
		rtnl_br_vlan_gopts_entry_free(next_entry);
		count++;
	}

	return count;
}

static void gopts_list_free(struct nl_list_head *gopts_list)
{
	struct rtnl_br_vlan_gopts_entry *entry;
	struct rtnl_br_vlan_gopts_entry *entry_next;

	nl_list_for_each_entry_safe(entry, entry_next, gopts_list, list_node)
		rtnl_br_vlan_gopts_entry_free(entry);
}

/**
 * Set a single entry in the given gopts object.
 * @arg gopts		gopts object to modify.
 * @arg entry		gopts entry to set (used as a reference).
 *
 * Sets options for a single VLAN ID. If an entry already exists with the same
 * VID, it will be replaced.
 *
 * @note The supplied entry is not consumed by this function, it is just cloned.
 *	 Therefore the caller still has to free the entry at some point.
 *
 * @see rtnl_br_vlan_gopts_set_entry_range()
 * @see rtnl_br_vlan_gopts_unset_entry()
 * @see rtnl_br_vlan_gopts_unset_entry_range()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts or entry is NULL.
 * @return -NLE_MISSING_ATTR if entry does not have VLAN ID set.
 */
int rtnl_br_vlan_gopts_set_entry(struct rtnl_br_vlan_gopts *gopts,
				 const struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	return rtnl_br_vlan_gopts_set_entry_range(gopts, entry, entry->vid);
}

/**
 * Set a range of entries with consecutive VLAN IDs in the given gopts object.
 * @arg gopts		gopts object to modify.
 * @arg entry		gopts entry to use as a reference. Its VLAN ID marks the
 *			start of the range, and must be set.
 * @arg vid_end		VLAN ID of the end of the range (inclusive).
 *
 * Sets options for a range of VLAN IDs. Any existing entries with a VID that
 * falls within the given range will be replaced.
 *
 * @note The supplied entry is not consumed by this function, it is just cloned.
 *	 Therefore the caller still has to free the entry at some point.
 *
 * @see rtnl_br_vlan_gopts_set_entry()
 * @see rtnl_br_vlan_gopts_unset_entry()
 * @see rtnl_br_vlan_gopts_unset_entry_range()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts or entry is NULL, or the range is invalid (end is
 *	   less than start or greater than 4094).
 * @return -NLE_MISSING_ATTR if entry does not have VLAN ID set.
 */
int rtnl_br_vlan_gopts_set_entry_range(
	struct rtnl_br_vlan_gopts *gopts,
	const struct rtnl_br_vlan_gopts_entry *entry, uint16_t vid_end)
{
	uint16_t vid_start;
	struct rtnl_br_vlan_gopts_entry *entry_before;
	struct nl_list_head new_entries;

	if (gopts == NULL || entry == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_VID))
		return -NLE_MISSING_ATTR;

	vid_start = entry->vid;

	if (!(vid_end > 0 && vid_end < VLAN_VID_MASK))
		return -NLE_INVAL;

	if (!(vid_start <= vid_end))
		return -NLE_INVAL;

	nl_init_list_head(&new_entries);

	for (uint16_t vid = vid_start; vid <= vid_end; vid++) {
		struct rtnl_br_vlan_gopts_entry *new_entry;

		new_entry = rtnl_br_vlan_gopts_entry_clone(entry);
		if (new_entry == NULL) {
			gopts_list_free(&new_entries);
			return -NLE_NOMEM;
		}

		new_entry->vid = vid;
		new_entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_VID;

		nl_list_add_tail(&new_entry->list_node, &new_entries);
	}

	entry_before =
		gopts_list_find_entry_before(&gopts->gopts_list, vid_start);

	gopts_list_clear_smaller_eq_after(&gopts->gopts_list, entry_before,
					  vid_end);

	nl_list_insert_list_after(&new_entries, &entry_before->list_node);

	return NLE_SUCCESS;
}

/**
 * Unset a single entry in the given gopts object.
 * @arg gopts		gopts object to modify.
 * @arg vid		VLAN ID identifying the entry.
 *
 * Removes the entry with the VLAN ID matching the given vid.
 *
 * @see rtnl_br_vlan_gopts_unset_entry_range()
 * @see rtnl_br_vlan_gopts_set_entry()
 * @see rtnl_br_vlan_gopts_set_entry_range()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts is NULL.
 * @return -NLE_OBJ_NOTFOUND if an entry with the given VID isn't found.
 */
int rtnl_br_vlan_gopts_unset_entry(struct rtnl_br_vlan_gopts *gopts,
				   uint16_t vid)
{
	return rtnl_br_vlan_gopts_unset_entry_range(gopts, vid, vid);
}

/**
 * Unset a range of entries with consecutive VLAN IDs in the given gopts object.
 * @arg gopts		gopts object to modify.
 * @arg vid_start	VLAN ID of start of range.
 * @arg vid_end		VLAN ID of end of range (inclusive).
 *
 * Removes any entries from the gopts object that have a VLAN ID that falls
 * within the given range. It is expected that at least one entry exists in this
 * range.
 *
 * @see rtnl_br_vlan_gopts_unset_entry()
 * @see rtnl_br_vlan_gopts_set_entry()
 * @see rtnl_br_vlan_gopts_set_entry_range()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts is NULL, or the range is invalid (end is less
 *	   than start).
 * @return -NLE_OBJ_NOTFOUND if no entries exist with a VLAN ID within the given
 *	   range.
 */
int rtnl_br_vlan_gopts_unset_entry_range(struct rtnl_br_vlan_gopts *gopts,
					 uint16_t vid_start, uint16_t vid_end)
{
	struct rtnl_br_vlan_gopts_entry *entry_before;
	uint32_t num_entries_deleted;

	if (gopts == NULL)
		return -NLE_INVAL;

	if (!(vid_start <= vid_end))
		return -NLE_INVAL;

	entry_before =
		gopts_list_find_entry_before(&gopts->gopts_list, vid_start);

	num_entries_deleted = gopts_list_clear_smaller_eq_after(
		&gopts->gopts_list, entry_before, vid_end);

	return num_entries_deleted > 0 ? NLE_SUCCESS : -NLE_OBJ_NOTFOUND;
}

/**
 * Get the entry with the given VLAN ID.
 * @arg gopts		gopts object.
 * @arg vid		VLAN ID to lookup.
 * @arg out		Pointer to store resulting reference to gopts entry.
 *
 * The returned entry is a reference to an entry in \a gopts. This allows entry
 * property modifications to be made.
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts or out is NULL.
 * @return -NLE_OBJ_NOTFOUND if an entry with the given VID isn't found.
 */
int rtnl_br_vlan_gopts_get_entry(const struct rtnl_br_vlan_gopts *gopts,
				 uint16_t vid,
				 struct rtnl_br_vlan_gopts_entry **out)
{
	struct rtnl_br_vlan_gopts_entry *entry_before;

	if (gopts == NULL || out == NULL)
		return -NLE_INVAL;

	entry_before = gopts_list_find_entry_before(&gopts->gopts_list, vid);

	if (entry_before->list_node.next != &gopts->gopts_list) {
		struct rtnl_br_vlan_gopts_entry *entry;

		entry = nl_list_entry(entry_before->list_node.next,
				      struct rtnl_br_vlan_gopts_entry,
				      list_node);

		if (entry->vid == vid) {
			*out = entry;
			return NLE_SUCCESS;
		}
	}

	return -NLE_OBJ_NOTFOUND;
}

/**
 * Iterate over each gopts entry.
 * @arg gopts		gopts object.
 * @arg cb		Callback function called for each entry. Entry
 *			properties may be modified but entries may not be added
 *			or removed during iteration.
 * @arg arg		Arbitrary data argument passed to callback function.
 *
 * Iterates over each entry in the given gopts object in ascending VID order.
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if gopts or cb is NULL.
 */
int rtnl_br_vlan_gopts_foreach_gopts_entry(
	const struct rtnl_br_vlan_gopts *gopts,
	void (*cb)(struct rtnl_br_vlan_gopts_entry *entry, void *arg),
	void *arg)
{
	struct rtnl_br_vlan_gopts_entry *entry;
	struct rtnl_br_vlan_gopts_entry *next_entry;

	if (gopts == NULL || cb == NULL)
		return -NLE_INVAL;

	nl_list_for_each_entry_safe(entry, next_entry, &gopts->gopts_list,
				    list_node) {
		cb(entry, arg);
	}

	return NLE_SUCCESS;
}

/**
 * Set the VLAN ID of a standalone gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @note To be standalone means that the entry does not belong to a gopts
 *	 object.
 *
 * @see rtnl_br_vlan_gopts_entry_get_vid()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL or value is not in the range 1-4094.
 * @return -NLE_OPNOTSUPP if entry is not standalone
 */
int rtnl_br_vlan_gopts_entry_set_vid(struct rtnl_br_vlan_gopts_entry *entry,
				     uint16_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	if (!nl_list_empty(&entry->list_node))
		return -NLE_OPNOTSUPP;

	if (!(value > 0 && value < VLAN_VID_MASK))
		return -NLE_INVAL;

	entry->vid = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_VID;

	return NLE_SUCCESS;
}

/**
 * Get the VLAN ID of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_vid()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_vid(
	const struct rtnl_br_vlan_gopts_entry *entry, uint16_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_VID))
		return -NLE_NOATTR;

	*out = entry->vid;

	return NLE_SUCCESS;
}

/**
 * Set the mcast snooping value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_snooping()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_snooping()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_snooping = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_SNOOPING;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast snooping value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_snooping()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_snooping()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_snooping = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_SNOOPING;

	return NLE_SUCCESS;
}

/**
 * Get the mcast snooping value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_snooping()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_snooping()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_snooping(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_SNOOPING))
		return -NLE_NOATTR;

	*out = entry->o_mcast_snooping;

	return NLE_SUCCESS;
}

/**
 * Set the mcast igmp version value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_igmp_version()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_igmp_version()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_igmp_version = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_IGMP_VERSION;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast igmp version value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_igmp_version()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_igmp_version()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_igmp_version = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_IGMP_VERSION;

	return NLE_SUCCESS;
}

/**
 * Get the mcast igmp version value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_igmp_version()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_igmp_version()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_igmp_version(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_IGMP_VERSION))
		return -NLE_NOATTR;

	*out = entry->o_mcast_igmp_version;

	return NLE_SUCCESS;
}

/**
 * Set the mcast mld version value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_mld_version()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_mld_version()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_mld_version = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MLD_VERSION;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast mld version value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_mld_version()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_mld_version()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_mld_version = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MLD_VERSION;

	return NLE_SUCCESS;
}

/**
 * Get the mcast mld version value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_mld_version()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_mld_version()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_mld_version(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MLD_VERSION))
		return -NLE_NOATTR;

	*out = entry->o_mcast_mld_version;

	return NLE_SUCCESS;
}

/**
 * Set the mcast last member cnt value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_last_member_cnt()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_last_member_cnt()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *entry, uint32_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_last_member_cnt = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_CNT;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast last member cnt value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_last_member_cnt()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_last_member_cnt()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_last_member_cnt = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_CNT;

	return NLE_SUCCESS;
}

/**
 * Get the mcast last member cnt value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_last_member_cnt()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_last_member_cnt()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_last_member_cnt(
	const struct rtnl_br_vlan_gopts_entry *entry, uint32_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_CNT))
		return -NLE_NOATTR;

	*out = entry->o_mcast_last_member_cnt;

	return NLE_SUCCESS;
}

/**
 * Set the mcast startup query cnt value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_startup_query_cnt()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_cnt()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *entry, uint32_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_startup_query_cnt = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_CNT;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast startup query cnt value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_startup_query_cnt()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_startup_query_cnt()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_startup_query_cnt = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_CNT;

	return NLE_SUCCESS;
}

/**
 * Get the mcast startup query cnt value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_startup_query_cnt()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_cnt()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_cnt(
	const struct rtnl_br_vlan_gopts_entry *entry, uint32_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_CNT))
		return -NLE_NOATTR;

	*out = entry->o_mcast_startup_query_cnt;

	return NLE_SUCCESS;
}

/**
 * Set the mcast last member intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_last_member_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_last_member_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_last_member_intvl = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_INTVL;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast last member intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_last_member_intvl()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_last_member_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_last_member_intvl = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_INTVL;

	return NLE_SUCCESS;
}

/**
 * Get the mcast last member intvl value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_last_member_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_last_member_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_last_member_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_LAST_MEMBER_INTVL))
		return -NLE_NOATTR;

	*out = entry->o_mcast_last_member_intvl;

	return NLE_SUCCESS;
}

/**
 * Set the mcast membership intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_membership_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_membership_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_membership_intvl = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MEMBERSHIP_INTVL;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast membership intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_membership_intvl()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_membership_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_membership_intvl = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MEMBERSHIP_INTVL;

	return NLE_SUCCESS;
}

/**
 * Get the mcast membership intvl value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_membership_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_membership_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_membership_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_MEMBERSHIP_INTVL))
		return -NLE_NOATTR;

	*out = entry->o_mcast_membership_intvl;

	return NLE_SUCCESS;
}

/**
 * Set the mcast querier intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_querier_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_querier_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_querier_intvl = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER_INTVL;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast querier intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_querier_intvl()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_querier_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_querier_intvl = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER_INTVL;

	return NLE_SUCCESS;
}

/**
 * Get the mcast querier intvl value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_querier_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_querier_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_querier_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER_INTVL))
		return -NLE_NOATTR;

	*out = entry->o_mcast_querier_intvl;

	return NLE_SUCCESS;
}

/**
 * Set the mcast query intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_query_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_query_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_query_intvl = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_INTVL;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast query intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_query_intvl()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_query_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_query_intvl = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_INTVL;

	return NLE_SUCCESS;
}

/**
 * Get the mcast query intvl value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_query_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_query_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_query_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_INTVL))
		return -NLE_NOATTR;

	*out = entry->o_mcast_query_intvl;

	return NLE_SUCCESS;
}

/**
 * Set the mcast query response intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_query_response_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_query_response_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_query_response_intvl = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_RESPONSE_INTVL;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast query response intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_query_response_intvl()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_query_response_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_query_response_intvl = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_RESPONSE_INTVL;

	return NLE_SUCCESS;
}

/**
 * Get the mcast query response intvl value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_query_response_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_query_response_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_query_response_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask &
	      BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERY_RESPONSE_INTVL))
		return -NLE_NOATTR;

	*out = entry->o_mcast_query_response_intvl;

	return NLE_SUCCESS;
}

/**
 * Set the mcast startup query intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_startup_query_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_startup_query_intvl = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_INTVL;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast startup query intvl value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_startup_query_intvl()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_startup_query_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_startup_query_intvl = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_INTVL;

	return NLE_SUCCESS;
}

/**
 * Get the mcast startup query intvl value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_startup_query_intvl()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_intvl()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_STARTUP_QUERY_INTVL))
		return -NLE_NOATTR;

	*out = entry->o_mcast_startup_query_intvl;

	return NLE_SUCCESS;
}

/**
 * Set the mcast querier value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_mcast_querier()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_querier()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_querier = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER;

	return NLE_SUCCESS;
}

/**
 * Unset the mcast querier value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_querier()
 * @see rtnl_br_vlan_gopts_entry_get_mcast_querier()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_mcast_querier = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER;

	return NLE_SUCCESS;
}

/**
 * Get the mcast querier value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_mcast_querier()
 * @see rtnl_br_vlan_gopts_entry_unset_mcast_querier()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_mcast_querier(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MCAST_QUERIER))
		return -NLE_NOATTR;

	*out = entry->o_mcast_querier;

	return NLE_SUCCESS;
}

/**
 * Set the msti value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 * @arg value		Value to set.
 *
 * @see rtnl_br_vlan_gopts_entry_get_msti()
 * @see rtnl_br_vlan_gopts_entry_unset_msti()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_set_msti(struct rtnl_br_vlan_gopts_entry *entry,
				      uint16_t value)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_msti = value;
	entry->mask |= BR_VLAN_GOPTS_ATTR_ENTRY_MSTI;

	return NLE_SUCCESS;
}

/**
 * Unset the msti value of a gopts entry.
 * @arg entry		gopts entry object to modify.
 *
 * @see rtnl_br_vlan_gopts_entry_set_msti()
 * @see rtnl_br_vlan_gopts_entry_get_msti()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry is NULL.
 */
int rtnl_br_vlan_gopts_entry_unset_msti(struct rtnl_br_vlan_gopts_entry *entry)
{
	if (entry == NULL)
		return -NLE_INVAL;

	entry->o_msti = 0;
	entry->mask &= ~BR_VLAN_GOPTS_ATTR_ENTRY_MSTI;

	return NLE_SUCCESS;
}

/**
 * Get the msti value of a gopts entry.
 * @arg entry		gopts entry object.
 * @arg out		Output argument.
 *
 * @see rtnl_br_vlan_gopts_entry_set_msti()
 * @see rtnl_br_vlan_gopts_entry_unset_msti()
 *
 * @return 0 on success or a negative error code.
 * @return -NLE_INVAL if entry or out is NULL.
 * @return -NLE_NOATTR if entry does not have the value set.
 */
int rtnl_br_vlan_gopts_entry_get_msti(
	const struct rtnl_br_vlan_gopts_entry *entry, uint16_t *out)
{
	if (entry == NULL || out == NULL)
		return -NLE_INVAL;

	if (!(entry->mask & BR_VLAN_GOPTS_ATTR_ENTRY_MSTI))
		return -NLE_NOATTR;

	*out = entry->o_msti;

	return NLE_SUCCESS;
}

/** @} */

static void gopts_constructor(struct nl_object *obj)
{
	struct rtnl_br_vlan_gopts *gopts = (struct rtnl_br_vlan_gopts *)obj;

	nl_init_list_head(&gopts->gopts_list);
}

static void gopts_free_data(struct nl_object *obj)
{
	struct rtnl_br_vlan_gopts *gopts = (struct rtnl_br_vlan_gopts *)obj;

	gopts_list_free(&gopts->gopts_list);
}

static bool gopts_lists_are_equal(const struct rtnl_br_vlan_gopts *a,
				  const struct rtnl_br_vlan_gopts *b)
{
	struct rtnl_br_vlan_gopts_entry *a_entry, *b_entry;

	a_entry = nl_list_entry(a->gopts_list.next,
				struct rtnl_br_vlan_gopts_entry, list_node);
	b_entry = nl_list_entry(b->gopts_list.next,
				struct rtnl_br_vlan_gopts_entry, list_node);

	while (true) {
		bool checked_all_a_entries = &a_entry->list_node ==
					     &a->gopts_list;
		bool checked_all_b_entries = &b_entry->list_node ==
					     &b->gopts_list;

		if (checked_all_a_entries || checked_all_b_entries)
			return checked_all_a_entries && checked_all_b_entries;

		if (!gopts_entries_are_equal(a_entry, b_entry, true)) {
			return false;
		}

		a_entry = nl_list_entry(a_entry->list_node.next,
					struct rtnl_br_vlan_gopts_entry,
					list_node);
		b_entry = nl_list_entry(b_entry->list_node.next,
					struct rtnl_br_vlan_gopts_entry,
					list_node);
	}
}

static uint64_t gopts_compare(struct nl_object *_a, struct nl_object *_b,
			      uint64_t attrs, int flags)
{
	const struct rtnl_br_vlan_gopts *a = (struct rtnl_br_vlan_gopts *)_a;
	const struct rtnl_br_vlan_gopts *b = (struct rtnl_br_vlan_gopts *)_b;
	uint64_t diff = 0;

#define _DIFF(ATTR, EXPR) ATTR_DIFF(attrs, ATTR, a, b, EXPR)
	diff |= _DIFF(BR_VLAN_GOPTS_ATTR_IFINDEX, a->ifindex != b->ifindex);
#undef _DIFF

	if (!gopts_lists_are_equal(a, b))
		diff |= BR_VLAN_GOPTS_ATTR_ENTRIES;

	return diff;
}

static int gopts_update(struct nl_object *old_obj, struct nl_object *new_obj)
{
	struct rtnl_br_vlan_gopts *existing_gopts =
		(struct rtnl_br_vlan_gopts *)old_obj;
	struct rtnl_br_vlan_gopts *new_gopts =
		(struct rtnl_br_vlan_gopts *)new_obj;
	int action = new_obj->ce_msgtype;

	if (action != RTM_NEWVLAN)
		return -NLE_OPNOTSUPP;

	if (new_gopts->ifindex != existing_gopts->ifindex)
		return -NLE_OPNOTSUPP;

	/* Ensure joining of sorted entry lists will result in a list that is
	 * still sorted */
	if (!nl_list_empty(&existing_gopts->gopts_list) &&
	    !nl_list_empty(&new_gopts->gopts_list)) {
		uint16_t first_list_end_vid =
			nl_list_last_entry(&existing_gopts->gopts_list,
					   struct rtnl_br_vlan_gopts_entry,
					   list_node)
				->vid;
		uint16_t second_list_start_vid =
			nl_list_first_entry(&new_gopts->gopts_list,
					    struct rtnl_br_vlan_gopts_entry,
					    list_node)
				->vid;

		if (!(first_list_end_vid < second_list_start_vid))
			return -NLE_INVAL;
	}

	/* Steal the entries from new_gopts and append them to existing_gopts */
	nl_list_join(&existing_gopts->gopts_list, &new_gopts->gopts_list);

	return NLE_SUCCESS;
}

static struct nl_object_ops obj_ops = {
	.oo_name = "route/br_vlan_global_opts",
	.oo_size = sizeof(struct rtnl_br_vlan_gopts),
	.oo_id_attrs = BR_VLAN_GOPTS_ATTR_IFINDEX,
	.oo_constructor = gopts_constructor,
	.oo_free_data = gopts_free_data,
	.oo_clone = gopts_clone,
	.oo_compare = gopts_compare,
	.oo_update = gopts_update,
};

/** @} */
