/*
 * lib/route/classifier.c       Classifier
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2009 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup tc
 * @defgroup cls Classifiers
 *
 * @par Classifier Identification
 * - protocol
 * - priority
 * - parent
 * - interface
 * - kind
 * - handle
 * 
 * @{
 */

#include <netlink-local.h>
#include <netlink-tc.h>
#include <netlink/netlink.h>
#include <netlink/utils.h>
#include <netlink/route/tc-api.h>
#include <netlink/route/classifier.h>
#include <netlink/route/link.h>

/** @cond SKIP */
#define CLS_ATTR_PRIO		(TCA_ATTR_MAX << 1)
#define CLS_ATTR_PROTOCOL	(TCA_ATTR_MAX << 2)
/** @endcond */

static struct nl_object_ops cls_obj_ops;
static struct nl_cache_ops rtnl_cls_ops;


static int cls_build(struct rtnl_cls *cls, int type, int flags,
		     struct nl_msg **result)
{
	int err, prio, proto;
	struct tcmsg *tchdr;

	err = rtnl_tc_msg_build(TC_CAST(cls), type, flags, result);
	if (err < 0)
		return err;

	tchdr = nlmsg_data(nlmsg_hdr(*result));
	prio = rtnl_cls_get_prio(cls);
	proto = rtnl_cls_get_protocol(cls);
	tchdr->tcm_info = TC_H_MAKE(prio << 16, htons(proto));

	return 0;
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct rtnl_cls *rtnl_cls_alloc(void)
{
	struct rtnl_tc *tc;

	tc = TC_CAST(nl_object_alloc(&cls_obj_ops));
	if (tc)
		tc->tc_type = RTNL_TC_TYPE_CLS;

	return (struct rtnl_cls *) tc;
}

void rtnl_cls_put(struct rtnl_cls *cls)
{
	nl_object_put((struct nl_object *) cls);
}

/** @} */

/**
 * @name Attributes
 * @{
 */

void rtnl_cls_set_prio(struct rtnl_cls *cls, uint16_t prio)
{
	cls->c_prio = prio;
	cls->ce_mask |= CLS_ATTR_PRIO;
}

uint16_t rtnl_cls_get_prio(struct rtnl_cls *cls)
{
	if (cls->ce_mask & CLS_ATTR_PRIO)
		return cls->c_prio;
	else
		return 0;
}

void rtnl_cls_set_protocol(struct rtnl_cls *cls, uint16_t protocol)
{
	cls->c_protocol = protocol;
	cls->ce_mask |= CLS_ATTR_PROTOCOL;
}

uint16_t rtnl_cls_get_protocol(struct rtnl_cls *cls)
{
	if (cls->ce_mask & CLS_ATTR_PROTOCOL)
		return cls->c_protocol;
	else
		return ETH_P_ALL;
}

/** @} */


/**
 * @name Classifier Addition/Modification/Deletion
 * @{
 */

/**
 * Build a netlink message to add a new classifier
 * @arg cls		classifier to add
 * @arg flags		additional netlink message flags
 * @arg result		Pointer to store resulting message.
 *
 * Builds a new netlink message requesting an addition of a classifier
 * The netlink message header isn't fully equipped with all relevant
 * fields and must be sent out via nl_send_auto_complete() or
 * supplemented as needed. \a classifier must contain the attributes of
 * the new classifier set via \c rtnl_cls_set_* functions. \a opts
 * may point to the clsasifier specific options.
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_cls_build_add_request(struct rtnl_cls *cls, int flags,
			       struct nl_msg **result)
{
	return cls_build(cls, RTM_NEWTFILTER, NLM_F_CREATE | flags, result);
}

/**
 * Add a new classifier
 * @arg sk		Netlink socket.
 * @arg cls 		classifier to add
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_cls_build_add_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been processed.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_cls_add(struct nl_sock *sk, struct rtnl_cls *cls, int flags)
{
	struct nl_msg *msg;
	int err;
	
	if ((err = rtnl_cls_build_add_request(cls, flags, &msg)) < 0)
		return err;
	
	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(sk);
}

/**
 * Build a netlink message to change classifier attributes
 * @arg cls		classifier to change
 * @arg flags		additional netlink message flags
 * @arg result		Pointer to store resulting message.
 *
 * Builds a new netlink message requesting a change of a neigh
 * attributes. The netlink message header isn't fully equipped with
 * all relevant fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed.
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_cls_build_change_request(struct rtnl_cls *cls, int flags,
				  struct nl_msg **result)
{
	return cls_build(cls, RTM_NEWTFILTER, NLM_F_REPLACE | flags, result);
}

/**
 * Change a classifier
 * @arg sk		Netlink socket.
 * @arg cls		classifier to change
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_cls_build_change_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been processed.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_cls_change(struct nl_sock *sk, struct rtnl_cls *cls, int flags)
{
	struct nl_msg *msg;
	int err;
	
	if ((err = rtnl_cls_build_change_request(cls, flags, &msg)) < 0)
		return err;
	
	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(sk);
}

/**
 * Build a netlink request message to delete a classifier
 * @arg cls		classifier to delete
 * @arg flags		additional netlink message flags
 * @arg result		Pointer to store resulting message.
 *
 * Builds a new netlink message requesting a deletion of a classifier.
 * The netlink message header isn't fully equipped with all relevant
 * fields and must thus be sent out via nl_send_auto_complete()
 * or supplemented as needed.
 *
 * @return 0 on success or a negative error code.
 */
int rtnl_cls_build_delete_request(struct rtnl_cls *cls, int flags,
				  struct nl_msg **result)
{
	return cls_build(cls, RTM_DELTFILTER, flags, result);
}


/**
 * Delete a classifier
 * @arg sk		Netlink socket.
 * @arg cls		classifier to delete
 * @arg flags		additional netlink message flags
 *
 * Builds a netlink message by calling rtnl_cls_build_delete_request(),
 * sends the request to the kernel and waits for the next ACK to be
 * received and thus blocks until the request has been processed.
 *
 * @return 0 on sucess or a negative error if an error occured.
 */
int rtnl_cls_delete(struct nl_sock *sk, struct rtnl_cls *cls, int flags)
{
	struct nl_msg *msg;
	int err;
	
	if ((err = rtnl_cls_build_delete_request(cls, flags, &msg)) < 0)
		return err;
	
	err = nl_send_auto_complete(sk, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(sk);
}

/** @} */

/**
 * @name Cache Management
 * @{
 */

/**
 * Build a classifier cache including all classifiers attached to the
 * specified class/qdisc on eht specified interface.
 * @arg sk		Netlink socket.
 * @arg ifindex		interface index of the link the classes are
 *                      attached to.
 * @arg parent          parent qdisc/class
 * @arg result		Pointer to store resulting cache.
 *
 * Allocates a new cache, initializes it properly and updates it to
 * include all classes attached to the specified interface.
 *
 * @note The caller is responsible for destroying and freeing the
 *       cache after using it.
 * @return 0 on success or a negative error code.
 */
int rtnl_cls_alloc_cache(struct nl_sock *sk, int ifindex, uint32_t parent,			 struct nl_cache **result)
{
	struct nl_cache * cache;
	int err;
	
	if (!(cache = nl_cache_alloc(&rtnl_cls_ops)))
		return -NLE_NOMEM;

	cache->c_iarg1 = ifindex;
	cache->c_iarg2 = parent;
	
	if (sk && (err = nl_cache_refill(sk, cache)) < 0) {
		nl_cache_free(cache);
		return err;
	}

	*result = cache;
	return 0;
}

/** @} */

static void cls_dump_line(struct rtnl_tc *tc, struct nl_dump_params *p)
{
	struct rtnl_cls *cls = (struct rtnl_cls *) tc;
	char buf[32];

	nl_dump(p, " prio %u protocol %s", cls->c_prio,
		nl_ether_proto2str(cls->c_protocol, buf, sizeof(buf)));
}

static int cls_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			  struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	struct rtnl_cls *cls;
	int err;

	if (!(cls = rtnl_cls_alloc()))
		return -NLE_NOMEM;

	if ((err = rtnl_tc_msg_parse(nlh, TC_CAST(cls))) < 0)
		goto errout;

	cls->c_prio = TC_H_MAJ(cls->c_info) >> 16;
	cls->c_protocol = ntohs(TC_H_MIN(cls->c_info));

	err = pp->pp_cb(OBJ_CAST(cls), pp);
errout:
	rtnl_cls_put(cls);

	return err;
}

static int cls_request_update(struct nl_cache *cache, struct nl_sock *sk)
{
	struct tcmsg tchdr = {
		.tcm_family = AF_UNSPEC,
		.tcm_ifindex = cache->c_iarg1,
		.tcm_parent = cache->c_iarg2,
	};

	return nl_send_simple(sk, RTM_GETTFILTER, NLM_F_DUMP, &tchdr,
			      sizeof(tchdr));
}

static struct rtnl_tc_type_ops cls_ops = {
	.tt_type		= RTNL_TC_TYPE_CLS,
	.tt_dump_prefix		= "cls",
	.tt_dump = {
		[NL_DUMP_LINE]	= cls_dump_line,
	},
};

static struct nl_cache_ops rtnl_cls_ops = {
	.co_name		= "route/cls",
	.co_hdrsize		= sizeof(struct tcmsg),
	.co_msgtypes		= {
					{ RTM_NEWTFILTER, NL_ACT_NEW, "new" },
					{ RTM_DELTFILTER, NL_ACT_DEL, "del" },
					{ RTM_GETTFILTER, NL_ACT_GET, "get" },
					END_OF_MSGTYPES_LIST,
				  },
	.co_protocol		= NETLINK_ROUTE,
	.co_request_update	= cls_request_update,
	.co_msg_parser		= cls_msg_parser,
	.co_obj_ops		= &cls_obj_ops,
};

static struct nl_object_ops cls_obj_ops = {
	.oo_name		= "route/cls",
	.oo_size		= sizeof(struct rtnl_cls),
	.oo_free_data		= rtnl_tc_free_data,
	.oo_clone		= rtnl_tc_clone,
	.oo_dump = {
	    [NL_DUMP_LINE]	= rtnl_tc_dump_line,
	    [NL_DUMP_DETAILS]	= rtnl_tc_dump_details,
	    [NL_DUMP_STATS]	= rtnl_tc_dump_stats,
	},
	.oo_compare		= rtnl_tc_compare,
	.oo_id_attrs		= (TCA_ATTR_IFINDEX | TCA_ATTR_HANDLE),
};

static void __init cls_init(void)
{
	rtnl_tc_type_register(&cls_ops);
	nl_cache_mngt_register(&rtnl_cls_ops);
}

static void __exit cls_exit(void)
{
	nl_cache_mngt_unregister(&rtnl_cls_ops);
	rtnl_tc_type_unregister(&cls_ops);
}

/** @} */
