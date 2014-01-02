/*
 * lib/route/link/veth.c	Virtual Ethernet
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2013 Cong Wang <xiyou.wangcong@gmail.com>
 */

/**
 * @ingroup link
 * @defgroup veth VETH
 * Virtual Ethernet
 *
 * @details
 * \b Link Type Name: "veth"
 *
 * @route_doc{link_veth, VETH Documentation}
 *
 * @{
 */

#include <netlink-private/netlink.h>
#include <netlink/netlink.h>
#include <netlink/attr.h>
#include <netlink/utils.h>
#include <netlink/object.h>
#include <netlink/route/rtnl.h>
#include <netlink-private/route/link/api.h>
#include <netlink/route/link/veth.h>

#include <linux/if_link.h>

static struct nla_policy veth_policy[VETH_INFO_MAX+1] = {
	[VETH_INFO_PEER]	= { .minlen = sizeof(struct ifinfomsg) },
};

static int veth_parse(struct rtnl_link *link, struct nlattr *data,
		      struct nlattr *xstats)
{
	struct nlattr *tb[VETH_INFO_MAX+1];
	struct nlattr *peer_tb[IFLA_MAX + 1];
	struct rtnl_link *peer = link->l_info;
	int err;

	NL_DBG(3, "Parsing veth link info");

	if ((err = nla_parse_nested(tb, VETH_INFO_MAX, data, veth_policy)) < 0)
		goto errout;

	if (tb[VETH_INFO_PEER]) {
		struct nlattr *nla_peer;
		struct ifinfomsg *ifi;

		nla_peer = tb[VETH_INFO_PEER];
		ifi = nla_data(nla_peer);

		peer->l_family = ifi->ifi_family;
		peer->l_arptype = ifi->ifi_type;
		peer->l_index = ifi->ifi_index;
		peer->l_flags = ifi->ifi_flags;
		peer->l_change = ifi->ifi_change;
		err = nla_parse(peer_tb, IFLA_MAX,
				nla_data(nla_peer) + sizeof(struct ifinfomsg),
				nla_len(nla_peer) - sizeof(struct ifinfomsg),
				rtln_link_policy);
		if (err < 0)
			goto errout;

		err = rtnl_link_info_parse(peer, peer_tb);
		if (err < 0)
			goto errout;
	}

	err = 0;

errout:
	return err;
}

static void veth_dump_line(struct rtnl_link *link, struct nl_dump_params *p)
{
}

static void veth_dump_details(struct rtnl_link *link, struct nl_dump_params *p)
{
	struct rtnl_link *peer = link->l_info;
	char *name;
	name = rtnl_link_get_name(peer);
	nl_dump(p, "      peer ");
	if (name)
		nl_dump_line(p, "%s\n", name);
	else
		nl_dump_line(p, "%u\n", peer->l_index);
}

static int veth_clone(struct rtnl_link *dst, struct rtnl_link *src)
{
	struct rtnl_link *dst_peer , *src_peer = src->l_info;
	int err;

	dst_peer = dst->l_info = rtnl_link_alloc();
	if (!dst_peer || !src_peer)
		return -NLE_NOMEM;
	if ((err = rtnl_link_set_type(dst, "veth")) < 0) {
		rtnl_link_put(dst_peer);
		return err;
	}

	memcpy(dst_peer, src_peer, sizeof(struct rtnl_link));

	return 0;
}

static int veth_put_attrs(struct nl_msg *msg, struct rtnl_link *link)
{
	struct rtnl_link *peer = link->l_info;
	struct ifinfomsg ifi;
	struct nlattr *data, *info_peer;

	memset(&ifi, 0, sizeof ifi);
	ifi.ifi_family = peer->l_family;
	ifi.ifi_type = peer->l_arptype;
	ifi.ifi_index = peer->l_index;
	ifi.ifi_flags = peer->l_flags;
	ifi.ifi_change = peer->l_change;

	if (!(data = nla_nest_start(msg, IFLA_INFO_DATA)))
		return -NLE_MSGSIZE;
	if (!(info_peer = nla_nest_start(msg, VETH_INFO_PEER)))
		return -NLE_MSGSIZE;
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		return -NLE_MSGSIZE;
	rtnl_link_fill_info(msg, peer);
	nla_nest_end(msg, info_peer);
	nla_nest_end(msg, data);

	return 0;
}

static struct rtnl_link_info_ops veth_info_ops = {
	.io_name		= "veth",
	.io_parse		= veth_parse,
	.io_dump = {
	    [NL_DUMP_LINE]	= veth_dump_line,
	    [NL_DUMP_DETAILS]	= veth_dump_details,
	},
	.io_clone		= veth_clone,
	.io_put_attrs		= veth_put_attrs,
};

/** @cond SKIP */

#define IS_VETH_LINK_ASSERT(link) \
	if ((link)->l_info_ops != &veth_info_ops) { \
		APPBUG("Link is not a veth link. set type \"veth\" first."); \
		return NULL; \
	}
/** @endcond */

/**
 * @name VETH Object
 * @{
 */

/**
 * Allocate link object of type veth
 *
 * @return Allocated link object or NULL.
 */
struct rtnl_link *rtnl_link_veth_alloc(void)
{
	struct rtnl_link *link, *peer;
	int err;

	if (!(link = rtnl_link_alloc()))
		return NULL;
	if (!(peer = rtnl_link_alloc())) {
		rtnl_link_put(link);
		return NULL;
	}

	if ((err = rtnl_link_set_type(link, "veth")) < 0) {
		rtnl_link_put(peer);
		rtnl_link_put(link);
		return NULL;
	}
	if ((err = rtnl_link_set_type(peer, "veth")) < 0) {
		rtnl_link_put(peer);
		rtnl_link_put(link);
		return NULL;
	}

	link->l_info = peer;
	peer->l_info = link;
	return link;
}

/**
 * Get the peer link of a veth link
 *
 * @return the peer link object.
 */
struct rtnl_link *rtnl_link_veth_get_peer(struct rtnl_link *link)
{
	IS_VETH_LINK_ASSERT(link);
	return link->l_info;
}

/**
 * Release a veth link and its peer
 *
 */
void rtnl_link_veth_release(struct rtnl_link *link)
{
	struct rtnl_link *peer = rtnl_link_veth_get_peer(link);
	rtnl_link_put(peer);
	rtnl_link_put(link);
}

/**
 * Check if link is a veth link
 * @arg link		Link object
 *
 * @return True if link is a veth link, otherwise false is returned.
 */
int rtnl_link_is_veth(struct rtnl_link *link)
{
	return link->l_info_ops && !strcmp(link->l_info_ops->io_name, "veth");
}

/**
 * Create a new kernel veth device
 * @arg sock		netlink socket
 * @arg name		name of the veth device or NULL
 * @arg peer_name	name of its peer or NULL
 * @arg pid		pid of the process in the new netns
 *
 * Creates a new veth device pair in the kernel and move the peer
 * to the network namespace where the process is. If no name is
 * provided, the kernel will automatically pick a name of the
 * form "veth%d" (e.g. veth0, veth1, etc.)
 *
 * @return 0 on success or a negative error code
 */
int rtnl_link_veth_add(struct nl_sock *sock, const char *name,
                       const char *peer_name, pid_t pid)
{
	struct rtnl_link *link, *peer;
	int err = -NLE_NOMEM;

	if (!(link = rtnl_link_veth_alloc()))
		return -NLE_NOMEM;
	peer = rtnl_link_veth_get_peer(link);

	if (name && peer_name) {
		rtnl_link_set_name(link, name);
		rtnl_link_set_name(peer, peer_name);
	}

	rtnl_link_set_ns_pid(peer, pid);
	err = rtnl_link_add(sock, link, NLM_F_CREATE);

	rtnl_link_put(peer);
	rtnl_link_put(link);

        return err;
}

/** @} */

static void __init veth_init(void)
{
	rtnl_link_register_info(&veth_info_ops);
}

static void __exit veth_exit(void)
{
	rtnl_link_unregister_info(&veth_info_ops);
}

/** @} */
