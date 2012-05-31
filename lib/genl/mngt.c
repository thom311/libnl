/*
 * lib/genl/mngt.c		Generic Netlink Management
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2012 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup genl
 * @defgroup genl_mngt Family and Operations Management
 *
 * Registering Generic Netlink Families and Commands
 *
 * @{
 */

#include <netlink-generic.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/mngt.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <netlink/utils.h>

/** @cond SKIP */

static NL_LIST_HEAD(genl_ops_list);

static int genl_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			   struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	int i, err;
	struct genlmsghdr *ghdr;
	struct genl_cmd *cmd;

	ghdr = nlmsg_data(nlh);

	if (ops->co_genl == NULL)
		BUG();

	for (i = 0; i < ops->co_genl->o_ncmds; i++) {
		cmd = &ops->co_genl->o_cmds[i];
		if (cmd->c_id == ghdr->cmd)
			goto found;
	}

	err = -NLE_MSGTYPE_NOSUPPORT;
	goto errout;

found:
	if (cmd->c_msg_parser == NULL)
		err = -NLE_OPNOTSUPP;
	else {
		struct nlattr *tb[cmd->c_maxattr + 1];
		struct genl_info info = {
			.who = who,
			.nlh = nlh,
			.genlhdr = ghdr,
			.userhdr = genlmsg_data(ghdr),
			.attrs = tb,
		};

		err = nlmsg_parse(nlh, ops->co_hdrsize, tb, cmd->c_maxattr,
				  cmd->c_attr_policy);
		if (err < 0)
			goto errout;

		err = cmd->c_msg_parser(ops, cmd, &info, pp);
	}
errout:
	return err;

}

char *genl_op2name(int family, int op, char *buf, size_t len)
{
	struct genl_ops *ops;
	int i;

	nl_list_for_each_entry(ops, &genl_ops_list, o_list) {
		if (ops->o_family == family) {
			for (i = 0; i < ops->o_ncmds; i++) {
				struct genl_cmd *cmd;
				cmd = &ops->o_cmds[i];

				if (cmd->c_id == op) {
					strncpy(buf, cmd->c_name, len - 1);
					return buf;
				}
			}
		}
	}

	strncpy(buf, "unknown", len - 1);
	return NULL;
}

/** @endcond */

/**
 * @name Registration (Cache Based)
 * @{
 */

/**
 * Register Generic Netlink family backed cache
 * @arg ops		Cache operations definition
 *
 * @return 0 on success or a negative error code.
 */
int genl_register(struct nl_cache_ops *ops)
{
	int err;

	if (ops->co_protocol != NETLINK_GENERIC) {
		err = -NLE_PROTO_MISMATCH;
		goto errout;
	}

	if (ops->co_hdrsize < GENL_HDRSIZE(0)) {
		err = -NLE_INVAL;
		goto errout;
	}

	if (ops->co_genl == NULL) {
		err = -NLE_INVAL;
		goto errout;
	}

	ops->co_genl->o_cache_ops = ops;
	ops->co_genl->o_name = ops->co_msgtypes[0].mt_name;
	ops->co_genl->o_family = ops->co_msgtypes[0].mt_id;
	ops->co_msg_parser = genl_msg_parser;

	/* FIXME: check for dup */

	nl_list_add_tail(&ops->co_genl->o_list, &genl_ops_list);

	err = nl_cache_mngt_register(ops);
errout:
	return err;
}

/**
 * Unregister cache based Generic Netlink family
 * @arg ops		Cache operations definition
 */
void genl_unregister(struct nl_cache_ops *ops)
{
	if (!ops)
		return;

	nl_cache_mngt_unregister(ops);
	nl_list_del(&ops->co_genl->o_list);
}

/** @} */

/** @cond SKIP */
static int __genl_ops_resolve(struct nl_cache *ctrl, struct genl_ops *ops)
{
	struct genl_family *family;

	family = genl_ctrl_search_by_name(ctrl, ops->o_name);
	if (family != NULL) {
		ops->o_id = genl_family_get_id(family);
		genl_family_put(family);

		return 0;
	}

	return -NLE_OBJ_NOTFOUND;
}
/** @endcond */

/**
 * @name Resolving the name of registered families
 * @{
 */

/**
 * Resolve a single Generic Netlink family
 * @arg sk		Generic Netlink socket
 * @arg ops		Generic Netlink family definition
 *
 * Resolves the family name to its numeric identifier.
 *
 * @return 0 on success or a negative error code.
 */
int genl_ops_resolve(struct nl_sock *sk, struct genl_ops *ops)
{
	struct nl_cache *ctrl;
	int err;

	if ((err = genl_ctrl_alloc_cache(sk, &ctrl)) < 0)
		goto errout;

	err = __genl_ops_resolve(ctrl, ops);

	nl_cache_free(ctrl);
errout:
	return err;
}

/**
 * Resolve all registered Generic Netlink families
 * @arg sk		Generic Netlink socket
 *
 * Walks through all local Generic Netlink families that have been registered
 * using genl_register() and resolves the name of each family to the
 * corresponding numeric identifier.
 *
 * @see genl_register()
 * @see genl_ops_resolve()
 *
 * @return 0 on success or a negative error code.
 */
int genl_mngt_resolve(struct nl_sock *sk)
{
	struct nl_cache *ctrl;
	struct genl_ops *ops;
	int err = 0;

	if ((err = genl_ctrl_alloc_cache(sk, &ctrl)) < 0)
		goto errout;

	nl_list_for_each_entry(ops, &genl_ops_list, o_list) {
		err = __genl_ops_resolve(ctrl, ops);
	}

	nl_cache_free(ctrl);
errout:
	return err;
}

/** @} */

/** @} */
