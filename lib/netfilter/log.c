/*
 * lib/netfilter/log.c	Netfilter Log
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
 * @defgroup log Log
 * @brief
 * @{
 */

#include <sys/types.h>
#include <linux/netfilter/nfnetlink_log.h>

#include <netlink-local.h>
#include <netlink/attr.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>

static struct nl_cache_ops nfnl_log_ops;

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

static struct nla_policy log_policy[NFULA_MAX+1] = {
	[NFULA_PACKET_HDR]		= {
		.minlen = sizeof(struct nfulnl_msg_packet_hdr)
	},
	[NFULA_MARK]			= { .type = NLA_U32 },
	[NFULA_TIMESTAMP]		= {
		.minlen = sizeof(struct nfulnl_msg_packet_timestamp)
	},
	[NFULA_IFINDEX_INDEV]		= { .type = NLA_U32 },
	[NFULA_IFINDEX_OUTDEV]		= { .type = NLA_U32 },
	[NFULA_IFINDEX_PHYSINDEV]	= { .type = NLA_U32 },
	[NFULA_IFINDEX_PHYSOUTDEV]	= { .type = NLA_U32 },
	[NFULA_HWADDR]			= {
		.minlen = sizeof(struct nfulnl_msg_packet_hw)
	},
	//[NFULA_PAYLOAD]
	[NFULA_PREFIX]			= { .type = NLA_STRING, },
	[NFULA_UID]			= { .type = NLA_U32 },
	[NFULA_SEQ]			= { .type = NLA_U32 },
	[NFULA_SEQ_GLOBAL]		= { .type = NLA_U32 },
};

struct nfnl_log *nfnlmsg_log_parse(struct nlmsghdr *nlh)
{
	struct nfnl_log *log;
	struct nlattr *tb[NFULA_MAX+1];
	struct nlattr *attr;
	int err;

	log = nfnl_log_alloc();
	if (!log)
		return NULL;

	log->ce_msgtype = nlh->nlmsg_type;

	err = nlmsg_parse(nlh, sizeof(struct nfgenmsg), tb, NFULA_MAX,
			  log_policy);
	if (err < 0)
		goto errout;

	nfnl_log_set_family(log, nfnlmsg_family(nlh));

	attr = tb[NFULA_PACKET_HDR];
	if (attr) {
		struct nfulnl_msg_packet_hdr *hdr = nla_data(attr);

		nfnl_log_set_hwproto(log, hdr->hw_protocol);
		nfnl_log_set_hook(log, hdr->hook);
	}

	attr = tb[NFULA_MARK];
	if (attr)
		nfnl_log_set_mark(log, ntohl(nla_get_u32(attr)));

	attr = tb[NFULA_TIMESTAMP];
	if (attr) {
		struct nfulnl_msg_packet_timestamp *timestamp = nla_data(attr);
		struct timeval tv;

		tv.tv_sec = ntohll(timestamp->sec);
		tv.tv_usec = ntohll(timestamp->usec);
		nfnl_log_set_timestamp(log, &tv);
	}

	attr = tb[NFULA_IFINDEX_INDEV];
	if (attr)
		nfnl_log_set_indev(log, ntohl(nla_get_u32(attr)));

	attr = tb[NFULA_IFINDEX_OUTDEV];
	if (attr)
		nfnl_log_set_outdev(log, ntohl(nla_get_u32(attr)));

	attr = tb[NFULA_IFINDEX_PHYSINDEV];
	if (attr)
		nfnl_log_set_physindev(log, ntohl(nla_get_u32(attr)));

	attr = tb[NFULA_IFINDEX_PHYSOUTDEV];
	if (attr)
		nfnl_log_set_physoutdev(log, ntohl(nla_get_u32(attr)));

	attr = tb[NFULA_HWADDR];
	if (attr) {
		struct nfulnl_msg_packet_hw *hw = nla_data(attr);

		nfnl_log_set_hwaddr(log, hw->hw_addr, ntohs(hw->hw_addrlen));
	}

	attr = tb[NFULA_PAYLOAD];
	if (attr) {
		err = nfnl_log_set_payload(log, nla_data(attr), nla_len(attr));
		if (err < 0)
			goto errout;
	}

	attr = tb[NFULA_PREFIX];
	if (attr) {
		err = nfnl_log_set_prefix(log, nla_data(attr));
		if (err < 0)
			goto errout;
	}

	attr = tb[NFULA_UID];
	if (attr)
		nfnl_log_set_uid(log, ntohl(nla_get_u32(attr)));

	attr = tb[NFULA_SEQ];
	if (attr)
		nfnl_log_set_seq(log, ntohl(nla_get_u32(attr)));

	attr = tb[NFULA_SEQ_GLOBAL];
	if (attr)
		nfnl_log_set_seq_global(log, ntohl(nla_get_u32(attr)));

	return log;

errout:
	nfnl_log_put(log);
	return NULL;
}

static int log_msg_parser(struct nl_cache_ops *ops, struct sockaddr_nl *who,
			 struct nlmsghdr *nlh, struct nl_parser_param *pp)
{
	struct nfnl_log *log;
	int err;

	log = nfnlmsg_log_parse(nlh);
	if (log == NULL)
		goto errout_errno;

	err = pp->pp_cb((struct nl_object *) log, pp);
	if (err < 0)
		goto errout;

	err = P_ACCEPT;

errout:
	nfnl_log_put(log);
	return err;

errout_errno:
	err = nl_get_errno();
	goto errout;
}

/**
 * @name Log Commands
 * @{
 */

static struct nl_msg *build_log_cmd_msg(uint8_t family, uint16_t queuenum,
					uint8_t command)
{
	struct nl_msg *msg;
	struct nfulnl_msg_config_cmd cmd;

	msg = nfnlmsg_alloc_simple(NFNL_SUBSYS_ULOG, NFULNL_MSG_CONFIG, 0,
				   family, queuenum);
	if (msg == NULL)
		return NULL;

	cmd.command = command;
	if (nla_put(msg, NFULA_CFG_CMD, sizeof(cmd), &cmd) < 0)
		goto nla_put_failure;

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

static int send_log_msg(struct nl_handle *handle, struct nl_msg *msg)
{
	int err;

	err = nl_send_auto_complete(handle, msg);
	nlmsg_free(msg);
	if (err < 0)
		return err;

	return nl_wait_for_ack(handle);
}

struct nl_msg *nfnl_log_build_bind(uint16_t queuenum)
{
	return build_log_cmd_msg(0, queuenum, NFULNL_CFG_CMD_BIND);
}

int nfnl_log_bind(struct nl_handle *nlh, uint16_t queuenum)
{
	struct nl_msg *msg;

	msg = nfnl_log_build_bind(queuenum);
	if (!msg)
		return nl_get_errno();

	return send_log_msg(nlh, msg);
}

struct nl_msg *nfnl_log_build_unbind(uint16_t queuenum)
{
	return build_log_cmd_msg(0, queuenum, NFULNL_CFG_CMD_UNBIND);
}

int nfnl_log_unbind(struct nl_handle *nlh, uint16_t queuenum)
{
	struct nl_msg *msg;

	msg = nfnl_log_build_bind(queuenum);
	if (!msg)
		return nl_get_errno();

	return send_log_msg(nlh, msg);
}

struct nl_msg *nfnl_log_build_pf_bind(uint8_t pf)
{
	return build_log_cmd_msg(pf, 0, NFULNL_CFG_CMD_PF_BIND);
}

int nfnl_log_pf_bind(struct nl_handle *nlh, uint8_t pf)
{
	struct nl_msg *msg;

	msg = nfnl_log_build_pf_bind(pf);
	if (!msg)
		return nl_get_errno();

	return send_log_msg(nlh, msg);
}

struct nl_msg *nfnl_log_build_pf_unbind(uint8_t pf)
{
	return build_log_cmd_msg(pf, 0, NFULNL_CFG_CMD_PF_UNBIND);
}

int nfnl_log_pf_unbind(struct nl_handle *nlh, uint8_t pf)
{
	struct nl_msg *msg;

	msg = nfnl_log_build_pf_unbind(pf);
	if (!msg)
		return nl_get_errno();

	return send_log_msg(nlh, msg);
}

struct nl_msg *nfnl_log_build_mode(uint16_t queuenum, uint8_t copy_mode,
				   uint32_t copy_range)
{
	struct nl_msg *msg;
	struct nfulnl_msg_config_mode mode;

	msg = nfnlmsg_alloc_simple(NFNL_SUBSYS_ULOG, NFULNL_MSG_CONFIG, 0,
			0, queuenum);
	if (msg == NULL)
		return NULL;

	mode.copy_mode = copy_mode;
	mode.copy_range = htonl(copy_range);
	if (nla_put(msg, NFULA_CFG_MODE, sizeof(mode), &mode) < 0)
		goto nla_put_failure;

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}

int nfnl_log_set_mode(struct nl_handle *nlh, uint16_t queuenum,
		      uint8_t copy_mode, uint32_t copy_range)
{
	struct nl_msg *msg;

	msg = nfnl_log_build_mode(queuenum, copy_mode, copy_range);
	if (!msg)
		return nl_get_errno();
	return send_log_msg(nlh, msg);
}

/** @} */

#define NFNLMSG_LOG_TYPE(type) NFNLMSG_TYPE(NFNL_SUBSYS_ULOG, (type))
static struct nl_cache_ops nfnl_log_ops = {
	.co_name		= "netfilter/log",
	.co_hdrsize		= NFNL_HDRLEN,
	.co_msgtypes		= {
		{ NFNLMSG_LOG_TYPE(NFULNL_MSG_PACKET), NL_ACT_NEW, "new" },
		END_OF_MSGTYPES_LIST,
	},
	.co_protocol		= NETLINK_NETFILTER,
	.co_msg_parser		= log_msg_parser,
	.co_obj_ops		= &log_obj_ops,
};

static void __init log_init(void)
{
	nl_cache_mngt_register(&nfnl_log_ops);
}

static void __exit log_exit(void)
{
	nl_cache_mngt_unregister(&nfnl_log_ops);
}

/** @} */
