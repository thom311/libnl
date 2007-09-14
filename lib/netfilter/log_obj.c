/*
 * lib/netfilter/log_obj.c	Netfilter Log Object
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

#include <netlink-local.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/log.h>

/** @cond SKIP */
#define LOG_ATTR_FAMILY			(1UL << 0)
#define LOG_ATTR_HWPROTO		(1UL << 1)
#define LOG_ATTR_HOOK			(1UL << 2)
#define LOG_ATTR_MARK			(1UL << 3)
#define LOG_ATTR_TIMESTAMP		(1UL << 4)
#define LOG_ATTR_INDEV			(1UL << 5)
#define LOG_ATTR_OUTDEV			(1UL << 6)
#define LOG_ATTR_PHYSINDEV		(1UL << 7)
#define LOG_ATTR_PHYSOUTDEV		(1UL << 8)
#define LOG_ATTR_HWADDR			(1UL << 9)
#define LOG_ATTR_PAYLOAD		(1UL << 10)
#define LOG_ATTR_PREFIX			(1UL << 11)
#define LOG_ATTR_UID			(1UL << 12)
#define LOG_ATTR_SEQ			(1UL << 13)
#define LOG_ATTR_SEQ_GLOBAL		(1UL << 14)
/** @endcond */

static void log_free_data(struct nl_object *c)
{
	struct nfnl_log *log = (struct nfnl_log *) c;

	if (log == NULL)
		return;

	free(log->log_payload);
	free(log->log_prefix);
}

static int log_clone(struct nl_object *_dst, struct nl_object *_src)
{
	struct nfnl_log *dst = (struct nfnl_log *) _dst;
	struct nfnl_log *src = (struct nfnl_log *) _src;
	int err;

	if (src->log_payload) {
		err = nfnl_log_set_payload(dst, src->log_payload,
					   src->log_payload_len);
		if (err < 0)
			goto errout;
	}

	if (src->log_prefix) {
		err = nfnl_log_set_prefix(dst, src->log_prefix);
		if (err < 0)
			goto errout;
	}

	return 0;
errout:
	return err;
}

static int log_dump(struct nl_object *a, struct nl_dump_params *p)
{
	struct nfnl_log *log = (struct nfnl_log *) a;
	struct nl_cache *link_cache;
	char buf[64];

	link_cache = nl_cache_mngt_require("route/link");

	if (log->ce_mask & LOG_ATTR_PREFIX)
		dp_dump(p, "%s", log->log_prefix);

	if (log->ce_mask & LOG_ATTR_INDEV) {
		if (link_cache)
			dp_dump(p, "IN=%s ",
				rtnl_link_i2name(link_cache, log->log_indev,
						 buf, sizeof(buf)));
		else
			dp_dump(p, "IN=%d ", log->log_indev);
	}

	if (log->ce_mask & LOG_ATTR_PHYSINDEV) {
		if (link_cache)
			dp_dump(p, "PHYSIN=%s ",
				rtnl_link_i2name(link_cache, log->log_physindev,
						 buf, sizeof(buf)));
		else
			dp_dump(p, "IN=%d ", log->log_physindev);
	}

	if (log->ce_mask & LOG_ATTR_OUTDEV) {
		if (link_cache)
			dp_dump(p, "OUT=%s ",
				rtnl_link_i2name(link_cache, log->log_outdev,
						 buf, sizeof(buf)));
		else
			dp_dump(p, "OUT=%d ", log->log_outdev);
	}

	if (log->ce_mask & LOG_ATTR_PHYSOUTDEV) {
		if (link_cache)
			dp_dump(p, "PHYSOUT=%s ",
				rtnl_link_i2name(link_cache,log->log_physoutdev,
						 buf, sizeof(buf)));
		else
			dp_dump(p, "PHYSOUT=%d ", log->log_physoutdev);
	}

	if (log->ce_mask & LOG_ATTR_HWADDR) {
		int i;

		dp_dump(p, "MAC");
		for (i = 0; i < log->log_hwaddr_len; i++)
			dp_dump(p, "%c%02x", i?':':'=', log->log_hwaddr[i]);
		dp_dump(p, " ");
	}

	/* FIXME: parse the payload to get iptables LOG compatible format */

	if (log->ce_mask & LOG_ATTR_FAMILY)
		dp_dump(p, "FAMILY=%s ",
			nl_af2str(log->log_family, buf, sizeof(buf)));

	if (log->ce_mask & LOG_ATTR_HWPROTO)
		dp_dump(p, "HWPROTO=%s ",
			nl_ether_proto2str(ntohs(log->log_hwproto),
					   buf, sizeof(buf)));

	if (log->ce_mask & LOG_ATTR_HOOK)
		dp_dump(p, "HOOK=%d ", log->log_hook);

	if (log->ce_mask & LOG_ATTR_MARK)
		dp_dump(p, "MARK=%d ", log->log_mark);

	if (log->ce_mask & LOG_ATTR_PAYLOAD)
		dp_dump(p, "PAYLOADLEN=%d ", log->log_payload_len);

	if (log->ce_mask & LOG_ATTR_SEQ)
		dp_dump(p, "SEQ=%d ", log->log_seq);

	if (log->ce_mask & LOG_ATTR_SEQ_GLOBAL)
		dp_dump(p, "SEQGLOBAL=%d ", log->log_seq_global);

	dp_dump(p, "\n");

	return 1;
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct nfnl_log *nfnl_log_alloc(void)
{
	return (struct nfnl_log *) nl_object_alloc(&log_obj_ops);
}

void nfnl_log_get(struct nfnl_log *log)
{
	nl_object_get((struct nl_object *) log);
}

void nfnl_log_put(struct nfnl_log *log)
{
	nl_object_put((struct nl_object *) log);
}

/** @} */

/**
 * @name Attributes
 * @{
 */

void nfnl_log_set_family(struct nfnl_log *log, uint8_t family)
{
	log->log_family = family;
	log->ce_mask |= LOG_ATTR_FAMILY;
}

uint8_t nfnl_log_get_family(const struct nfnl_log *log)
{
	if (log->ce_mask & LOG_ATTR_FAMILY)
		return log->log_family;
	else
		return AF_UNSPEC;
}

void nfnl_log_set_hwproto(struct nfnl_log *log, uint16_t hwproto)
{
	log->log_hwproto = hwproto;
	log->ce_mask |= LOG_ATTR_HWPROTO;
}

int nfnl_log_test_hwproto(const struct nfnl_log *log)
{
	return !!(log->ce_mask & LOG_ATTR_HWPROTO);
}

uint16_t nfnl_log_get_hwproto(const struct nfnl_log *log)
{
	return log->log_hwproto;
}

void nfnl_log_set_hook(struct nfnl_log *log, uint8_t hook)
{
	log->log_hook = hook;
	log->ce_mask |= LOG_ATTR_HOOK;
}

int nfnl_log_test_hook(const struct nfnl_log *log)
{
	return !!(log->ce_mask & LOG_ATTR_HOOK);
}

uint8_t nfnl_log_get_hook(const struct nfnl_log *log)
{
	return log->log_hook;
}

void nfnl_log_set_mark(struct nfnl_log *log, uint32_t mark)
{
	log->log_mark = mark;
	log->ce_mask |= LOG_ATTR_MARK;
}

int nfnl_log_test_mark(const struct nfnl_log *log)
{
	return !!(log->ce_mask & LOG_ATTR_MARK);
}

uint32_t nfnl_log_get_mark(const struct nfnl_log *log)
{
	return log->log_mark;
}

void nfnl_log_set_timestamp(struct nfnl_log *log, struct timeval *tv)
{
	log->log_timestamp.tv_sec = tv->tv_sec;
	log->log_timestamp.tv_usec = tv->tv_usec;
	log->ce_mask |= LOG_ATTR_TIMESTAMP;
}

const struct timeval *nfnl_log_get_timestamp(const struct nfnl_log *log)
{
	if (!(log->ce_mask & LOG_ATTR_TIMESTAMP))
		return NULL;
	return &log->log_timestamp;
}

void nfnl_log_set_indev(struct nfnl_log *log, uint32_t indev)
{
	log->log_indev = indev;
	log->ce_mask |= LOG_ATTR_INDEV;
}

uint32_t nfnl_log_get_indev(const struct nfnl_log *log)
{
	return log->log_indev;
}

void nfnl_log_set_outdev(struct nfnl_log *log, uint32_t outdev)
{
	log->log_outdev = outdev;
	log->ce_mask |= LOG_ATTR_OUTDEV;
}

uint32_t nfnl_log_get_outdev(const struct nfnl_log *log)
{
	return log->log_outdev;
}

void nfnl_log_set_physindev(struct nfnl_log *log, uint32_t physindev)
{
	log->log_physindev = physindev;
	log->ce_mask |= LOG_ATTR_PHYSINDEV;
}

uint32_t nfnl_log_get_physindev(const struct nfnl_log *log)
{
	return log->log_physindev;
}

void nfnl_log_set_physoutdev(struct nfnl_log *log, uint32_t physoutdev)
{
	log->log_physoutdev = physoutdev;
	log->ce_mask |= LOG_ATTR_PHYSOUTDEV;
}

uint32_t nfnl_log_get_physoutdev(const struct nfnl_log *log)
{
	return log->log_physoutdev;
}

void nfnl_log_set_hwaddr(struct nfnl_log *log, uint8_t *hwaddr, int len)
{
	if (len > sizeof(log->log_hwaddr))
		len = sizeof(log->log_hwaddr);
	log->log_hwaddr_len = len;
	memcpy(log->log_hwaddr, hwaddr, len);
	log->ce_mask |= LOG_ATTR_HWADDR;
}

const uint8_t *nfnl_log_get_hwaddr(const struct nfnl_log *log, int *len)
{
	if (!(log->ce_mask & LOG_ATTR_HWADDR)) {
		*len = 0;
		return NULL;
	}

	*len = log->log_hwaddr_len;
	return log->log_hwaddr;
}

int nfnl_log_set_payload(struct nfnl_log *log, uint8_t *payload, int len)
{
	free(log->log_payload);
	log->log_payload = malloc(len);
	if (!log->log_payload)
		return nl_errno(ENOMEM);

	memcpy(log->log_payload, payload, len);
	log->log_payload_len = len;
	log->ce_mask |= LOG_ATTR_PAYLOAD;
	return 0;
}

const void *nfnl_log_get_payload(const struct nfnl_log *log, int *len)
{
	if (!(log->ce_mask & LOG_ATTR_PAYLOAD)) {
		*len = 0;
		return NULL;
	}

	*len = log->log_payload_len;
	return log->log_payload;
}

int nfnl_log_set_prefix(struct nfnl_log *log, void *prefix)
{
	free(log->log_prefix);
	log->log_prefix = strdup(prefix);
	if (!log->log_prefix)
		return nl_errno(ENOMEM);

	log->ce_mask |= LOG_ATTR_PREFIX;
	return 0;
}

const char *nfnl_log_get_prefix(const struct nfnl_log *log)
{
	return log->log_prefix;
}

void nfnl_log_set_uid(struct nfnl_log *log, uint32_t uid)
{
	log->log_uid = uid;
	log->ce_mask |= LOG_ATTR_UID;
}

int nfnl_log_test_uid(const struct nfnl_log *log)
{
	return !!(log->ce_mask & LOG_ATTR_UID);
}

uint32_t nfnl_log_get_uid(const struct nfnl_log *log)
{
	return log->log_uid;
}

void nfnl_log_set_seq(struct nfnl_log *log, uint32_t seq)
{
	log->log_seq = seq;
	log->ce_mask |= LOG_ATTR_SEQ;
}

int nfnl_log_test_seq(const struct nfnl_log *log)
{
	return !!(log->ce_mask & LOG_ATTR_SEQ);
}

uint32_t nfnl_log_get_seq(const struct nfnl_log *log)
{
	return log->log_seq;
}

void nfnl_log_set_seq_global(struct nfnl_log *log, uint32_t seq_global)
{
	log->log_seq_global = seq_global;
	log->ce_mask |= LOG_ATTR_SEQ_GLOBAL;
}

int nfnl_log_test_seq_global(const struct nfnl_log *log)
{
	return !!(log->ce_mask & LOG_ATTR_SEQ_GLOBAL);
}

uint32_t nfnl_log_get_seq_global(const struct nfnl_log *log)
{
	return log->log_seq_global;
}

/** @} */

struct nl_object_ops log_obj_ops = {
	.oo_name		= "netfilter/log",
	.oo_size		= sizeof(struct nfnl_log),
	.oo_free_data		= log_free_data,
	.oo_clone		= log_clone,
	.oo_dump[NL_DUMP_BRIEF]	= log_dump,
	.oo_dump[NL_DUMP_FULL]	= log_dump,
	.oo_dump[NL_DUMP_STATS]	= log_dump,
};

/** @} */
