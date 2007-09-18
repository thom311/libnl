/*
 * lib/netfilter/ct_obj.c	Conntrack Object
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

#include <sys/types.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

#include <netlink-local.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/ct.h>

/** @cond SKIP */
#define CT_ATTR_FAMILY		(1UL << 0)
#define CT_ATTR_PROTO		(1UL << 1)

#define CT_ATTR_TCP_STATE	(1UL << 2)

#define CT_ATTR_STATUS		(1UL << 3)
#define CT_ATTR_TIMEOUT		(1UL << 4)
#define CT_ATTR_MARK		(1UL << 5)
#define CT_ATTR_USE		(1UL << 6)
#define CT_ATTR_ID		(1UL << 7)

#define CT_ATTR_ORIG_SRC	(1UL << 8)
#define CT_ATTR_ORIG_DST	(1UL << 9)
#define CT_ATTR_ORIG_SRC_PORT	(1UL << 10)
#define CT_ATTR_ORIG_DST_PORT	(1UL << 11)
#define CT_ATTR_ORIG_ICMP_ID	(1UL << 12)
#define CT_ATTR_ORIG_ICMP_TYPE	(1UL << 13)
#define CT_ATTR_ORIG_ICMP_CODE	(1UL << 14)
#define CT_ATTR_ORIG_PACKETS	(1UL << 15)
#define CT_ATTR_ORIG_BYTES	(1UL << 16)

#define CT_ATTR_REPL_SRC	(1UL << 17)
#define CT_ATTR_REPL_DST	(1UL << 18)
#define CT_ATTR_REPL_SRC_PORT	(1UL << 19)
#define CT_ATTR_REPL_DST_PORT	(1UL << 20)
#define CT_ATTR_REPL_ICMP_ID	(1UL << 21)
#define CT_ATTR_REPL_ICMP_TYPE	(1UL << 22)
#define CT_ATTR_REPL_ICMP_CODE	(1UL << 23)
#define CT_ATTR_REPL_PACKETS	(1UL << 24)
#define CT_ATTR_REPL_BYTES	(1UL << 25)
/** @endcond */

static void ct_free_data(struct nl_object *c)
{
	struct nfnl_ct *ct = (struct nfnl_ct *) c;

	if (ct == NULL)
		return;

	nl_addr_put(ct->ct_orig.src);
	nl_addr_put(ct->ct_orig.dst);
	nl_addr_put(ct->ct_repl.src);
	nl_addr_put(ct->ct_repl.dst);
}

static int ct_clone(struct nl_object *_dst, struct nl_object *_src)
{
	struct nfnl_ct *dst = (struct nfnl_ct *) _dst;
	struct nfnl_ct *src = (struct nfnl_ct *) _src;
	struct nl_addr *addr;

	if (src->ct_orig.src) {
		addr = nl_addr_clone(src->ct_orig.src);
		if (!addr)
			goto errout;
		dst->ct_orig.src = addr;
	}

	if (src->ct_orig.dst) {
		addr = nl_addr_clone(src->ct_orig.dst);
		if (!addr)
			goto errout;
		dst->ct_orig.dst = addr;
	}

	if (src->ct_repl.src) {
		addr = nl_addr_clone(src->ct_repl.src);
		if (!addr)
			goto errout;
		dst->ct_repl.src = addr;
	}

	if (src->ct_repl.dst) {
		addr = nl_addr_clone(src->ct_repl.dst);
		if (!addr)
			goto errout;
		dst->ct_repl.dst = addr;
	}

	return 0;
errout:
	return nl_get_errno();
}

static void ct_dump_dir(struct nfnl_ct *ct, int repl,
			struct nl_dump_params *p)
{
	struct nl_addr *addr;
	char addrbuf[64];

	addr = nfnl_ct_get_src(ct, repl);
	if (addr)
		dp_dump(p, "src=%s ",
			nl_addr2str(addr, addrbuf, sizeof(addrbuf)));

	addr = nfnl_ct_get_dst(ct, repl);
	if (addr)
		dp_dump(p, "dst=%s ",
			nl_addr2str(addr, addrbuf, sizeof(addrbuf)));

	if (nfnl_ct_test_src_port(ct, repl))
		dp_dump(p, "sport=%u ", ntohs(nfnl_ct_get_src_port(ct, repl)));
	if (nfnl_ct_test_dst_port(ct, repl))
		dp_dump(p, "dport=%u ", ntohs(nfnl_ct_get_dst_port(ct, repl)));

	if (nfnl_ct_test_icmp_type(ct, repl))
		dp_dump(p, "type=%d ", nfnl_ct_get_icmp_type(ct, repl));
	if (nfnl_ct_test_icmp_type(ct, repl))
		dp_dump(p, "code=%d ", nfnl_ct_get_icmp_code(ct, repl));
	if (nfnl_ct_test_icmp_type(ct, repl))
		dp_dump(p, "id=%d ", ntohs(nfnl_ct_get_icmp_id(ct, repl)));

	if (nfnl_ct_test_packets(ct, repl))
		dp_dump(p, "packets=%llu ", nfnl_ct_get_packets(ct, repl));
	if (nfnl_ct_test_bytes(ct, repl))
		dp_dump(p, "bytes=%llu ", nfnl_ct_get_bytes(ct, repl));
}

/* Compatible with /proc/net/nf_conntrack */
static int ct_dump(struct nl_object *a, struct nl_dump_params *p)
{
	struct nfnl_ct *ct = (struct nfnl_ct *) a;
	char buf[64];
	uint32_t status;
	uint8_t family;
	uint8_t proto;

	family = nfnl_ct_get_family(ct);
	dp_dump(p, "%-8s %u ", nl_af2str(family, buf, sizeof(buf)), family);

	if (nfnl_ct_test_proto(ct)) {
		proto = nfnl_ct_get_proto(ct);
		dp_dump(p, "%-8s %u ",
			nl_ip_proto2str(proto, buf, sizeof(buf)), proto);
	}

	if (nfnl_ct_test_timeout(ct))
		dp_dump(p, "%ld ", nfnl_ct_get_timeout(ct));

	if (nfnl_ct_test_tcp_state(ct))
		dp_dump(p, "%s ",
			nfnl_ct_tcp_state2str(nfnl_ct_get_tcp_state(ct),
					      buf, sizeof(buf)));

	ct_dump_dir(ct, 0, p);

	status = nfnl_ct_get_status(ct);
	if (!(status & IPS_SEEN_REPLY))
		dp_dump(p, "[UNREPLIED] ");

	ct_dump_dir(ct, 1, p);

	if (status & IPS_ASSURED)
		dp_dump(p, "[ASSURED] ");

	if (nfnl_ct_test_mark(ct))
		dp_dump(p, "mark=%u ", nfnl_ct_get_mark(ct));

	if (nfnl_ct_test_use(ct))
		dp_dump(p, "use=%u ", nfnl_ct_get_use(ct));

	dp_dump(p, "\n");

	return 1;
}

static int ct_compare(struct nl_object *_a, struct nl_object *_b,
			uint32_t attrs, int flags)
{
	struct nfnl_ct *a = (struct nfnl_ct *) _a;
	struct nfnl_ct *b = (struct nfnl_ct *) _b;
	int diff = 0;

#define CT_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, CT_ATTR_##ATTR, a, b, EXPR)
#define CT_DIFF_VAL(ATTR, FIELD) CT_DIFF(ATTR, a->FIELD != b->FIELD)
#define CT_DIFF_ADDR(ATTR, FIELD) \
	((flags & LOOSE_FLAG_COMPARISON) \
		? CT_DIFF(ATTR, nl_addr_cmp_prefix(a->FIELD, b->FIELD)) \
		: CT_DIFF(ATTR, nl_addr_cmp(a->FIELD, b->FIELD)))

	diff |= CT_DIFF_VAL(FAMILY,		ct_family);
	diff |= CT_DIFF_VAL(PROTO,		ct_proto);
	diff |= CT_DIFF_VAL(TCP_STATE,		ct_protoinfo.tcp.state);
	diff |= CT_DIFF_VAL(TIMEOUT,		ct_timeout);
	diff |= CT_DIFF_VAL(MARK,		ct_mark);
	diff |= CT_DIFF_VAL(USE,		ct_use);
	diff |= CT_DIFF_VAL(ID,			ct_id);
	diff |= CT_DIFF_ADDR(ORIG_SRC,		ct_orig.src);
	diff |= CT_DIFF_ADDR(ORIG_DST,		ct_orig.dst);
	diff |= CT_DIFF_VAL(ORIG_SRC_PORT,	ct_orig.proto.port.src);
	diff |= CT_DIFF_VAL(ORIG_DST_PORT,	ct_orig.proto.port.dst);
	diff |= CT_DIFF_VAL(ORIG_ICMP_ID,	ct_orig.proto.icmp.id);
	diff |= CT_DIFF_VAL(ORIG_ICMP_TYPE,	ct_orig.proto.icmp.type);
	diff |= CT_DIFF_VAL(ORIG_ICMP_CODE,	ct_orig.proto.icmp.code);
	diff |= CT_DIFF_VAL(ORIG_PACKETS,	ct_orig.packets);
	diff |= CT_DIFF_VAL(ORIG_BYTES,		ct_orig.bytes);
	diff |= CT_DIFF_ADDR(REPL_SRC,		ct_repl.src);
	diff |= CT_DIFF_ADDR(REPL_DST,		ct_repl.dst);
	diff |= CT_DIFF_VAL(REPL_SRC_PORT,	ct_repl.proto.port.src);
	diff |= CT_DIFF_VAL(REPL_DST_PORT,	ct_repl.proto.port.dst);
	diff |= CT_DIFF_VAL(REPL_ICMP_ID,	ct_repl.proto.icmp.id);
	diff |= CT_DIFF_VAL(REPL_ICMP_TYPE,	ct_repl.proto.icmp.type);
	diff |= CT_DIFF_VAL(REPL_ICMP_CODE,	ct_repl.proto.icmp.code);
	diff |= CT_DIFF_VAL(REPL_PACKETS,	ct_repl.packets);
	diff |= CT_DIFF_VAL(REPL_BYTES,		ct_repl.bytes);

	if (flags & LOOSE_FLAG_COMPARISON)
		diff |= CT_DIFF(STATUS, (a->ct_status ^ b->ct_status) &
					b->ct_status_mask);
	else
		diff |= CT_DIFF(STATUS, a->ct_status != b->ct_status);

#undef CT_DIFF
#undef CT_DIFF_VAL
#undef CT_DIFF_ADDR

	return diff;
}

static struct trans_tbl ct_attrs[] = {
	__ADD(CT_ATTR_FAMILY,		family)
	__ADD(CT_ATTR_PROTO,		proto)
	__ADD(CT_ATTR_TCP_STATE,	tcpstate)
	__ADD(CT_ATTR_STATUS,		status)
	__ADD(CT_ATTR_TIMEOUT,		timeout)
	__ADD(CT_ATTR_MARK,		mark)
	__ADD(CT_ATTR_USE,		use)
	__ADD(CT_ATTR_ID,		id)
	__ADD(CT_ATTR_ORIG_SRC,		origsrc)
	__ADD(CT_ATTR_ORIG_DST,		origdst)
	__ADD(CT_ATTR_ORIG_SRC_PORT,	origsrcport)
	__ADD(CT_ATTR_ORIG_DST_PORT,	origdstport)
	__ADD(CT_ATTR_ORIG_ICMP_ID,	origicmpid)
	__ADD(CT_ATTR_ORIG_ICMP_TYPE,	origicmptype)
	__ADD(CT_ATTR_ORIG_ICMP_CODE,	origicmpcode)
	__ADD(CT_ATTR_ORIG_PACKETS,	origpackets)
	__ADD(CT_ATTR_ORIG_BYTES,	origbytes)
	__ADD(CT_ATTR_REPL_SRC,		replysrc)
	__ADD(CT_ATTR_REPL_DST,		replydst)
	__ADD(CT_ATTR_REPL_SRC_PORT,	replysrcport)
	__ADD(CT_ATTR_REPL_DST_PORT,	replydstport)
	__ADD(CT_ATTR_REPL_ICMP_ID,	replyicmpid)
	__ADD(CT_ATTR_REPL_ICMP_TYPE,	replyicmptype)
	__ADD(CT_ATTR_REPL_ICMP_CODE,	replyicmpcode)
	__ADD(CT_ATTR_REPL_PACKETS,	replypackets)
	__ADD(CT_ATTR_REPL_BYTES,	replybytes)
};

static char *ct_attrs2str(int attrs, char *buf, size_t len)
{
	return __flags2str(attrs, buf, len, ct_attrs, ARRAY_SIZE(ct_attrs));
}

/**
 * @name Allocation/Freeing
 * @{
 */

struct nfnl_ct *nfnl_ct_alloc(void)
{
	return (struct nfnl_ct *) nl_object_alloc(&ct_obj_ops);
}

void nfnl_ct_get(struct nfnl_ct *ct)
{
	nl_object_get((struct nl_object *) ct);
}

void nfnl_ct_put(struct nfnl_ct *ct)
{
	nl_object_put((struct nl_object *) ct);
}

/** @} */

/**
 * @name Attributes
 * @{
 */

void nfnl_ct_set_family(struct nfnl_ct *ct, uint8_t family)
{
	ct->ct_family = family;
	ct->ce_mask |= CT_ATTR_FAMILY;
}

uint8_t nfnl_ct_get_family(const struct nfnl_ct *ct)
{
	if (ct->ce_mask & CT_ATTR_FAMILY)
		return ct->ct_family;
	else
		return AF_UNSPEC;
}

void nfnl_ct_set_proto(struct nfnl_ct *ct, uint8_t proto)
{
	ct->ct_proto = proto;
	ct->ce_mask |= CT_ATTR_PROTO;
}

int nfnl_ct_test_proto(const struct nfnl_ct *ct)
{
	return !!(ct->ce_mask & CT_ATTR_PROTO);
}

uint8_t nfnl_ct_get_proto(const struct nfnl_ct *ct)
{
	return ct->ct_proto;
}

void nfnl_ct_set_tcp_state(struct nfnl_ct *ct, uint8_t state)
{
	ct->ct_protoinfo.tcp.state = state;
	ct->ce_mask |= CT_ATTR_TCP_STATE;
}

int nfnl_ct_test_tcp_state(const struct nfnl_ct *ct)
{
	return !!(ct->ce_mask & CT_ATTR_TCP_STATE);
}

uint8_t nfnl_ct_get_tcp_state(const struct nfnl_ct *ct)
{
	return ct->ct_protoinfo.tcp.state;
}

static struct trans_tbl tcp_states[] = {
	__ADD(TCP_CONNTRACK_NONE,NONE)
	__ADD(TCP_CONNTRACK_SYN_SENT,SYN_SENT)
	__ADD(TCP_CONNTRACK_SYN_RECV,SYN_RECV)
	__ADD(TCP_CONNTRACK_ESTABLISHED,ESTABLISHED)
	__ADD(TCP_CONNTRACK_FIN_WAIT,FIN_WAIT)
	__ADD(TCP_CONNTRACK_CLOSE_WAIT,CLOSE_WAIT)
	__ADD(TCP_CONNTRACK_LAST_ACK,LAST_ACK)
	__ADD(TCP_CONNTRACK_TIME_WAIT,TIME_WAIT)
	__ADD(TCP_CONNTRACK_CLOSE,CLOSE)
	__ADD(TCP_CONNTRACK_LISTEN,LISTEN)
};

char *nfnl_ct_tcp_state2str(uint8_t state, char *buf, size_t len)
{
	return __type2str(state, buf, len, tcp_states, ARRAY_SIZE(tcp_states));
}

int nfnl_ct_str2tcp_state(const char *name)
{
        return __str2type(name, tcp_states, ARRAY_SIZE(tcp_states));
}

void nfnl_ct_set_status(struct nfnl_ct *ct, uint32_t status)
{
	ct->ct_status_mask |= status;
	ct->ct_status |= status;
	ct->ce_mask |= CT_ATTR_STATUS;
}

void nfnl_ct_unset_status(struct nfnl_ct *ct, uint32_t status)
{
	ct->ct_status_mask |= status;
	ct->ct_status &= ~status;
	ct->ce_mask |= CT_ATTR_STATUS;
}

uint32_t nfnl_ct_get_status(const struct nfnl_ct *ct)
{
	return ct->ct_status;
}

void nfnl_ct_set_timeout(struct nfnl_ct *ct, uint32_t timeout)
{
	ct->ct_timeout = timeout;
	ct->ce_mask |= CT_ATTR_TIMEOUT;
}

int nfnl_ct_test_timeout(const struct nfnl_ct *ct)
{
	return !!(ct->ce_mask & CT_ATTR_TIMEOUT);
}

uint32_t nfnl_ct_get_timeout(const struct nfnl_ct *ct)
{
	return ct->ct_timeout;
}

void nfnl_ct_set_mark(struct nfnl_ct *ct, uint32_t mark)
{
	ct->ct_mark = mark;
	ct->ce_mask |= CT_ATTR_MARK;
}

int nfnl_ct_test_mark(const struct nfnl_ct *ct)
{
	return !!(ct->ce_mask & CT_ATTR_MARK);
}

uint32_t nfnl_ct_get_mark(const struct nfnl_ct *ct)
{
	return ct->ct_mark;
}

void nfnl_ct_set_use(struct nfnl_ct *ct, uint32_t use)
{
	ct->ct_use = use;
	ct->ce_mask |= CT_ATTR_USE;
}

int nfnl_ct_test_use(const struct nfnl_ct *ct)
{
	return !!(ct->ce_mask & CT_ATTR_USE);
}

uint32_t nfnl_ct_get_use(const struct nfnl_ct *ct)
{
	return ct->ct_use;
}

void nfnl_ct_set_id(struct nfnl_ct *ct, uint32_t id)
{
	ct->ct_id = id;
	ct->ce_mask |= CT_ATTR_ID;
}

int nfnl_ct_test_id(const struct nfnl_ct *ct)
{
	return !!(ct->ce_mask & CT_ATTR_ID);
}

uint32_t nfnl_ct_get_id(const struct nfnl_ct *ct)
{
	return ct->ct_id;
}

static int ct_set_addr(struct nfnl_ct *ct, struct nl_addr *addr,
		int attr, struct nl_addr ** ct_addr)
{
	if (ct->ce_mask & CT_ATTR_FAMILY) {
		if (addr->a_family != ct->ct_family)
			return nl_error(EINVAL, "Address family mismatch");
	} else
		nfnl_ct_set_family(ct, addr->a_family);

	if (*ct_addr)
		nl_addr_put(*ct_addr);

	nl_addr_get(addr);
	*ct_addr = addr;
	ct->ce_mask |= attr;

	return 0;
}

int nfnl_ct_set_src(struct nfnl_ct *ct, int repl, struct nl_addr *addr)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_SRC : CT_ATTR_ORIG_SRC;
	return ct_set_addr(ct, addr, attr, &dir->src);
}

int nfnl_ct_set_dst(struct nfnl_ct *ct, int repl, struct nl_addr *addr)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_DST : CT_ATTR_ORIG_DST;
	return ct_set_addr(ct, addr, attr, &dir->dst);
}

struct nl_addr *nfnl_ct_get_src(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_SRC : CT_ATTR_ORIG_SRC;
	if (!(ct->ce_mask & attr))
		return NULL;
	return dir->src;
}

struct nl_addr *nfnl_ct_get_dst(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_DST : CT_ATTR_ORIG_DST;
	if (!(ct->ce_mask & attr))
		return NULL;
	return dir->dst;
}

void nfnl_ct_set_src_port(struct nfnl_ct *ct, int repl, uint16_t port)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_SRC_PORT : CT_ATTR_ORIG_SRC_PORT;

	dir->proto.port.src = port;
	ct->ce_mask |= attr;
}

int nfnl_ct_test_src_port(const struct nfnl_ct *ct, int repl)
{
	int attr = repl ? CT_ATTR_REPL_SRC_PORT : CT_ATTR_ORIG_SRC_PORT;
	return !!(ct->ce_mask & attr);
}

uint16_t nfnl_ct_get_src_port(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->proto.port.src;
}

void nfnl_ct_set_dst_port(struct nfnl_ct *ct, int repl, uint16_t port)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_DST_PORT : CT_ATTR_ORIG_DST_PORT;

	dir->proto.port.dst = port;
	ct->ce_mask |= attr;
}

int nfnl_ct_test_dst_port(const struct nfnl_ct *ct, int repl)
{
	int attr = repl ? CT_ATTR_REPL_DST_PORT : CT_ATTR_ORIG_DST_PORT;
	return !!(ct->ce_mask & attr);
}

uint16_t nfnl_ct_get_dst_port(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->proto.port.dst;
}

void nfnl_ct_set_icmp_id(struct nfnl_ct *ct, int repl, uint16_t id)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_ICMP_ID : CT_ATTR_ORIG_ICMP_ID;

	dir->proto.icmp.id = id;
	ct->ce_mask |= attr;
}

int nfnl_ct_test_icmp_id(const struct nfnl_ct *ct, int repl)
{
	int attr = repl ? CT_ATTR_REPL_ICMP_ID : CT_ATTR_ORIG_ICMP_ID;
	return !!(ct->ce_mask & attr);
}

uint16_t nfnl_ct_get_icmp_id(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->proto.icmp.id;
}

void nfnl_ct_set_icmp_type(struct nfnl_ct *ct, int repl, uint8_t type)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_ICMP_TYPE : CT_ATTR_ORIG_ICMP_TYPE;

	dir->proto.icmp.type = type;
	ct->ce_mask |= attr;
}

int nfnl_ct_test_icmp_type(const struct nfnl_ct *ct, int repl)
{
	int attr = repl ? CT_ATTR_REPL_ICMP_TYPE : CT_ATTR_ORIG_ICMP_TYPE;
	return !!(ct->ce_mask & attr);
}

uint8_t nfnl_ct_get_icmp_type(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->proto.icmp.type;
}

void nfnl_ct_set_icmp_code(struct nfnl_ct *ct, int repl, uint8_t code)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_ICMP_CODE : CT_ATTR_ORIG_ICMP_CODE;

	dir->proto.icmp.code = code;
	ct->ce_mask |= attr;
}

int nfnl_ct_test_icmp_code(const struct nfnl_ct *ct, int repl)
{
	int attr = repl ? CT_ATTR_REPL_ICMP_CODE : CT_ATTR_ORIG_ICMP_CODE;
	return !!(ct->ce_mask & attr);
}

uint8_t nfnl_ct_get_icmp_code(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->proto.icmp.code;
}

void nfnl_ct_set_packets(struct nfnl_ct *ct, int repl, uint64_t packets)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_PACKETS : CT_ATTR_ORIG_PACKETS;

	dir->packets = packets;
	ct->ce_mask |= attr;
}

int nfnl_ct_test_packets(const struct nfnl_ct *ct, int repl)
{
	int attr = repl ? CT_ATTR_REPL_PACKETS : CT_ATTR_ORIG_PACKETS;
	return !!(ct->ce_mask & attr);
}

uint64_t nfnl_ct_get_packets(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->packets;
}

void nfnl_ct_set_bytes(struct nfnl_ct *ct, int repl, uint64_t bytes)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_BYTES : CT_ATTR_ORIG_BYTES;

	dir->bytes = bytes;
	ct->ce_mask |= attr;
}

int nfnl_ct_test_bytes(const struct nfnl_ct *ct, int repl)
{
	int attr = repl ? CT_ATTR_REPL_BYTES : CT_ATTR_ORIG_BYTES;
	return !!(ct->ce_mask & attr);
}

uint64_t nfnl_ct_get_bytes(const struct nfnl_ct *ct, int repl)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->bytes;
}

/** @} */

struct nl_object_ops ct_obj_ops = {
	.oo_name		= "netfilter/ct",
	.oo_size		= sizeof(struct nfnl_ct),
	.oo_free_data		= ct_free_data,
	.oo_clone		= ct_clone,
	.oo_dump[NL_DUMP_BRIEF]	= ct_dump,
	.oo_dump[NL_DUMP_FULL]	= ct_dump,
	.oo_dump[NL_DUMP_STATS]	= ct_dump,
	.oo_compare		= ct_compare,
	.oo_attrs2str		= ct_attrs2str,
};

/** @} */
