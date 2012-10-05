/*
 * lib/netfilter/exp_obj.c	Conntrack Expectation Object
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2008 Thomas Graf <tgraf@suug.ch>
 * Copyright (c) 2007 Philip Craig <philipc@snapgear.com>
 * Copyright (c) 2007 Secure Computing Corporation
 */

#include <sys/types.h>
#include <netinet/in.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <linux/netfilter/nf_conntrack_tcp.h>

#include <netlink-local.h>
#include <netlink/netfilter/nfnl.h>
#include <netlink/netfilter/exp.h>

// The 32-bit attribute mask in the common object header isn't
// big enough to handle all attributes of an expectation.  So
// we'll for sure specify optional attributes + parent attributes
// that are required for valid object comparison.  Comparison of
// these parent attributes will include nested attributes.

/** @cond SKIP */
#define EXP_ATTR_FAMILY             (1UL << 0)
#define EXP_ATTR_TIMEOUT            (1UL << 1) // 32-bit
#define EXP_ATTR_ID	                (1UL << 2) // 32-bit
#define EXP_ATTR_HELPER_NAME        (1UL << 3) // string (16 bytes max)
#define EXP_ATTR_ZONE               (1UL << 4) // 16-bit
#define EXP_ATTR_CLASS              (1UL << 5) // 32-bit
#define EXP_ATTR_FLAGS              (1UL << 6) // 32-bit
#define EXP_ATTR_FN                 (1UL << 7) // String

// Tuples
#define EXP_ATTR_EXPECT             (1UL << 8)  // contains ip, proto
#define EXP_ATTR_EXPECT_IP          (1UL << 9) // contains src, dst
#define EXP_ATTR_EXPECT_L4PROTO     (1UL << 10) // contains l4proto # + PORT attrs or ICMP attrs
#define EXP_ATTR_EXPECT_L4PROTO_NUM (1UL << 11)
#define EXP_ATTR_MASTER             (1UL << 12) // contains ip, proto
#define EXP_ATTR_MASTER_IP          (1UL << 13) // contains src, dst
#define EXP_ATTR_MASTER_L4PROTO     (1UL << 14) // contains l4proto # + PORT attrs or ICMP attrs
#define EXP_ATTR_MASTER_L4PROTO_NUM (1UL << 15)
#define EXP_ATTR_MASK               (1UL << 16) // contains ip, proto
#define EXP_ATTR_MASK_IP            (1UL << 17) // contains src, dst
#define EXP_ATTR_MASK_L4PROTO       (1UL << 18) // contains l4proto # + PORT attrs or ICMP attrs
#define EXP_ATTR_MASK_L4PROTO_NUM   (1UL << 19)
#define EXP_ATTR_NAT                (1UL << 20) // contains ip, proto
#define EXP_ATTR_NAT_IP             (1UL << 21) // contains src, dst
#define EXP_ATTR_NAT_L4PROTO        (1UL << 22) // contains l4proto # + PORT attrs or ICMP attrs
#define EXP_ATTR_NAT_L4PROTO_NUM    (1UL << 23)

#define EXP_ATTR_NAT_DIR            (1UL << 24)
/** @endcond */

static void exp_free_data(struct nl_object *c)
{
	struct nfnl_exp *exp = (struct nfnl_exp *) c;

	if (exp == NULL)
		return;

    nl_addr_put(exp->exp_expect.src);
    nl_addr_put(exp->exp_expect.dst);
    nl_addr_put(exp->exp_master.src);
    nl_addr_put(exp->exp_master.dst);
    nl_addr_put(exp->exp_mask.src);
    nl_addr_put(exp->exp_mask.dst);
    nl_addr_put(exp->exp_nat.src);
    nl_addr_put(exp->exp_nat.dst);

    free(exp->exp_fn);
    free(exp->exp_helper_name);
}

static int exp_clone(struct nl_object *_dst, struct nl_object *_src)
{
    struct nfnl_exp *dst = (struct nfnl_exp *) _dst;
    struct nfnl_exp *src = (struct nfnl_exp *) _src;
    struct nl_addr *addr;
    int result = 0;

    // Expectation
    if (src->exp_expect.src) {
        addr = nl_addr_clone(src->exp_expect.src);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_expect.src = addr;
    }

    if (src->exp_expect.dst) {
        addr = nl_addr_clone(src->exp_expect.dst);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_expect.dst = addr;
    }

    // Master CT
    if (src->exp_master.src) {
        addr = nl_addr_clone(src->exp_master.src);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_master.src = addr;
    }

    if (src->exp_master.dst) {
        addr = nl_addr_clone(src->exp_master.dst);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_master.dst = addr;
    }

    // Mask
    if (src->exp_mask.src) {
        addr = nl_addr_clone(src->exp_mask.src);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_mask.src = addr;
    }

    if (src->exp_mask.dst) {
        addr = nl_addr_clone(src->exp_mask.dst);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_mask.dst = addr;
    }

    // NAT
    if (src->exp_nat.src) {
        addr = nl_addr_clone(src->exp_nat.src);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_nat.src = addr;
    }

    if (src->exp_nat.dst) {
        addr = nl_addr_clone(src->exp_nat.dst);
        if (!addr)
            return -NLE_NOMEM;
        dst->exp_nat.dst = addr;
    }

	return 0;
}

static void dump_addr(struct nl_dump_params *p, struct nl_addr *addr, int port)
{
	char buf[64];

	if (addr)
		nl_dump(p, "%s", nl_addr2str(addr, buf, sizeof(buf)));

	if (port)
		nl_dump(p, ":%u ", port);
	else if (addr)
		nl_dump(p, " ");
}

static void dump_icmp(struct nl_dump_params *p, struct nfnl_ct *ct, int tuple)
{
	nl_dump(p, "icmp type %d ", nfnl_exp_get_icmp_type(ct, tuple));

	nl_dump(p, "code %d ", nfnl_exp_get_icmp_code(ct, tuple));

	nl_dump(p, "id %d ", nfnl_exp_get_icmp_id(ct, tuple));
}

static void ct_dump_tuples(struct nfnl_exp *exp, struct nl_dump_params *p)
{
	struct nl_addr *tuple_src, *tuple_dst;
	int tuple_sport = 0, tuple_dport = 0;
	int i = NFNL_EXP_EXPECT;
	int icmp = 0;

	for (i; i <= NFNL_EXP_NAT; i++) {

        if (nfnl_exp_test_tuple(exp, i)) {

        tuple_src = nfnl_ct_get_src(exp, i);
        tuple_dst = nfnl_ct_get_dst(exp, i);

        // Don't have tests for individual ports/types/codes/ids,
        // just test L4 Proto.  Ugly, but can't do much else without
        // more mask bits

        if (nfnl_exp_test_l4proto(exp, i)) {
            int l4proto = nfnl_exp_get_l4proto(exp, i);
            if ( !(l4proto == IPPROTO_ICMP ||
                   l4proto == IPPROTO_ICMPV6) ) {
                tuple_sport = nfnl_exp_get_src_port(exp, i);
                tuple_dport = nfnl_exp_get_dst_port(exp, i);
            } else {
                icmp = 1;
            }
        }
        dump_addr(p, tuple_src, tuple_sport);
        dump_addr(p, tuple_dst, tuple_dport);
        if (icmp)
            dump_icmp(p, exp, 0);
    }
}

/* Compatible with /proc/net/nf_conntrack */
static void ct_dump_line(struct nl_object *a, struct nl_dump_params *p)
{
	struct nfnl_ct *ct = (struct nfnl_ct *) a;
	char buf[64];

	nl_new_line(p);

	if (nfnl_ct_test_proto(ct))
		nl_dump(p, "%s ",
		  nl_ip_proto2str(nfnl_ct_get_proto(ct), buf, sizeof(buf)));

	ct_dump_tuples(ct, p);

	nl_dump(p, "\n");
}

static void ct_dump_details(struct nl_object *a, struct nl_dump_params *p)
{
	struct nfnl_ct *ct = (struct nfnl_ct *) a;
	char buf[64];
	int fp = 0;

	ct_dump_line(a, p);

	nl_dump(p, "    id 0x%x ", ct->ct_id);
	nl_dump_line(p, "family %s ",
		nl_af2str(ct->ct_family, buf, sizeof(buf)));

	if (nfnl_ct_test_use(ct))
		nl_dump(p, "refcnt %u ", nfnl_ct_get_use(ct));

	if (nfnl_ct_test_timeout(ct)) {
		uint64_t timeout_ms = nfnl_ct_get_timeout(ct) * 1000UL;
		nl_dump(p, "timeout %s ",
			nl_msec2str(timeout_ms, buf, sizeof(buf)));
	}

	if (ct->ct_status)
		nl_dump(p, "<");

#define PRINT_FLAG(str) \
	{ nl_dump(p, "%s%s", fp++ ? "," : "", (str)); }

	if (exp->exp_flags & NF_CT_EXPECT_PERMANENT)
		PRINT_FLAG("PERMANENT");
	if (exp->exp_flags & NF_CT_EXPECT_INACTIVE)
		PRINT_FLAG("INACTIVE");
	if (exp->exp_flags & NF_CT_EXPECT_USERSPACE)
		PRINT_FLAG("USERSPACE");
#undef PRINT_FLAG

	if (exp->exp_flags)
		nl_dump(p, ">");
	nl_dump(p, "\n");
}

/*
static void ct_dump_stats(struct nl_object *a, struct nl_dump_params *p)
{
	struct nfnl_ct *ct = (struct nfnl_ct *) a;
	double res;
	char *unit;
	uint64_t packets;
	const char * const names[] = {"rx", "tx"};
	int i;

	ct_dump_details(a, p);

	if (!nfnl_ct_test_bytes(ct, 0) ||
	    !nfnl_ct_test_packets(ct, 0) ||
	    !nfnl_ct_test_bytes(ct, 1) ||
	    !nfnl_ct_test_packets(ct, 1))
	    {
		nl_dump_line(p, "    Statistics are not available.\n");
		nl_dump_line(p, "    Please set sysctl net.netfilter.nf_conntrack_acct=1\n");
		nl_dump_line(p, "    (Require kernel 2.6.27)\n");
		return;
	    }

	nl_dump_line(p, "        # packets      volume\n");
	for (i=0; i<=1; i++) {
		res = nl_cancel_down_bytes(nfnl_ct_get_bytes(ct, i), &unit);
		packets = nfnl_ct_get_packets(ct, i);
		nl_dump_line(p, "    %s %10" PRIu64  " %7.2f %s\n", names[i], packets, res, unit);
	}
}
*/

static int exp_cmp_tuples_loose(struct nfnl_ct_dir *a, struct nfnl_ct_dir *b)
{
    // Must return 0 for match, 1 for mismatch
    // Parent attribute, so must reflect lower level attribute diffs
    int d = exp_cmp_tuples_ip_loose(a, b);
    if (d == 0) {
        d = exp_cmp_tuples_proto(&a->proto, &b->proto))
    }
    return d;
}

static int exp_cmp_tuples(struct nfnl_exp_dir *a, struct nfnl_exp_dir *b)
{
    // Must return 0 for match, 1 for mismatch
    // Parent attribute, so must reflect lower level attribute diffs
    int d = exp_cmp_tuples_ip(a, b);
    if (d == 0) {
        d = exp_cmp_tuples_proto(&a->proto, &b->proto))
    }
    return d;
}

static int exp_cmp_tuples_ip_loose(struct nfnl_exp_dir *a, struct nfnl_exp_dir *b) {
    // Must return 0 for match, 1 for mismatch
    int d = nl_addr_cmp_prefix(a->src, b->src);

    if (d == 0) {
        d = nl_addr_cmp_prefix(a->dst, b->dst);
    }
    return d;
}


static int exp_cmp_tuples_ip(struct nfnl_exp_dir *a, struct nfnl_exp_dir *b) {
    // Must return 0 for match, 1 for mismatch
    int d = nl_addr_cmp(a->src, b->src);

    if (d == 0) {
        d = nl_addr_cmp(a->dst, b->dst);
    }
    return d;
}


static int exp_cmp_tuples_proto(struct nfnl_exp_proto *a, struct nfnl_exp_proto *b) {
    // Must return 0 for match, 1 for mismatch

    // Parent attribute, so must reflect lower level attribute diffs
    int d = exp_cmp_tuples_protonum(a->l4protonum, b->l4protonum);

    if (d == 0) {
        // Check actual proto data
        if (a->l4protonum == IPPROTO_ICMP ||
            a->l4protonum == IPPROTO_ICMPV6) {
            d == ( (a->l4protodata.icmp.code != b->l4protodata.icmp.code) ||
                   (a->l4protodata.icmp.type != b->l4protodata.icmp.type) ||
                   (a->l4protodata.icmp.id != b->l4protodata.icmp.id) )
        } else {
            d == ( (a->l4protodata.port.src != b->l4protodata.port.src) ||
                   (a->l4protodata.port.dst != b->l4protodata.icmp.dst) )
        }
    }

    return d;
}

static int exp_cmp_tuples_protonum(uint8_t a, uint8_t b) {
    // Must return 0 for match, 1 for mismatch
    return (a != b)
}

static int exp_compare(struct nl_object *_a, struct nl_object *_b,
			                uint32_t attrs, int flags)
{
	struct nfnl_exp *a = (struct nfnl_exp *) _a;
	struct nfnl_exp *b = (struct nfnl_exp *) _b;
	int diff = 0;

#define EXP_DIFF(ATTR, EXPR) ATTR_DIFF(attrs, EXP_ATTR_##ATTR, a, b, EXPR)
#define EXP_DIFF_VAL(ATTR, FIELD) EXP_DIFF(ATTR, a->FIELD != b->FIELD)
#define EXP_DIFF_STRING(ATTR, FIELD) EXP_DIFF(ATTR, (strncmp(a->FIELD, b->FIELD, 16) != 0))

#define EXP_DIFF_TUPLE(ATTR, FIELD) \
    ((flags & LOOSE_COMPARISON) \
        ? EXP_DIFF(ATTR, exp_cmp_tuples_loose(a->FIELD, b->FIELD)) \
        : EXP_DIFF(ATTR, exp_cmp_tuples(a->FIELD, b->FIELD)))

#define EXP_DIFF_IP(ATTR, FIELD) \
    ((flags & LOOSE_COMPARISON) \
        ? EXP_DIFF(ATTR, exp_cmp_tuples_ip_loose(a->FIELD, b->FIELD)) \
        : EXP_DIFF(ATTR, exp_cmp_tuples_ip(a->FIELD, b->FIELD)))

#define EXP_DIFF_PROTO(ATTR, FIELD) \
        EXP_DIFF(ATTR, exp_cmp_tuples_proto(a->FIELD, b->FIELD))

        diff |= EXP_DIFF_VAL(FAMILY,        exp_family);
        diff |= EXP_DIFF_VAL(TIMEOUT,       exp_timeout);
        diff |= EXP_DIFF_VAL(ID,            exp_id);
        diff |= EXP_DIFF_VAL(ZONE,          exp_zone);
        diff |= EXP_DIFF_VAL(CLASS,         exp_class);
        diff |= EXP_DIFF_VAL(FLAGS,         exp_flags);
        diff |= EXP_DIFF_VAL(NAT_DIR,       exp_flags);

        diff |= EXP_DIFF(FLAGS, (a->exp_flags ^ b->exp_flags));

#undef CT_DIFF
#undef CT_DIFF_VAL
#undef EXP_DIFF_STRING
#undef CT_DIFF_TUPLE
#undef CT_DIFF_IP
#undef CT_DIFF_PROTO

	return diff;
}

static const struct trans_tbl ct_attrs[] = {
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

void nfnl_exp_set_family(struct nfnl_exp *exp, uint8_t family)
{
	exp->exp_family = family;
	exp->ce_mask |= EXP_ATTR_FAMILY;
}

uint8_t nfnl_exp_get_family(const struct nfnl_exp *exp)
{
	if (exp->ce_mask & EXP_ATTR_FAMILY)
		return exp->exp_family;
	else
		return AF_UNSPEC;
}

void nfnl_exp_set_proto(struct nfnl_exp *exp, uint8_t proto)
{
	exp->exp_proto = proto;
	exp->ce_mask |= EXP_ATTR_PROTO;
}

int nfnl_exp_test_proto(const struct nfnl_exp *exp)
{
	return !!(exp->ce_mask & EXP_ATTR_PROTO);
}

uint8_t nfnl_exp_get_proto(const struct nfnl_exp *ct)
{
	return exp->ct_proto;
}

void nfnl_exp_set_flags(struct nfnl_exp *exp, uint32_t flags)
{
	exp->exp_flags |= flags;
	exp->ce_mask |= EXP_ATTR_FLAGS;
}

void nfnl_exp_unset_flags(struct nfnl_exp *exp, uint32_t flags)
{
	exp->exp_flags &= ~flags;
	exp->ce_mask |= EXP_ATTR_FLAGS;
}

uint32_t nfnl_exp_get_status(const struct nfnl_exp *exp)
{
	return exp->exp_flags;
}

static const struct trans_tbl flag_table[] = {
	__ADD(IPS_EXPECTED, expected)
	__ADD(IPS_SEEN_REPLY, seen_reply)
	__ADD(IPS_ASSURED, assured)
};

char * nfnl_exp_flags2str(int flags, char *buf, size_t len)
{
	return __flags2str(flags, buf, len, status_flags,
			   ARRAY_SIZE(flag_table));
}

int nfnl_exp_str2status(const char *name)
{
	return __str2flags(name, flag_table, ARRAY_SIZE(flag_table));
}

void nfnl_exp_set_timeout(struct nfnl_exp *exp, uint32_t timeout)
{
	exp->exp_timeout = timeout;
	exp->ce_mask |= EXP_ATTR_TIMEOUT;
}

int nfnl_exp_test_timeout(const struct nfnl_exp *exp)
{
	return !!(exp->ce_mask & EXP_ATTR_TIMEOUT);
}

uint32_t nfnl_exp_get_timeout(const struct nfnl_exp *exp)
{
	return exp->exp_timeout;
}

void nfnl_exp_set_id(struct nfnl_exp *exp, uint32_t id)
{
	exp->exp_id = id;
	exp->ce_mask |= EXP_ATTR_ID;
}

int nfnl_exp_test_id(const struct nfnl_exp *exp)
{
	return !!(exp->ce_mask & EXP_ATTR_ID);
}

uint32_t nfnl_exp_get_id(const struct nfnl_exp *exp)
{
	return exp->exp_id;
}

static int exp_set_addr(struct nfnl_exp *exp, struct nl_addr *addr,
                          int attr, struct nl_addr ** exp_addr)
{
	if (exp->ce_mask & EXP_ATTR_FAMILY) {
		if (addr->a_family != exp->exp_family)
			return -NLE_AF_MISMATCH;
	} else
		nfnl_exp_set_family(exp, addr->a_family);

	if (*exp_addr)
		nl_addr_put(*exp_addr);

	nl_addr_get(addr);
	*exp_addr = addr;
	exp->ce_mask |= attr;

	return 0;
}

int nfnl_exp_set_src(struct nfnl_exp *exp, int tuple, struct nl_addr *addr)
{
	struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;
	int attr = repl ? CT_ATTR_REPL_SRC : CT_ATTR_ORIG_SRC;

        switch (tuple) {
            case :
                dir = &exp->exp_expect;
                attr = EXP_ATTR_
                break;
            case :
                dir = &exp->exp_master;
                break;
            case :
                dir = &exp->exp_mask;
                break;
            case :
                dir = &exp->exp_nat;
            default :
        }

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

uint8_t nfnl_ct_get_icmp_code(const struct nfnl_ct *ct, int tuple)
{
	const struct nfnl_ct_dir *dir = repl ? &ct->ct_repl : &ct->ct_orig;

	return dir->proto.icmp.code;
}

/** @} */

struct nl_object_ops exp_obj_ops = {
	.oo_name		= "netfilter/exp",
	.oo_size		= sizeof(struct nfnl_exp),
	.oo_free_data		= exp_free_data,
	.oo_clone		= exp_clone,
	.oo_dump = {
	    [NL_DUMP_LINE]	= exp_dump_line,
	    [NL_DUMP_DETAILS]	= exp_dump_details,
	    [NL_DUMP_STATS]	= exp_dump_stats,
	},
	.oo_compare		= exp_compare,
	.oo_attrs2str		= exp_attrs2str,
};

/** @} */
