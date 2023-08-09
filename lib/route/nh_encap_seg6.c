/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-default.h"

#include "nl-route.h"
#include "nexthop-encap.h"
#include "seg6.h"

#include <linux/lwtunnel.h>
#include <linux/seg6_iptunnel.h>

#include <netlink/attr.h>
#include <netlink/route/nexthop.h>

#include "nl-priv-dynamic-core/nl-core.h"

static int seg6_encap_build_msg(struct nl_msg *msg, void *priv)
{
	struct seg6_iptunnel_encap *slwt;

	slwt = priv;
	return nla_put(msg, SEG6_IPTUNNEL_SRH, SEG6_IPTUN_ENCAP_SIZE(slwt), slwt);
}

static struct nla_policy seg6_encap_policy[SEG6_IPTUNNEL_MAX + 1] = {
	[SEG6_IPTUNNEL_SRH] = { .minlen = sizeof(struct seg6_iptunnel_encap) +
	                                  sizeof(struct ipv6_sr_hdr) +
	                                  sizeof(struct in6_addr) },
};

/**
 * Copied from Linux 6.4: seg6_build_state:net/ipv6/seg6_iptunnel.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 */
static int seg6_encap_parse_msg(struct nlattr *nla, struct rtnl_nexthop *nh)
{
	struct nlattr *tb[SEG6_IPTUNNEL_MAX + 1];
	struct seg6_iptunnel_encap *tuninfo;
	int err, tuninfo_len;
	struct rtnl_nh_encap *rtnh_encap;
	struct seg6_iptunnel_encap *slwt;

	err = nla_parse_nested(tb, SEG6_IPTUNNEL_MAX, nla, seg6_encap_policy);
	if (err < 0)
		return err;

	if (!tb[SEG6_IPTUNNEL_SRH])
		return -NLE_INVAL;

	tuninfo = nla_data(tb[SEG6_IPTUNNEL_SRH]);
	tuninfo_len = nla_len(tb[SEG6_IPTUNNEL_SRH]);

	switch (tuninfo->mode) {
	case SEG6_IPTUN_MODE_INLINE:
		break;
	case SEG6_IPTUN_MODE_ENCAP:
		break;
	case SEG6_IPTUN_MODE_L2ENCAP:
		break;
	case SEG6_IPTUN_MODE_ENCAP_RED:
		break;
	case SEG6_IPTUN_MODE_L2ENCAP_RED:
		break;
	default:
		return -NLE_INVAL;
	}

	/* verify that SRH is consistent */
	if (!seg6_validate_srh(tuninfo->srh, tuninfo_len - sizeof(*tuninfo), false))
		return -NLE_INVAL;

	slwt = malloc(tuninfo_len);
	if (slwt == NULL)
		return -NLE_NOMEM;

	memcpy(slwt, tuninfo, tuninfo_len);

	rtnh_encap = calloc(1, sizeof(*rtnh_encap));
	if (!rtnh_encap)
		return -NLE_NOMEM;

	rtnh_encap->priv = slwt;
	rtnh_encap->ops = &seg6_encap_ops;

	nh_set_encap(nh, rtnh_encap);

	return 0;
}

static int seg6_encap_compare(void *a, void *b)
{
	struct seg6_iptunnel_encap *slwt_a, *slwt_b;
	int len;

	slwt_a = a;
	slwt_b = b;
	len = SEG6_IPTUN_ENCAP_SIZE(slwt_a);

	if (len != SEG6_IPTUN_ENCAP_SIZE(slwt_b))
		return 1;

	return memcmp(slwt_a, slwt_b, len);
}

static const char *seg6_mode_types[] = {
	[SEG6_IPTUN_MODE_INLINE]        = "inline",
	[SEG6_IPTUN_MODE_ENCAP]         = "encap",
	[SEG6_IPTUN_MODE_L2ENCAP]       = "l2encap",
	[SEG6_IPTUN_MODE_ENCAP_RED]     = "encap.red",
	[SEG6_IPTUN_MODE_L2ENCAP_RED]   = "l2encap.red"
};

static void seg6_encap_dump(void *priv, struct nl_dump_params *dp)
{
	struct seg6_iptunnel_encap *slwt;
	const char *mode;

	slwt = priv;
	if (slwt->mode < 0 || slwt->mode >= ARRAY_SIZE(seg6_mode_types))
		mode = "<unknown>";
	else
		mode = seg6_mode_types[slwt->mode];

	nl_dump(dp, "mode %s ", mode);
	seg6_dump_srh(dp, slwt->srh);
}

struct nh_encap_ops seg6_encap_ops = {
	.encap_type	= LWTUNNEL_ENCAP_SEG6,
	.build_msg	= seg6_encap_build_msg,
	.parse_msg	= seg6_encap_parse_msg,
	.compare	= seg6_encap_compare,
	.dump		= seg6_encap_dump,
};

static 	struct seg6_iptunnel_encap *
get_seg6_slwt(struct rtnl_nexthop *nh)
{
	if (!nh->rtnh_encap || nh->rtnh_encap->ops->encap_type != LWTUNNEL_ENCAP_SEG6)
		return NULL;

	return (struct seg6_iptunnel_encap *)nh->rtnh_encap->priv;
}

int rtnl_route_nh_get_encap_seg6_mode(struct rtnl_nexthop * nh)
{
	struct seg6_iptunnel_encap *slwt;

	slwt = get_seg6_slwt(nh);
	if (slwt == NULL)
		return -1;

	return slwt->mode;
}

int rtnl_route_nh_get_encap_seg6_srh(struct rtnl_nexthop * nh, void **psrh)
{
	struct seg6_iptunnel_encap *slwt;

	slwt = get_seg6_slwt(nh);
	if (slwt == NULL)
		return -1;

	*psrh = slwt->srh;
	return 0;
}
