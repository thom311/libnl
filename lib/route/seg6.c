/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-default.h"

#include <linux/seg6_hmac.h>
#include <linux/ipv6.h>

#include <netlink/utils.h>

#include "seg6.h"

/**
 * Copied from Linux 6.4: seg6_validate_srh:net/ipv6/seg6.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 *         Ahmed Abdelsalam <ahabdels@gmail.com>
 */
bool seg6_validate_srh(struct ipv6_sr_hdr *srh, int len)
{
	int tlv_offset, trailing;

	if (IPV6_EXTHDR_LEN(srh->hdrlen) != len)
		return false;

	tlv_offset = sizeof(*srh) +
		     (srh->first_segment + 1) * sizeof(struct in6_addr);

	trailing = len - tlv_offset;
	if (trailing < 0)
		return false;

	if (sr_has_hmac(srh)) {
		if (trailing < sizeof(struct sr6_tlv_hmac))
			return false;
	}

	return true;
}

/**
 * Copied from iproute2 v6.4.0 print_srh:ip/iproute_lwtunnel.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 */
void seg6_dump_srh(struct nl_dump_params *dp, struct ipv6_sr_hdr *srh)
{
	int i, offset;
	char addr[INET6_ADDRSTRLEN];
	struct sr6_tlv_hmac *tlv;

	nl_dump(dp, "segs %d [ ", srh->first_segment + 1);
	for (i = srh->first_segment; i >= 0; i--) {
		nl_dump(dp, "%s",
			_nl_inet_ntop(AF_INET6, &srh->segments[i], addr));
	}
	nl_dump(dp, "] ");
	if (sr_has_hmac(srh)) {
		offset = IPV6_EXTHDR_LEN(srh->hdrlen) -
			 sizeof(struct sr6_tlv_hmac);
		tlv = (struct sr6_tlv_hmac *)((char *)srh + offset);

		nl_dump(dp, "hmac %X ", ntohl(tlv->hmackeyid));
	}
}
