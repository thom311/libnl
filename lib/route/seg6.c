/* SPDX-License-Identifier: LGPL-2.1-only */

#include "nl-default.h"

#include <stdbool.h>
#include <linux/seg6_hmac.h>
#include <linux/ipv6.h>
#include <netlink/utils.h>

#include "seg6.h"

/**
 * Copied from Linux 6.4: seg6_validate_srh:net/ipv6/seg6.c
 * Author: David Lebrun <david.lebrun@uclouvain.be>
 */
bool seg6_validate_srh(struct ipv6_sr_hdr *srh, int len, bool reduced)
{
	unsigned int tlv_offset;
	int max_last_entry;
	int trailing;

	if (srh->type != IPV6_SRCRT_TYPE_4)
		return false;

	if (IPV6_EXTHDR_LEN(srh->hdrlen) != len)
		return false;

	if (!reduced && srh->segments_left > srh->first_segment) {
		return false;
	} else {
		max_last_entry = (srh->hdrlen / 2) - 1;

		if (srh->first_segment > max_last_entry)
			return false;

		if (srh->segments_left > srh->first_segment + 1)
			return false;
	}

	tlv_offset = sizeof(*srh) + ((srh->first_segment + 1) << 4);

	trailing = len - tlv_offset;
	if (trailing < 0)
		return false;

	while (trailing) {
		struct sr6_tlv *tlv;
		unsigned int tlv_len;

		if (trailing < sizeof(*tlv))
			return false;

		tlv = (struct sr6_tlv *)((unsigned char *)srh + tlv_offset);
		tlv_len = sizeof(*tlv) + tlv->len;

		trailing -= tlv_len;
		if (trailing < 0)
			return false;

		tlv_offset += tlv_len;
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
		nl_dump(dp, "%s", _nl_inet_ntop(AF_INET6, &srh->segments[i], addr));
	}
	nl_dump(dp, "] ");
	if (sr_has_hmac(srh)) {
		offset = IPV6_EXTHDR_LEN(srh->hdrlen) - sizeof(struct sr6_tlv_hmac);
		tlv = (struct sr6_tlv_hmac *)((char *)srh + offset);

		nl_dump(dp, "hmac %X ", ntohl(tlv->hmackeyid));
	}
}
