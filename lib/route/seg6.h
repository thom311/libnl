/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef NETLINK_SEG6_PRIV_H_
#define NETLINK_SEG6_PRIV_H_

struct ipv6_sr_hdr;
struct nl_dump_params;

/**
 * Get IPv6 extension header length in bytes
 * @arg exthdr_len_field		IPV6 Header extension length field
 *
 * @see	RFC2460
 *
 * IPV6 Header extension length field come in 8-octet units,
 * not including the first 8 octets
 */
#define IPV6_EXTHDR_LEN(exthdr_len_field) (((exthdr_len_field) + 1) << 3)

bool seg6_validate_srh(struct ipv6_sr_hdr *srh, int len, bool reduced);
extern void seg6_dump_srh(struct nl_dump_params *dp, struct ipv6_sr_hdr *srh);

#endif
