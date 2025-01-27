/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef NETLINK_BR_VLAN_GLOBAL_OPTS_H_
#define NETLINK_BR_VLAN_GLOBAL_OPTS_H_

#include <netlink/netlink.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rtnl_br_vlan_gopts;
struct rtnl_br_vlan_gopts_entry;

struct rtnl_br_vlan_gopts *rtnl_br_vlan_gopts_alloc(void);
void rtnl_br_vlan_gopts_put(struct rtnl_br_vlan_gopts *gopts);

struct rtnl_br_vlan_gopts_entry *rtnl_br_vlan_gopts_entry_alloc(void);
void rtnl_br_vlan_gopts_entry_free(struct rtnl_br_vlan_gopts_entry *entry);
struct rtnl_br_vlan_gopts_entry *
rtnl_br_vlan_gopts_entry_clone(const struct rtnl_br_vlan_gopts_entry *entry);

int rtnl_br_vlan_gopts_build_modify_request(
	const struct rtnl_br_vlan_gopts *gopts, struct nl_msg **result);

int rtnl_br_vlan_gopts_modify(struct nl_sock *sk,
			      const struct rtnl_br_vlan_gopts *gopts);

int rtnl_br_vlan_gopts_build_get_request(uint32_t ifindex,
					 struct nl_msg **result);

int rtnl_br_vlan_gopts_get_kernel(struct nl_sock *sk, uint32_t ifindex,
				  struct rtnl_br_vlan_gopts **result);

int rtnl_br_vlan_gopts_set_ifindex(struct rtnl_br_vlan_gopts *gopts,
				   uint32_t value);
int rtnl_br_vlan_gopts_get_ifindex(const struct rtnl_br_vlan_gopts *gopts,
				   uint32_t *out);

int rtnl_br_vlan_gopts_set_entry(struct rtnl_br_vlan_gopts *gopts,
				 const struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_set_entry_range(
	struct rtnl_br_vlan_gopts *gopts,
	const struct rtnl_br_vlan_gopts_entry *entry, uint16_t vid_end);

int rtnl_br_vlan_gopts_unset_entry(struct rtnl_br_vlan_gopts *gopts,
				   uint16_t vid);
int rtnl_br_vlan_gopts_unset_entry_range(struct rtnl_br_vlan_gopts *gopts,
					 uint16_t vid_start, uint16_t vid_end);

int rtnl_br_vlan_gopts_get_entry(const struct rtnl_br_vlan_gopts *gopts,
				 uint16_t vid,
				 struct rtnl_br_vlan_gopts_entry **out);

int rtnl_br_vlan_gopts_foreach_gopts_entry(
	const struct rtnl_br_vlan_gopts *gopts,
	void (*cb)(struct rtnl_br_vlan_gopts_entry *entry, void *arg),
	void *arg);

int rtnl_br_vlan_gopts_entry_set_vid(struct rtnl_br_vlan_gopts_entry *entry,
				     uint16_t value);
int rtnl_br_vlan_gopts_entry_get_vid(
	const struct rtnl_br_vlan_gopts_entry *entry, uint16_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_snooping(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_igmp_version(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_mld_version(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *entry, uint32_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_last_member_cnt(
	const struct rtnl_br_vlan_gopts_entry *entry, uint32_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *entry, uint32_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_cnt(
	const struct rtnl_br_vlan_gopts_entry *entry, uint32_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_last_member_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_membership_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_querier_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_query_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_query_response_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry, uint64_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_intvl(
	const struct rtnl_br_vlan_gopts_entry *entry, uint64_t *out);

int rtnl_br_vlan_gopts_entry_set_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *entry, uint8_t value);
int rtnl_br_vlan_gopts_entry_unset_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_mcast_querier(
	const struct rtnl_br_vlan_gopts_entry *entry, uint8_t *out);

int rtnl_br_vlan_gopts_entry_set_msti(struct rtnl_br_vlan_gopts_entry *entry,
				      uint16_t value);
int rtnl_br_vlan_gopts_entry_unset_msti(struct rtnl_br_vlan_gopts_entry *entry);
int rtnl_br_vlan_gopts_entry_get_msti(
	const struct rtnl_br_vlan_gopts_entry *entry, uint16_t *out);

#ifdef __cplusplus
}
#endif

#endif /* NETLINK_BR_VLAN_GLOBAL_OPTS_H_ */
