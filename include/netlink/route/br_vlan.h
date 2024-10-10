/* SPDX-License-Identifier: LGPL-2.1-only */

#ifndef NETLINK_BR_VLAN_H_
#define NETLINK_BR_VLAN_H_

#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/route/link.h>

#ifdef __cplusplus
extern "C" {
#endif

struct rtnl_br_vlan;
struct rtnl_br_vlan_gopts_entry;
// struct rtnl_br_vlan_entry;

struct rtnl_br_vlan *rtnl_br_vlan_alloc(void);
void rtnl_br_vlan_put(struct rtnl_br_vlan *br_vlan);

struct rtnl_br_vlan_gopts_entry *rtnl_br_vlan_gopts_alloc(void);
void rtnl_br_vlan_gopts_put(struct rtnl_br_vlan_gopts_entry *opts);

void rtnl_br_vlan_gopts_append(struct rtnl_br_vlan *br_vlan,
			       struct rtnl_br_vlan_gopts_entry *opts);

// int rtnl_br_vlan_global_opts_build_change_request(
// 	struct rtnl_br_vlan_gopts_entry *old,
// 	struct rtnl_br_vlan_gopts_entry *tmpl, struct nl_msg **result);
// int rtnl_br_vlan_global_opts_change(struct nl_sock *sk,
// 				    struct rtnl_br_vlan_gopts_entry *old,
// 				    struct rtnl_br_vlan_gopts_entry *tmpl);
int rtnl_br_vlan_gopts_list_build_set_request(struct rtnl_br_vlan *opts_list,
					      struct nl_msg **result);
int rtnl_br_vlan_gopts_list_set(struct nl_sock *sk,
				struct rtnl_br_vlan *opts_list);

//////

int rtnl_br_vlan_set_ifindex(struct rtnl_br_vlan *br_vlan, uint32_t value);
int rtnl_br_vlan_get_ifindex(struct rtnl_br_vlan *br_vlan, uint32_t *out);

void rtnl_br_vlan_add_gopts_entry(struct rtnl_br_vlan *br_vlan,
				  struct rtnl_br_vlan_gopts_entry *entry);
void rtnl_br_vlan_foreach_gopts_entry(
	struct rtnl_br_vlan *br_vlan,
	void (*cb)(struct rtnl_br_vlan_gopts_entry *, void *), void *arg);

int rtnl_br_vlan_gopts_entry_set_id(struct rtnl_br_vlan_gopts_entry *opts,
				    uint16_t value);
int rtnl_br_vlan_gopts_entry_get_id(struct rtnl_br_vlan_gopts_entry *opts,
				    uint16_t *out);
int rtnl_br_vlan_gopts_entry_set_range(struct rtnl_br_vlan_gopts_entry *opts,
				       uint16_t value);
int rtnl_br_vlan_gopts_entry_get_range(struct rtnl_br_vlan_gopts_entry *opts,
				       uint16_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_snooping(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_igmp_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_mld_version(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_last_member_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_cnt(
	struct rtnl_br_vlan_gopts_entry *opts, uint32_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_last_member_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_membership_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_querier_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_query_response_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_startup_query_intvl(
	struct rtnl_br_vlan_gopts_entry *opts, uint64_t *out);
int rtnl_br_vlan_gopts_entry_set_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t value);
int rtnl_br_vlan_gopts_entry_get_mcast_querier(
	struct rtnl_br_vlan_gopts_entry *opts, uint8_t *out);
int rtnl_br_vlan_gopts_entry_set_msti(struct rtnl_br_vlan_gopts_entry *opts,
				      uint16_t value);
int rtnl_br_vlan_gopts_entry_get_msti(struct rtnl_br_vlan_gopts_entry *opts,
				      uint16_t *out);

// TODO: add getters

#ifdef __cplusplus
}
#endif

#endif /* NETLINK_BR_VLAN_H_ */
