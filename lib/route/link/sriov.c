/*
 * lib/route/link/sriov.c      SRIOV VF Info
 *
 *     This library is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU Lesser General Public
 *     License as published by the Free Software Foundation version 2.1
 *     of the License.
 *
 * Copyright (c) 2016 Intel Corp. All rights reserved.
 * Copyright (c) 2016 Jef Oliver <jef.oliver@intel.com>
 */

/**
 * @ingroup link
 * @defgroup sriov SRIOV
 * SR-IOV VF link module
 *
 * @details
 * SR-IOV (Single Root Input/Output Virtualization) is a network interface
 * that allows for the isolation of the PCI Express resources. In a virtual
 * environment, SR-IOV allows multiple virtual machines can share a single
 * PCI Express hardware interface. This is done via VFs (Virtual Functions),
 * virtual hardware devices with their own PCI address.
 *
 * @{
 */

#include <netlink-private/netlink.h>
#include <netlink-private/route/link/api.h>
#include <netlink/netlink.h>
#include <netlink/route/link.h>

#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <netlink-private/route/link/sriov.h>
#include <netlink/route/link/sriov.h>

/** @cond SKIP */

#define SET_VF_STAT(link, vf_num, stb, stat, attr) \
	vf_data->vf_stats[stat] = nla_get_u64(stb[attr])

/* SRIOV-VF Attributes */
#define SRIOV_ATTR_INDEX 		(1 <<  0)
#define SRIOV_ATTR_ADDR 		(1 <<  1)
#define SRIOV_ATTR_VLAN 		(1 <<  2)
#define SRIOV_ATTR_TX_RATE 		(1 <<  3)
#define SRIOV_ATTR_SPOOFCHK 		(1 <<  4)
#define SRIOV_ATTR_RATE_MAX 		(1 <<  5)
#define SRIOV_ATTR_RATE_MIN 		(1 <<  6)
#define SRIOV_ATTR_LINK_STATE 		(1 <<  7)
#define SRIOV_ATTR_RSS_QUERY_EN 	(1 <<  8)
#define SRIOV_ATTR_STATS 		(1 <<  9)
#define SRIOV_ATTR_TRUST 		(1 << 10)

static struct nla_policy sriov_info_policy[IFLA_VF_MAX+1] = {
	[IFLA_VF_MAC]		= { .minlen = sizeof(struct ifla_vf_mac) },
	[IFLA_VF_VLAN]		= { .minlen = sizeof(struct ifla_vf_vlan) },
	[IFLA_VF_VLAN_LIST]     = { .type = NLA_NESTED },
	[IFLA_VF_TX_RATE]	= { .minlen = sizeof(struct ifla_vf_tx_rate) },
	[IFLA_VF_SPOOFCHK]	= { .minlen = sizeof(struct ifla_vf_spoofchk) },
	[IFLA_VF_RATE]		= { .minlen = sizeof(struct ifla_vf_rate) },
	[IFLA_VF_LINK_STATE]	= { .minlen = sizeof(struct ifla_vf_link_state) },
	[IFLA_VF_RSS_QUERY_EN]	= { .minlen = sizeof(struct ifla_vf_rss_query_en) },
	[IFLA_VF_STATS]		= { .type = NLA_NESTED },
	[IFLA_VF_TRUST]		= { .minlen = sizeof(struct ifla_vf_trust) },
	[IFLA_VF_IB_NODE_GUID]	= { .minlen = sizeof(struct ifla_vf_guid) },
	[IFLA_VF_IB_PORT_GUID]	= { .minlen = sizeof(struct ifla_vf_guid) },
};

static struct nla_policy sriov_stats_policy[IFLA_VF_STATS_MAX+1] = {
	[IFLA_VF_STATS_RX_PACKETS]	= { .type = NLA_U64 },
	[IFLA_VF_STATS_TX_PACKETS]	= { .type = NLA_U64 },
	[IFLA_VF_STATS_RX_BYTES]	= { .type = NLA_U64 },
	[IFLA_VF_STATS_TX_BYTES]	= { .type = NLA_U64 },
	[IFLA_VF_STATS_BROADCAST]	= { .type = NLA_U64 },
	[IFLA_VF_STATS_MULTICAST]	= { .type = NLA_U64 },
};

/** @endcond */

/* Free stored SRIOV VF data */
void rtnl_link_sriov_free_data(struct rtnl_link *link) {
	int err = 0;
	struct rtnl_link_vf *list, *vf, *next;

	if (!(err = rtnl_link_has_vf_list(link)))
		return;

	list = link->l_vf_list;
	nl_list_for_each_entry_safe(vf, next, &list->vf_list, vf_list) {
		nl_list_del(&vf->vf_list);
		rtnl_link_vf_put(vf);
	}

	rtnl_link_vf_put(link->l_vf_list);

	return;
}

/* Fill VLAN info array */
static int rtnl_link_vf_vlan_info(int len, struct ifla_vf_vlan_info **vi,
				  nl_vf_vlans_t **nvi) {
	int cur = 0, err;
	nl_vf_vlans_t *vlans;

	if (len <= 0)
		return 0;

	if ((err = rtnl_link_vf_vlan_alloc(&vlans, len)) < 0)
		return err;

	cur = 0;
	while (cur < len) {
		vlans->vlans[cur].vf_vlan = vi[cur]->vlan ? vi[cur]->vlan : 0;
		vlans->vlans[cur].vf_vlan_qos = vi[cur]->qos ? vi[cur]->qos : 0;
		if (vi[cur]->vlan_proto) {
			vlans->vlans[cur].vf_vlan_proto = ntohs(vi[cur]->vlan_proto);
		} else {
			vlans->vlans[cur].vf_vlan_proto = ETH_P_8021Q;
		}
		cur++;
	}

	*nvi = vlans;
	return 0;
}

/* Parse IFLA_VFINFO_LIST and IFLA_VF_INFO attributes */
int rtnl_link_sriov_parse_vflist(struct rtnl_link *link, struct nlattr **tb) {
	int err, len, list_len, list_rem;
	struct ifla_vf_mac *vf_lladdr;
	struct ifla_vf_vlan *vf_vlan;
	struct ifla_vf_vlan_info *vf_vlan_info[MAX_VLAN_LIST_LEN];
	struct ifla_vf_tx_rate *vf_tx_rate;
	struct ifla_vf_spoofchk *vf_spoofchk;
	struct ifla_vf_link_state *vf_linkstate;
	struct ifla_vf_rate *vf_rate;
	struct ifla_vf_rss_query_en *vf_rss_query;
	struct ifla_vf_trust *vf_trust;
	struct nlattr *nla, *nla_list, *t[IFLA_VF_MAX+1],
		*stb[RTNL_LINK_VF_STATS_MAX+1];
	nl_vf_vlans_t *vf_vlans = NULL;
	struct rtnl_link_vf *vf_data, *vf_head = NULL;

	len = nla_len(tb[IFLA_VFINFO_LIST]);
	link->l_vf_list = rtnl_link_vf_alloc();
	if (!link->l_vf_list)
		return -NLE_NOMEM;
	vf_head = link->l_vf_list;

	for (nla = nla_data(tb[IFLA_VFINFO_LIST]); nla_ok(nla, len);
	     nla = nla_next(nla, &len)) {
		err = nla_parse(t, IFLA_VF_MAX, nla_data(nla), nla_len(nla),
				sriov_info_policy);
		if (err < 0)
			return err;

		vf_data = rtnl_link_vf_alloc();
		if (!vf_data)
			return -NLE_NOMEM;

		if (t[IFLA_VF_MAC]) {
			vf_lladdr = nla_data(t[IFLA_VF_MAC]);

			vf_data->vf_index = vf_lladdr->vf;
			vf_data->ce_mask |= SRIOV_ATTR_INDEX;

			vf_data->vf_lladdr = nl_addr_build(AF_LLC,
							   vf_lladdr->mac, 6);
			if (vf_data->vf_lladdr == NULL)
				return -NLE_NOMEM;
			nl_addr_set_family(vf_data->vf_lladdr, AF_LLC);
			vf_data->ce_mask |= SRIOV_ATTR_ADDR;
		}

		if (t[IFLA_VF_VLAN_LIST]) {
			list_len = 0;
			nla_for_each_nested(nla_list, t[IFLA_VF_VLAN_LIST],
					    list_rem) {
				vf_vlan_info[len] = nla_data(nla_list);
				list_len++;
			}

			err = rtnl_link_vf_vlan_info(list_len, vf_vlan_info,
						     &vf_vlans);
			if (err < 0)
				return err;

			vf_data->vf_vlans = vf_vlans;
			vf_data->ce_mask |= SRIOV_ATTR_VLAN;
		} else if (t[IFLA_VF_VLAN]) {
			vf_vlan = nla_data(t[IFLA_VF_VLAN]);

			if (vf_vlan->vlan) {
				err = rtnl_link_vf_vlan_alloc(&vf_vlans, 1);
				if (err < 0)
					return err;

				vf_vlans->vlans[0].vf_vlan = vf_vlan->vlan;
				vf_vlans->vlans[0].vf_vlan_qos = vf_vlan->qos;
				vf_vlans->vlans[0].vf_vlan_proto = ETH_P_8021Q;

				vf_data->vf_vlans = vf_vlans;
				vf_data->ce_mask |= SRIOV_ATTR_VLAN;
			}
		}

		if (t[IFLA_VF_TX_RATE]) {
			vf_tx_rate = nla_data(t[IFLA_VF_TX_RATE]);

			if (vf_tx_rate->rate) {
				vf_data->vf_rate = vf_tx_rate->rate;
				vf_data->ce_mask |= SRIOV_ATTR_TX_RATE;
			}
		}

		if (t[IFLA_VF_SPOOFCHK]) {
			vf_spoofchk = nla_data(t[IFLA_VF_SPOOFCHK]);

			if (vf_spoofchk->setting != -1) {
				vf_data->vf_spoofchk = vf_spoofchk->setting ? 1 : 0;
				vf_data->ce_mask |= SRIOV_ATTR_SPOOFCHK;
			}
		}

		if (t[IFLA_VF_LINK_STATE]) {
			vf_linkstate = nla_data(t[IFLA_VF_LINK_STATE]);

			vf_data->vf_linkstate = vf_linkstate->link_state;
			vf_data->ce_mask |= SRIOV_ATTR_LINK_STATE;
		}

		if (t[IFLA_VF_RATE]) {
			vf_rate = nla_data(t[IFLA_VF_RATE]);

			if (vf_rate->max_tx_rate) {
				vf_data->vf_max_tx_rate = vf_rate->max_tx_rate;
				vf_data->ce_mask |= SRIOV_ATTR_RATE_MAX;
			}
			if (vf_rate->min_tx_rate) {
				vf_data->vf_min_tx_rate = vf_rate->min_tx_rate;
				vf_data->ce_mask |= SRIOV_ATTR_RATE_MIN;
			}
		}

		if (t[IFLA_VF_RSS_QUERY_EN]) {
			vf_rss_query = nla_data(t[IFLA_VF_RSS_QUERY_EN]);

			if (vf_rss_query->setting != -1) {
				vf_data->vf_rss_query_en = vf_rss_query->setting ? 1 : 0;
				vf_data->ce_mask |= SRIOV_ATTR_RSS_QUERY_EN;
			}
		}

		if (t[IFLA_VF_STATS]) {
			err = nla_parse_nested(stb, IFLA_VF_STATS_MAX,
					       t[IFLA_VF_STATS],
					       sriov_stats_policy);
			if (err < 0)
				return err;

			SET_VF_STAT(link, cur, stb,
				    RTNL_LINK_VF_STATS_RX_PACKETS,
				    IFLA_VF_STATS_RX_PACKETS);
			SET_VF_STAT(link, cur, stb,
				    RTNL_LINK_VF_STATS_TX_PACKETS,
				    IFLA_VF_STATS_TX_PACKETS);
			SET_VF_STAT(link, cur, stb,
				    RTNL_LINK_VF_STATS_RX_BYTES,
				    IFLA_VF_STATS_RX_BYTES);
			SET_VF_STAT(link, cur, stb,
				    RTNL_LINK_VF_STATS_TX_BYTES,
				    IFLA_VF_STATS_TX_BYTES);
			SET_VF_STAT(link, cur, stb,
				    RTNL_LINK_VF_STATS_BROADCAST,
				    IFLA_VF_STATS_BROADCAST);
			SET_VF_STAT(link, cur, stb,
				    RTNL_LINK_VF_STATS_MULTICAST,
				    IFLA_VF_STATS_MULTICAST);

			vf_data->ce_mask |= IFLA_VF_STATS;
		}

		if (t[IFLA_VF_TRUST]) {
			vf_trust = nla_data(t[IFLA_VF_TRUST]);

			if (vf_trust->setting != -1) {
				vf_data->vf_trust = vf_trust->setting ? 1 : 0;
				vf_data->ce_mask |= SRIOV_ATTR_TRUST;
			}
		}

		nl_list_add_head(&vf_data->vf_list, &vf_head->vf_list);
		vf_head = vf_data;
	}

	return 0;
}

/**
 * @name SR-IOV Sub-Object
 * @{
 */

/**
 * Allocate a new SRIOV VF object
 *
 * @return NULL if out of memory
 * @return New VF Object
 *
 * @see rtnl_link_vf_put()
 *
 * The SRIOV VF object must be returned to the link object with
 * rtnl_link_vf_put() when operations are done to prevent memory leaks.
 */
struct rtnl_link_vf *rtnl_link_vf_alloc(void) {
	struct rtnl_link_vf *vf;

	if (!(vf = calloc(1, sizeof(*vf))))
		return NULL;

	NL_INIT_LIST_HEAD(&vf->vf_list);
	vf->ce_refcnt = 1;

	NL_DBG(4, "Allocated new SRIOV VF object %p\n", vf);

	return vf;
}

/**
 * Free SRIOV VF object.
 * @arg vf_data 	SRIOV VF data object
 */
void rtnl_link_vf_free(struct rtnl_link_vf *vf_data) {
	if (!vf_data)
		return;

	if (vf_data->ce_refcnt > 0)
		NL_DBG(1, "Warning: Freeing SRIOV VF object in use...\n");

	if (vf_data->ce_mask & SRIOV_ATTR_ADDR)
		nl_addr_put(vf_data->vf_lladdr);
	if (vf_data->ce_mask & SRIOV_ATTR_VLAN)
		rtnl_link_vf_vlan_put(vf_data->vf_vlans);

	NL_DBG(4, "Freed SRIOV VF object %p\n", vf_data);
	free(vf_data);

	return;
}

/**
 * Lookup SRIOV VF in link object by VF index.
 *
 * @return NULL if VF not found
 * @return VF Object
 *
 * @see rtnl_link_vf_put()
 *
 * The SRIOV VF object must be returned to the link object with
 * rtnl_link_vf_put() when operations are done to prevent memory leaks.
 */
struct rtnl_link_vf *rtnl_link_vf_get(struct rtnl_link *link, uint32_t vf_num) {
	struct rtnl_link_vf *list, *vf, *next, *ret = NULL;

	list = link->l_vf_list;
	nl_list_for_each_entry_safe(vf, next, &list->vf_list, vf_list) {
		if (vf->vf_index == vf_num) {
			ret = vf;
			break;
		}
	}

	if (ret) {
		ret->ce_refcnt++;
		NL_DBG(4, "New reference to SRIOV VF object %p, total %i\n",
		       ret, ret->ce_refcnt);
	}

	return ret;
}

/**
 * Return SRIOV VF object to the owning link object.
 * @arg vf_data 	SRIOV VF data object
 *
 * @see rtnl_link_vf_alloc()
 * @see rtnl_link_vf_get()
 */
void rtnl_link_vf_put(struct rtnl_link_vf *vf_data) {
	if (!vf_data)
		return;

	vf_data->ce_refcnt--;
	NL_DBG(4, "Returned SRIOV VF object reference %p, %i remaining\n",
	       vf_data, vf_data->ce_refcnt);

	if (vf_data->ce_refcnt < 0)
		BUG();

	if (vf_data->ce_refcnt <= 0)
		rtnl_link_vf_free(vf_data);

	return;
}

/**
 * Get link layer address of SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg addr 		Pointer to store Link Layer address
 *
 * @see rtnl_link_get_num_vf()
 *
 * @copydoc pointer_lifetime_warning
 * @return 0 if addr is present and addr is set to pointer containing address
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the link layer address is not set
 */
int rtnl_link_vf_get_addr(struct rtnl_link_vf *vf_data, struct nl_addr **addr)
{
	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_ADDR)
		*addr = vf_data->vf_lladdr;
	else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get index of SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg vf_index 	Pointer to store VF index
 *
 * @see rtnl_link_get_num_vf()
 *
 * @return 0 if index is present and vf_index is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF index is not set
 */
int rtnl_link_vf_get_index(struct rtnl_link_vf *vf_data, uint32_t *vf_index)
{
	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_INDEX)
		*vf_index = vf_data->vf_index;
	else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get link state of SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg vf_linkstate 	Pointer to store VF link state
 *
 * @see rtnl_link_get_num_vf()
 *
 * @return 0 if link state is present and vf_linkstate is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF link state is not set
 */
int rtnl_link_vf_get_linkstate(struct rtnl_link_vf *vf_data,
			       uint32_t *vf_linkstate)
{
	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_LINK_STATE)
		*vf_linkstate = vf_data->vf_linkstate;
	else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get TX Rate Limit of SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg vf_rate 	Pointer to store VF rate limiting data
 *
 * @see rtnl_link_get_num_vf()
 *
 * When the older rate API has been implemented, the rate member of the struct
 * will be set, and the api member will be set to RTNL_LINK_VF_API_OLD.
 * When the newer rate API has been implemented, the max_tx_rate
 * and/or the minx_tx_rate will be set, and the api member will be set to
 * RTNL_LINK_VF_API_NEW.
 *
 * @return 0 if rate is present and vf_rate is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF rate is not set
 */
int rtnl_link_vf_get_rate(struct rtnl_link_vf *vf_data,
			  struct nl_vf_rate *vf_rate)
{
	int set = 0;

	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	vf_rate->api = RTNL_LINK_VF_RATE_API_UNSPEC;
	vf_rate->rate = 0;
	vf_rate->max_tx_rate = 0;
	vf_rate->min_tx_rate = 0;

	if (vf_data->ce_mask & SRIOV_ATTR_RATE_MAX) {
		if (vf_data->vf_max_tx_rate) {
			vf_rate->api = RTNL_LINK_VF_RATE_API_NEW;
			vf_rate->max_tx_rate = vf_data->vf_max_tx_rate;
			set = 1;
		}
	}
	if (vf_data->ce_mask & SRIOV_ATTR_RATE_MIN) {
		if (vf_data->vf_min_tx_rate) {
			vf_rate->api = RTNL_LINK_VF_RATE_API_NEW;
			vf_rate->min_tx_rate = vf_data->vf_min_tx_rate;
			set = 1;
		}
	}
	if ((!set) && (vf_data->ce_mask & SRIOV_ATTR_TX_RATE)) {
		if (vf_data->vf_rate) {
			vf_rate->api = RTNL_LINK_VF_RATE_API_OLD;
			vf_rate->rate = vf_data->vf_rate;
			set = 1;
		}
	}

	if (!set)
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get RSS Query EN value of SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg vf_rss_query_en	Pointer to store VF RSS Query value
 *
 * @see rtnl_link_get_num_vf()
 *
 * @return 0 if rss_query_en is present and vf_rss_query_en is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF RSS Query EN value is not set
 */
int rtnl_link_vf_get_rss_query_en(struct rtnl_link_vf *vf_data,
				  uint32_t *vf_rss_query_en)
{
	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_RSS_QUERY_EN)
		*vf_rss_query_en = vf_data->vf_rss_query_en;
	else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get spoof checking value of SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg vf_spoofchk 	Pointer to store VF spoofchk value
 *
 * @see rtnl_link_get_num_vf()
 *
 * @return 0 if spoofchk is present and vf_spoofchk is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF spoofcheck is not set
 */
int rtnl_link_vf_get_spoofchk(struct rtnl_link_vf *vf_data,
			      uint32_t *vf_spoofchk)
{
	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_SPOOFCHK)
		*vf_spoofchk = vf_data->vf_spoofchk;
	else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get value of stat counter for SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg stat 		Identifier of statistical counter
 * @arg vf_stat 	Pointer to store VF stat value in
 *
 * @see rtnl_link_get_num_vf()
 *
 * @return 0 if stat is present and vf_stat is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF stat is not set
 */
int rtnl_link_vf_get_stat(struct rtnl_link_vf *vf_data,
			  rtnl_link_vf_stats_t stat, uint64_t *vf_stat)
{
	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_STATS)
		*vf_stat = vf_data->vf_stats[stat];
	else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get trust setting of SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg vf_trust 	Pointer to store VF trust value
 *
 * @see rtnl_link_get_num_vf()
 *
 * @return 0 if trust is present and vf_trust is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF trust setting is not set
 */
int rtnl_link_vf_get_trust(struct rtnl_link_vf *vf_data, uint32_t *vf_trust)
{
	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_TRUST)
		*vf_trust = vf_data->vf_trust;
	else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Get an array of VLANS on SRIOV Virtual Function
 * @arg vf_data 	SRIOV VF object
 * @arg vf_vlans 	Pointer to nl_vf_vlans_t struct to store vlan info.
 *
 * @see rtnl_link_get_num_vf()
 *
 * The SRIOV VF VLANs object must be returned to the SRIOV VF object with
 * rtnl_link_vf_vlans_put() when operations are done to prevent memory leaks.
 *
 * @copydoc pointer_lifetime_warning
 * @return 0 if VLAN info is present and vf_vlans is set
 * @return -NLE_OBJ_NOTFOUND if information for VF info is not found
 * @return -NLE_NOATTR if the VF vlans is not set
 */
int rtnl_link_vf_get_vlans(struct rtnl_link_vf *vf_data,
			   nl_vf_vlans_t **vf_vlans) {
	nl_vf_vlans_t *vf;

	if (!vf_data)
		return -NLE_OBJ_NOTFOUND;

	if (vf_data->ce_mask & SRIOV_ATTR_VLAN) {
		vf = vf_data->vf_vlans;
		vf->ce_refcnt++;
		*vf_vlans = vf;
	} else
		return -NLE_NOATTR;

	return 0;
}

/**
 * Allocate a SRIOV VF VLAN object
 * @param vf_vlans 	Pointer to store VLAN object at
 * @param vlan_count 	Number of VLANs that will be stored in VLAN object
 *
 * The SRIOV VF VLANs object must be returned to the sRIOV VF object with
 * rtnl_link_vf_vlan_put() when operations are done to prevent memory leaks.
 *
 * @return 0 if VLAN object is created and vf_vlans is set.
 * @return -NLE_NOMEM if object could not be allocated.
 * @return -NLE_INVAL if vlan_count is more than supported by SRIOV VF
 */
int rtnl_link_vf_vlan_alloc(nl_vf_vlans_t **vf_vlans, int vlan_count) {
	nl_vf_vlans_t *vlans;
	nl_vf_vlan_info_t *vlan_info;

	if (vlan_count > MAX_VLAN_LIST_LEN)
		return -NLE_INVAL;

	vlans = calloc(1, sizeof(*vlans));
	if (!vf_vlans)
		return -NLE_NOMEM;

	vlan_info = calloc(vlan_count+1, sizeof(*vlan_info));
	if (!vlan_info) {
		free(vlans);
		return -NLE_NOMEM;
	}

	NL_DBG(4, "Allocated new SRIOV VF VLANs object %p\n", vlans);

	vlans->ce_refcnt = 1;
	vlans->size = vlan_count;
	vlans->vlans = vlan_info;
	*vf_vlans = vlans;

	return 0;
}

/**
 * Free an allocated SRIOV VF VLANs object
 * @param vf_vlans 	SRIOV VF VLANs object
 */
void rtnl_link_vf_vlan_free(nl_vf_vlans_t *vf_vlans) {
	if (!vf_vlans)
		return;

	if (vf_vlans->ce_refcnt > 0)
		NL_DBG(1, "Warning: Freeing SRIOV VF VLANs object in use...\n");

	NL_DBG(4, "Freed SRIOV VF object %p\n", vf_vlans);
	free(vf_vlans->vlans);
	free(vf_vlans);

	return;
}

/**
 * Return SRIOV VF VLANs object to the owning SRIOV VF object.
 * @param vf_vlans 	SRIOV VF VLANs object
 */
void rtnl_link_vf_vlan_put(nl_vf_vlans_t *vf_vlans) {
	if (!vf_vlans)
		return;

	vf_vlans->ce_refcnt--;
	NL_DBG(4, "Returned SRIOV VF VLANs object reference %p, %i remaining\n",
	       vf_vlans, vf_vlans->ce_refcnt);

	if (vf_vlans->ce_refcnt < 0)
		BUG();

	if (vf_vlans->ce_refcnt <= 0)
		rtnl_link_vf_vlan_free(vf_vlans);

	return;
}


/** @} */

/** @} */
