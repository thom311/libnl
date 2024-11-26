/* SPDX-License-Identifier: LGPL-2.1-only */
/*
 * Copyright (c) 2003-2013 Thomas Graf <tgraf@suug.ch>
 */

#ifndef NETLINK_LINK_API_H_
#define NETLINK_LINK_API_H_

#include <netlink/netlink.h>
#include <netlink/route/link.h>

#include "nl-priv-dynamic-core/nl-core.h"

/**
 * @ingroup link_api
 *
 * Available operations to modules implementing a link info type.
 */
struct rtnl_link_info_ops
{
	/** Name of link info type, must match name on kernel side */
	char *		io_name;

	/** Reference count, DO NOT MODIFY */
	int		io_refcnt;

	/** Called to assign an info type to a link.
	 * Has to allocate enough resources to hold attributes. Can
	 * use link->l_info to store a pointer. */
	int	      (*io_alloc)(struct rtnl_link *);

	/** Called to parse the link info attribute.
	 * Must parse the attribute and assign all values to the link.
	 */
	int	      (*io_parse)(struct rtnl_link *,
				  struct nlattr *,
				  struct nlattr *);

	/** Called when the link object is dumped.
	 * Must dump the info type specific attributes. */
	void	      (*io_dump[NL_DUMP_MAX+1])(struct rtnl_link *,
						struct nl_dump_params *);

	/** Called when a link object is cloned.
	 * Must clone all info type specific attributes. */
	int	      (*io_clone)(struct rtnl_link *, struct rtnl_link *);

	/** Called when construction a link netlink message.
	 * Must append all info type specific attributes to the message. */
	int	      (*io_put_attrs)(struct nl_msg *, struct rtnl_link *);

	/** Called to release all resources previously allocated
	 * in either io_alloc() or io_parse(). */
	void	      (*io_free)(struct rtnl_link *);

	/** Called to compare link info parameters between two links. */
	int	      (*io_compare)(struct rtnl_link *, struct rtnl_link *,
				    int flags);

	struct nl_list_head		io_list;
};

extern struct rtnl_link_info_ops *rtnl_link_info_ops_lookup(const char *);
extern void			rtnl_link_info_ops_get(struct rtnl_link_info_ops *);
extern void			rtnl_link_info_ops_put(struct rtnl_link_info_ops *);
extern int			rtnl_link_register_info(struct rtnl_link_info_ops *);
extern int			rtnl_link_unregister_info(struct rtnl_link_info_ops *);


/**
 * @ingroup link_api
 *
 * Available operations to modules implementing a link address family.
 */
struct rtnl_link_af_ops
{
	/** The address family this operations set implements */
	const unsigned int	ao_family;

	/** Number of users of this operations, DO NOT MODIFY. */
	int			ao_refcnt;

	/** Validation policy for IFLA_PROTINFO attribute. This pointer
	 * can be set to a nla_policy structure describing the minimal
	 * requirements the attribute must meet. Failure of meeting these
	 * requirements will result in a parsing error. */
	const struct nla_policy *ao_protinfo_policy;

	/** Called after address family has been assigned to link. Must
	 * allocate data buffer to hold address family specific data and
	 * store it in link->l_af_data. */
	void *		      (*ao_alloc)(struct rtnl_link *);

	/** Called when the link is cloned, must allocate a clone of the
	 * address family specific buffer and return it. */
	void *		      (*ao_clone)(struct rtnl_link *, void *);

	/** Called when the link gets freed. Must free all allocated data */
	void		      (*ao_free)(struct rtnl_link *, void *);

	/** Called if a IFLA_PROTINFO attribute needs to be parsed. Typically
	 * stores the parsed data in the address family specific buffer. */
	int		      (*ao_parse_protinfo)(struct rtnl_link *,
						   struct nlattr *, void *);

	/** Called if a IFLA_AF_SPEC attribute needs to be parsed. Typically
	 * stores the parsed data in the address family specific buffer. */
	int		      (*ao_parse_af)(struct rtnl_link *,
					     struct nlattr *, void *);

	/** Called if a link message is sent to the kernel. Must append the
	 * link address family specific attributes to the message. */
	int		      (*ao_fill_af)(struct rtnl_link *,
					    struct nl_msg *msg, void *);

	/** Called if the full IFLA_AF_SPEC data needs to be parsed. Typically
	 * stores the parsed data in the address family specific buffer. */
	int                   (*ao_parse_af_full)(struct rtnl_link *,
	                                          struct nlattr *, void *);

	/** Called for GETLINK message to the kernel. Used to append
	 * link address family specific attributes to the request message. */
	int		      (*ao_get_af)(struct nl_msg *msg,
					   uint32_t *ext_filter_mask);

	/** Dump address family specific link attributes */
	void		      (*ao_dump[NL_DUMP_MAX+1])(struct rtnl_link *,
							struct nl_dump_params *,
							void *);

	/** Comparison function
	 *
	 * Will be called when two links are compared for their af data. It
	 * takes two link objects in question, an object specific bitmask
	 * defining which attributes should be compared and flags to control
	 * the behaviour
	 *
	 * The function must return a bitmask with the relevant bit set for
	 * each attribute that mismatches
	 */
	int		      (*ao_compare)(struct rtnl_link *,
					    struct rtnl_link *, int, uint32_t, int);

	/**
	 * Update function
	 *
	 * Will be called when af data of the link object given by first argument
	 * needs to be updated with the af data of the second supplied link object
	 *
	 * The function must return 0 for success and error for failure
	 * to update. In case of failure its assumed that the original
	 * object is not touched
	 */
	int		      (*ao_update)(struct rtnl_link *, struct rtnl_link *);

	/* RTM_NEWLINK override
	 *
	 * Called if a change link request is set to the kernel. If this returns
	 * anything other than zero, RTM_NEWLINK will be overriden with
	 * RTM_SETLINK when rtnl_link_build_change_request() is called.
	 */
	int		      (*ao_override_rtm)(struct rtnl_link *);

	/** Called if a link message is sent to the kernel. Must append the
	 * link protocol specific attributes to the message. (IFLA_PROTINFO) */
	int		      (*ao_fill_pi)(struct rtnl_link *,
								struct nl_msg *msg, void *);

	/** PROTINFO type
	 *
	 * Called if a link message is sent to the kernel. If this is set,
	 * the default IFLA_PROTINFO is bitmasked with what is specified
	 * here. (eg. NLA_F_NESTED)
	 */
	const int ao_fill_pi_flags;

	/** IFLA_AF_SPEC nesting override
	 *
	 * Called if a link message is sent to the kernel. If this is set,
	 * the AF specific nest is not created. Instead, AF specific attributes
	 * are nested directly in the IFLA_AF_SPEC attribute.
	 */
	 const int ao_fill_af_no_nest;
};

extern struct rtnl_link_af_ops *rtnl_link_af_ops_lookup(unsigned int);
extern void			rtnl_link_af_ops_put(struct rtnl_link_af_ops *);
extern void *			rtnl_link_af_alloc(struct rtnl_link *,
						const struct rtnl_link_af_ops *);
extern void *			rtnl_link_af_data(const struct rtnl_link *,
						const struct rtnl_link_af_ops *);
extern int			rtnl_link_af_register(struct rtnl_link_af_ops *);
extern int			rtnl_link_af_unregister(struct rtnl_link_af_ops *);
extern int			rtnl_link_af_data_compare(struct rtnl_link *a,
							  struct rtnl_link *b,
							  int family);
extern int			rtnl_link_info_data_compare(struct rtnl_link *a,
							    struct rtnl_link *b,
							    int flags);

extern struct rtnl_link *link_lookup(struct nl_cache *cache, int ifindex);

#endif
