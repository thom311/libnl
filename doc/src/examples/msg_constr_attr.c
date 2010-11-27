struct nl_msg *build_msg(int ifindex, struct nl_addr *lladdr, int mtu)
{
	struct nl_msg *msg;
	struct nlattr *info, *vlan;
	struct ifinfomsg ifi = {
		.ifi_family = AF_INET,
		.ifi_index = ifindex,
	};

	/* Allocate a default sized netlink message */
	if (!(msg = nlmsg_alloc_simple(RTM_SETLINK, 0)))
		return NULL;

	/* Append the protocol specific header (struct ifinfomsg)*/
	if (nlmsg_append(msg, &ifi, sizeof(ifi), NLMSG_ALIGNTO) < 0)
		goto nla_put_failure

	/* Append a 32 bit integer attribute to carry the MTU */
	NLA_PUT_U32(msg, IFLA_MTU, mtu);

	/* Append a unspecific attribute to carry the link layer address */
	NLA_PUT_ADDR(msg, IFLA_ADDRESS, lladdr);

	/* Append a container for nested attributes to carry link information */
	if (!(info = nla_nest_start(msg, IFLA_LINKINFO)))
		goto nla_put_failure;

	/* Put a string attribute into the container */
	NLA_PUT_STRING(msg, IFLA_INFO_KIND, "vlan");

	/*
	 * Append another container inside the open container to carry
	 * vlan specific attributes
	 */
	if (!(vlan = nla_nest_start(msg, IFLA_INFO_DATA)))
		goto nla_put_failure;

	/* add vlan specific info attributes here... */

	/* Finish nesting the vlan attributes and close the second container. */
	nla_nest_end(msg, vlan);

	/* Finish nesting the link info attribute and close the first container. */
	nla_nest_end(msg, info);

	return msg;

nla_put_failure:
	nlmsg_free(msg);
	return NULL;
}
