/*
 * lib/genl/genl.c		Generic Netlink
 *
 *	This library is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU Lesser General Public
 *	License as published by the Free Software Foundation version 2.1
 *	of the License.
 *
 * Copyright (c) 2003-2006 Thomas Graf <tgraf@suug.ch>
 */

/**
 * @ingroup nlfam
 * @defgroup genl Generic Netlink
 *
 * @par Message Format
 * @code
 *  <------- NLMSG_ALIGN(hlen) ------> <---- NLMSG_ALIGN(len) --->
 * +----------------------------+- - -+- - - - - - - - - - -+- - -+
 * |           Header           | Pad |       Payload       | Pad |
 * |      struct nlmsghdr       |     |                     |     |
 * +----------------------------+- - -+- - - - - - - - - - -+- - -+
 * @endcode
 * @code
 *  <-------- GENL_HDRLEN -------> <--- hdrlen -->
 *                                 <------- genlmsg_len(ghdr) ------>
 * +------------------------+- - -+---------------+- - -+------------+
 * | Generic Netlink Header | Pad | Family Header | Pad | Attributes |
 * |    struct genlmsghdr   |     |               |     |            |
 * +------------------------+- - -+---------------+- - -+------------+
 * genlmsg_data(ghdr)--------------^                     ^
 * genlmsg_attrdata(ghdr, hdrlen)-------------------------
 * @endcode
 *
 * @par 1) Creating a new generic netlink message
 * @code
 * struct nl_msg *msg;
 * struct myhdr {
 *         int a;
 *         int b;
 * } *hdr;
 *
 * // Create a new empty netlink message
 * msg = nlmsg_alloc();
 *
 * // Append the netlink and generic netlink message header, this
 * // operation also reserves room for the family specific header.
 * hdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, family, sizeof(hdr),
 *                   NLM_F_ECHO, MYOP, VERSION);
 *
 * // Fill out your own family specific header.
 * hdr->a = 1;
 * hdr->b = 2;
 *
 * // Append the optional attributes.
 * nla_put_u32(msg, 1, 0x10);
 *
 * // Message is ready to be sent.
 * nl_send_auto_complete(nl_handle, msg);
 *
 * // All done? Free the message.
 * nlmsg_free(msg);
 * @endcode
 *
 * @par 2) Sending of trivial messages
 * @code
 * // For trivial messages not requiring any family specific header or
 * // attributes, genl_send_simple() may be used to send messages directly.
 * genl_send_simple(nl_handle, family, MY_SIMPLE_CMD, VERSION, 0);
 * @endcode
 * @{
 */

#include <netlink-generic.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/utils.h>

/**
 * @name Socket Creating
 * @{
 */

int genl_connect(struct nl_handle *handle)
{
	return nl_connect(handle, NETLINK_GENERIC);
}

/** @} */

/**
 * @name Sending
 * @{
 */

/**
 * Send trivial generic netlink message
 * @arg handle		Netlink handle.
 * @arg family		Generic netlink family
 * @arg cmd		Command
 * @arg version		Version
 * @arg flags		Additional netlink message flags.
 *
 * Fills out a routing netlink request message and sends it out
 * using nl_send_simple().
 *
 * @return 0 on success or a negative error code.
 */
int genl_send_simple(struct nl_handle *handle, int family, int cmd,
		     int version, int flags)
{
	struct genlmsghdr hdr = {
		.cmd = cmd,
		.version = version,
	};

	return nl_send_simple(handle, family, flags, &hdr, sizeof(hdr));
}

/** @} */


/**
 * @name Message Parsing
 * @{
 */

/**
 * Get head of message payload
 * @arg gnlh	genetlink messsage header
 */
void *genlmsg_data(const struct genlmsghdr *gnlh)
{
	return ((unsigned char *) gnlh + GENL_HDRLEN);
}

/**
 * Get lenght of message payload
 * @arg gnlh	genetlink message header
 */
int genlmsg_len(const struct genlmsghdr *gnlh)
{
	struct nlmsghdr *nlh = (struct nlmsghdr *)((unsigned char *)gnlh -
							NLMSG_HDRLEN);
	return (nlh->nlmsg_len - GENL_HDRLEN - NLMSG_HDRLEN);
}

/**
 * Get head of attribute data
 * @arg gnlh	generic netlink message header
 * @arg hdrlen	length of family specific header
 */
struct nlattr *genlmsg_attrdata(const struct genlmsghdr *gnlh, int hdrlen)
{
	return genlmsg_data(gnlh) + NLMSG_ALIGN(hdrlen);
}

/**
 * Get length of attribute data
 * @arg gnlh	generic netlink message header
 * @arg hdrlen	length of family specific header
 */
int genlmsg_attrlen(const struct genlmsghdr *gnlh, int hdrlen)
{
	return genlmsg_len(gnlh) - NLMSG_ALIGN(hdrlen);
}

/** @} */

/**
 * @name Message Building
 * @{
 */

/**
 * Add generic netlink header to netlink message
 * @arg msg		netlink message
 * @arg pid		netlink process id or NL_AUTO_PID
 * @arg seq		sequence number of message or NL_AUTO_SEQ
 * @arg family		generic netlink family
 * @arg hdrlen		length of user specific header
 * @arg flags		message flags
 * @arg cmd		generic netlink command
 * @arg version		protocol version
 *
 * Returns pointer to user specific header.
 */
void *genlmsg_put(struct nl_msg *msg, uint32_t pid, uint32_t seq, int family,
		  int hdrlen, int flags, uint8_t cmd, uint8_t version)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr hdr = {
		.cmd = cmd,
		.version = version,
	};

	nlh = nlmsg_put(msg, pid, seq, family, GENL_HDRLEN + hdrlen, flags);
	if (nlh == NULL)
		return NULL;

	memcpy(nlmsg_data(nlh), &hdr, sizeof(hdr));
	NL_DBG(2, "msg %p: Added generic netlink header cmd=%d version=%d\n",
	       msg, cmd, version);

	return nlmsg_data(nlh) + GENL_HDRLEN;
}

/** @} */

/** @} */
