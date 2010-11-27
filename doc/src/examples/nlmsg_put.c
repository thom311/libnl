#include <netlink/msg.h>

struct nlmsghdr *hdr;
struct nl_msg *msg;
struct myhdr {
	uint32_t foo1, foo2;
} hdr = { 10, 20 };

/* Allocate a message with the default maximum message size */
msg = nlmsg_alloc();

/*
 * Add header with message type MY_MSGTYPE, the flag NLM_F_CREATE,
 * let library fill port and sequence number, and reserve room for
 * struct myhdr
 */
hdr = nlmsg_put(msg, NL_AUTO_PORT, NL_AUTO_SEQ, MY_MSGTYPE, sizeof(hdr), NLM_F_CREATE);

/* Copy own header into newly reserved payload section */
memcpy(nlmsg_data(hdr), &hdr, sizeof(hdr));

/*
 * The message will now look like this:
 *     +-------------------+- - -+----------------+- - -+
 *     |  struct nlmsghdr  | Pad |  struct myhdr  | Pad |
 *     +-------------------+-----+----------------+- - -+
 * nlh -^                        /                \
 *                              +--------+---------+
 *                              |  foo1  |  foo2   |
 *                              +--------+---------+
 */
