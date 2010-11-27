#include <netlink/msg.h>

struct nlmsghdr *hdr;

nlmsg_for_each(hdr, stream, length) {
	/* do something with message */
}
