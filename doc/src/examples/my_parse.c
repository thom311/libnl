#include <netlink/msg.h>

void my_parse(void *stream, int length)
{
	struct nlmsghdr *hdr = stream;

	while (nlmsg_ok(hdr, length)) {
		// Parse message here
		hdr = nlmsg_next(hdr, &length);
	}
}
