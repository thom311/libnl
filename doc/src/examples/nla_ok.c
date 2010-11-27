#include <netlink/msg.h>
#include <netlink/attr.h>

struct nlattr *hdr = nlmsg_attrdata(msg, 0);
int remaining = nlmsg_attrlen(msg, 0);

while (nla_ok(hdr, remaining)) {
	/* parse attribute here */
	hdr = nla_next(hdr, &remaining);
};
