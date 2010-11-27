#include <netlink/msg.h>
#include <netlink/attr.h>

enum {
	MY_ATTR_FOO = 1,
	MY_ATTR_BAR,
	__MY_ATTR_MAX,
};

#define MY_ATTR_MAX (__MY_ATTR_MAX - 1)

static struct nla_policy my_policy[MY_ATTR_MAX+1] = {
	[MY_ATTR_FOO] = { .type = NLA_U32 },
	[MY_ATTR_BAR] = { .type = NLA_STRING,
			  .maxlen = 16 },
};

void parse_msg(struct nlmsghdr *nlh)
{
	struct nlattr *attrs[MY_ATTR_MAX+1];

	if (nlmsg_parse(nlh, 0, attrs, MY_ATTR_MAX, my_policy) < 0)
		/* error */

	if (attrs[MY_ATTR_FOO]) {
		/* MY_ATTR_FOO is present in message */
		printf("value: %u\n", nla_get_u32(attrs[MY_ATTR_FOO]));
	}
}
