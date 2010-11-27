#include <netlink/msg.h>
#include <netlink/attr.h>

void construct_attrs(struct nl_msg *msg)
{
	NLA_PUT_STRING(msg, MY_ATTR_FOO1, "some text");
	NLA_PUT_U32(msg, MY_ATTR_FOO1, 0x1010);
	NLA_PUT_FLAG(msg, MY_ATTR_FOO3, 1);

	return 0;

nla_put_failure:
	/* NLA_PUT* macros jump here in case of an error */
	return -EMSGSIZE;
}
