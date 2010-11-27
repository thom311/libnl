#include <netlink/attr.h>

struct nalttr *nla;
int rem;

nla_for_each_attr(nla, attrstream, streamlen, rem) {
	/* validate & parse attribute */
}

if (rem > 0)
	/* unparsed attribute data */
