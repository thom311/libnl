int parse_message(struct nlmsghdr *hdr)
{
	/*
	 * The policy defines two attributes: a 32 bit integer and a container
	 * for nested attributes.
	 */
	struct nla_policy attr_policy[] = {
		[ATTR_FOO] = { .type = NLA_U32 },
		[ATTR_BAR] = { .type = NLA_NESTED },
	};
	struct nlattr *attrs[ATTR_MAX+1];
	int err;

	/*
	 * The nlmsg_parse() function will make sure that the message contains
	 * enough payload to hold the header (struct my_hdr), validates any
	 * attributes attached to the messages and stores a pointer to each
	 * attribute in the attrs[] array accessable by attribute type.
	 */
	if ((err = nlmsg_parse(hdr, sizeof(struct my_hdr), attrs, ATTR_MAX,
			       attr_policy)) < 0)
		goto errout;

	if (attrs[ATTR_FOO]) {
		/*
		 * It is safe to directly access the attribute payload without
		 * any further checks since nlmsg_parse() enforced the policy.
		 */
		uint32_t foo = nla_get_u32(attrs[ATTR_FOO]);
	}

	if (attrs[ATTR_BAR]) {
		struct *nested[NESTED_MAX+1];

		/*
		 * Attributes nested in a container can be parsed the same way
		 * as top level attributes.
		 */
		err = nla_parse_nested(nested, NESTED_MAX, attrs[ATTR_BAR],
                		       nested_policy);
		if (err < 0)
			goto errout;

		// Process nested attributes here.
	}

	err = 0;
errout:
	return err;
}
