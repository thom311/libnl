if (attrs[ATTR_OPTS]) {
	struct nlattr *nested[NESTED_MAX+1];
	struct nla_policy nested_policy[] = {
		[NESTED_FOO] = { .type = NLA_U32 },
	};

	if (nla_parse_nested(nested, NESTED_MAX, attrs[ATTR_OPTS], nested_policy) < 0)
		/* error */
	
	if (nested[NESTED_FOO])
		uint32_t val = nla_get_u32(nested[NESTED_FOO]);
}
