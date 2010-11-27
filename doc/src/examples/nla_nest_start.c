int put_opts(struct nl_msg *msg)
{
	struct nlattr *opts;

	if (!(opts = nla_nest_start(msg, ATTR_OPTS)))
		goto nla_put_failure;

	NLA_PUT_U32(msg, NESTED_FOO, 123);
	NLA_PUT_STRING(msg, NESTED_BAR, "some text");

	nla_nest_end(msg, opts);
	return 0;

nla_put_failure:
	return -EMSGSIZE;
}
