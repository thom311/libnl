struct my_attr_struct {
	uint32_t a;
	uint32_t b;
};

int my_put(struct nl_msg *msg)
{
	struct my_attr_struct obj = {
		.a = 10,
		.b = 20,
	};

	return nla_put(msg, ATTR_MY_STRUCT, sizeof(obj), &obj);
}
