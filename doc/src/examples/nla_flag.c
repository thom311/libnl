/* nla_put_flag() appends a zero sized attribute to the message. */
nla_put_flag(msg, ATTR_FLAG);


/* There is no need for a receival function, the presence is the value. */
if (attrs[ATTR_FLAG])
	/* flag is present */
