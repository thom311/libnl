#include "../src/utils.h"

int main(int argc, char *argv[])
{
	struct nl_handle *h;
	int i;

	for (i = 0; i < 1025; i++) {
		h = nl_handle_alloc();
		printf("Created handle with port 0x%x\n",
			nl_socket_get_local_port(h));
	}

	return 0;
}
