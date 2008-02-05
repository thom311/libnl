#include "../src/utils.h"
#include <signal.h>

static int quit = 0;

static void change_cb(struct nl_cache *cache, struct nl_object *obj,
		      int action)
{
	struct nl_dump_params dp = {
		.dp_type = NL_DUMP_BRIEF,
		.dp_fd = stdout,
	};

	if (action == NL_ACT_NEW)
		printf("NEW ");
	else if (action == NL_ACT_DEL)
		printf("DEL ");
	else if (action == NL_ACT_CHANGE)
		printf("CHANGE ");

	nl_object_dump(obj, &dp);
}

static void sigint(int arg)
{
	quit = 1;
}

int main(int argc, char *argv[])
{
	struct nl_cache_mngr *mngr;
	struct nl_cache *lc, *nc, *ac, *rc;
	struct nl_handle *handle;

	signal(SIGINT, sigint);

	nltool_init(argc, argv);

	handle = nltool_alloc_handle();

	mngr = nl_cache_mngr_alloc(handle, NETLINK_ROUTE, NL_AUTO_PROVIDE);
	if (!mngr) {
		nl_perror("nl_cache_mngr_alloc");
		return -1;
	}

	lc = nl_cache_mngr_add(mngr, "route/link", &change_cb);
	if (lc == NULL) {
		nl_perror("nl_cache_mngr_add(route/link");
		return -1;
	}

	nc = nl_cache_mngr_add(mngr, "route/neigh", &change_cb);
	if (nc == NULL) {
		nl_perror("nl_cache_mngr_add(route/neigh");
		return -1;
	}

	ac = nl_cache_mngr_add(mngr, "route/addr", &change_cb);
	if (ac == NULL) {
		nl_perror("nl_cache_mngr_add(route/addr");
		return -1;
	}

	rc = nl_cache_mngr_add(mngr, "route/route", &change_cb);
	if (rc == NULL) {
		nl_perror("nl_cache_mngr_add(route/route");
		return -1;
	}

	while (!quit) {
		int err = nl_cache_mngr_poll(mngr, 5000);
		if (err < 0 && err != -EINTR) {
			nl_perror("nl_cache_mngr_poll()");
			return -1;
		}

	}

	nl_cache_mngr_free(mngr);
	nl_handle_destroy(handle);

	return 0;
}
