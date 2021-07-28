#include <netlink/netlink.h>
#include <netlink/cache.h>
#include <netlink/cli/utils.h>
#include <signal.h>

#include <netlink-private/cache-api.h>

#include <linux/netlink.h>

static int quit = 0;

static struct nl_dump_params params = {
	.dp_type = NL_DUMP_LINE,
};


static void change_cb(struct nl_cache *cache, struct nl_object *obj,
		      int action, void *data)
{
	if (action == NL_ACT_NEW)
		printf("NEW ");
	else if (action == NL_ACT_DEL)
		printf("DEL ");
	else if (action == NL_ACT_CHANGE)
		printf("CHANGE ");

	nl_object_dump(obj, &params);
}

static void sigint(int arg)
{
	quit = 1;
}

static void print_usage(FILE* stream, const char *name)
{
	fprintf(stream,
		"Usage: %s [OPTIONS]... <cache name>... \n"
		"\n"
		"OPTIONS\n"
		" -f, --format=TYPE     Output format { brief | details | stats }\n"
		"                       Default: brief\n"
		" -h, --help            Show this help text.\n"
		, name);
}

int main(int argc, char *argv[])
{
	struct nl_cache_mngr *mngr;
	struct nl_cache *cache;
	int err;

	for (;;) {
		static struct option long_opts[] = {
			{ "format", required_argument, 0, 'f' },
			{ "help", 0, 0, 'h' },
			{ 0, 0, 0, 0 }
		};
		int c;

		c = getopt_long(argc, argv, "hf:", long_opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'f':
			params.dp_type = nl_cli_parse_dumptype(optarg);
			break;
		case 'h':
			print_usage(stdout, argv[0]);
			exit(0);
		case '?':
			print_usage(stderr, argv[0]);
			exit(1);
		}
	}

	err = nl_cache_mngr_alloc(NULL, NETLINK_ROUTE, NL_AUTO_PROVIDE, &mngr);
	if (err < 0)
		nl_cli_fatal(err, "Unable to allocate cache manager: %s",
			     nl_geterror(err));

	while (optind < argc) {
		err = nl_cache_mngr_add(mngr, argv[optind], &change_cb, NULL,
					&cache);
		if (err < 0)
			nl_cli_fatal(err, "Unable to add cache %s: %s",
				     argv[optind], nl_geterror(err));
		optind++;
	}

	params.dp_fd = stdout;
	signal(SIGINT, sigint);

	while (!quit) {
		int err = nl_cache_mngr_poll(mngr, 1000);
		if (err < 0 && err != -NLE_INTR)
			nl_cli_fatal(err, "Polling failed: %s", nl_geterror(err));

		nl_cache_mngr_info(mngr, &params);
	}

	nl_cache_mngr_free(mngr);

	return 0;
}
