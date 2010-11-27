#include <netlink/handlers.h>

/* Allocate a callback set and initialize it to the verbose default set */
struct nl_cb *cb = nl_cb_alloc(NL_CB_VERBOSE);

/* Modify the set to call my_func() for all valid messages */
nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, my_func, NULL);

/*
 * Set the error message handler to the verbose default implementation
 * and direct it to print all errors to the given file descriptor.
 */
FILE *file = fopen(...);
nl_cb_err(cb, NL_CB_VERBOSE, NULL, file);
