include/nl-priv-dynamic-route
=============================

This exposes private API from libnl-route-3. The only purpose is for tests to
be able to access the internals.  This is usable to lib/route itself, and tests
that either statically or dynamically link with libnl-route-3.

The difference between nl-priv-static-route and nl-priv-dynamic-route, is that
the former uses internal ABI, so it is only usable when the test statically
links with lib/route.  On the other hand, nl-priv-dynamic-route also works with
only the public API (that is, dynamically linking with libnl-route-3).
