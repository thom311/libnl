include/nl-priv-dynamic-route
=============================

libnl-route-3 wrongly exposes some symbols that are not part of public headers.
They are used by other internal code.

These are the symbols.

This header can be used by internal code, that dynamically links with libnl-route-3.
But best we reduce the use of such hidden API, so avoid it.
