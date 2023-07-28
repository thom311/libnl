include/base
============

This directory contains libnl-independent helper.

It's an internal "library" of helpers, that purely depend
on C and external dependencies.

Currently, it's also header-only, so there is no need to link
with anything special.

This can be used freely by all our internal code, but it's private API,
so it cannot be used in public headers.
