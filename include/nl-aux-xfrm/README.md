include/nl-aux-xfrm
===================

This contains private/internal helpers that depend on the public libnl-3 (core)
and libnl-xfrm-3.

Itself, it must only rely on C, include/base/ and public headers of libnl-3 (core)
and libnl-xfrm-3.

They can be used by all internal code that uses the public API of both libnl-3 (core)
and libnl-xfrm-3.

It can also be used by lib/xfrm itself (that is, the implementation of
libnl-xfrm-3).

It must not be used in public headers, it's internal only.

Currently this is header-only, it does not require any additional linking.
