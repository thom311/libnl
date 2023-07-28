include/nl-aux-core
====================

This contains private/internal helpers that depend on the public API of libnl-3 (core).

Itself, it must only rely on C, include/base/ and public headers of libnl-3 (core).

They can be used by all internal code that uses the public API of libnl-3.

It can also be used by lib/ itself (that is, the implementation of
libnl-core-3).

It must not be used in public headers, it's internal only.

Currently this is header-only, it does not require any additional linking.
