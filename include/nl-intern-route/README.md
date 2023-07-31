include/nl-intern-route
=======================

This contains headers that extend the libnl-route-3 API with internal helpers.
It is only usable to components that statically link with the libnl-route-3
source. That means libnl-route-3 sources itself (lib/libnl-route-3.la)
and the unit tests.
