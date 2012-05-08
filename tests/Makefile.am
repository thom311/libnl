# -*- Makefile -*-

AM_CPPFLAGS  = -Wall -I${top_srcdir}/include -I${top_builddir}/include -D_GNU_SOURCE -DSYSCONFDIR=\"$(sysconfdir)/libnl\"

LDADD = \
	${top_builddir}/src/lib/libnl-cli-3.la \
	${top_builddir}/lib/libnl-3.la \
	${top_builddir}/lib/libnl-nf-3.la \
	${top_builddir}/lib/libnl-genl-3.la \
	${top_builddir}/lib/libnl-route-3.la

check_PROGRAMS = \
	test-cache-mngr \
	test-create-bond \
	test-create-vlan \
	test-delete-link \
	test-genl \
	test-nf-cache-mngr \
	test-socket-creation \
	test-complex-HTB-with-hash-filters

# Eventually add these to TESTS once converted to be real
# test programs
# TESTS = $(check_PROGRAMS)

test_cache_mngr_SOURCES = test-cache-mngr.c
test_create_bond_SOURCES = test-create-bond.c
test_create_vlan_SOURCES = test-create-vlan.c
test_delete_link_SOURCES = test-delete-link.c
test_genl_SOURCES = test-genl.c
test_nf_cache_mngr_SOURCES = test-nf-cache-mngr.c
test_socket_creation_SOURCES = test-socket-creation.c
test_complex_HTB_with_hash_filters_SOURCES = test-complex-HTB-with-hash-filters.c
