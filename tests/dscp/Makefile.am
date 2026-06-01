AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include
AM_CFLAGS=-Wall $(LIBOSMONETIF_CFLAGS) $(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS)

AM_LDFLAGS = -no-install
LDADD = $(top_builddir)/src/.libs/libosmo-sigtran.a \
	$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMONETIF_LIBS) $(LIBSCTP_LIBS)

if BUILD_WITH_TCAP_LOADSHARING
LDADD += $(LIBOSMOASN1TCAP_LIBS)
endif

EXTRA_DIST = dscp_test.ok dscp_test.py

check_PROGRAMS = get_tos_diag

get_tos_diag_SOURCES = get_tos_diag.c


