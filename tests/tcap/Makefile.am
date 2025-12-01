AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_srcdir)/src
AM_CFLAGS = -Wall \
	$(LIBOSMOCORE_CFLAGS) $(LIBOSMOVTY_CFLAGS) $(LIBOSMONETIF_CFLAGS) $(LIBOSMOASN1TCAP_CFLAGS) $(LIBSCTP_CFLAGS)

AM_LDFLAGS = -no-install

LDADD = $(top_builddir)/src/.libs/libosmo-sigtran.a \
	$(LIBOSMOCORE_LIBS) $(LIBOSMOGSM_LIBS) $(LIBOSMOVTY_LIBS) $(LIBOSMONETIF_LIBS) $(LIBOSMOASN1TCAP_LIBS) $(LIBSCTP_LIBS)

check_PROGRAMS = \
	tcap_transaction_tracking_test \
	$(NULL)

EXTRA_DIST = \
	tcap_transaction_tracking_test.ok \
	$(NULL)


tcap_transaction_tracking_test_SOURCES = \
	tcap_transaction_tracking_test.c \
	$(NULL)
