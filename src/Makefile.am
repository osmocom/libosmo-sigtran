AM_CPPFLAGS = $(all_includes) -I$(top_srcdir)/include -I$(top_builddir)
AM_CFLAGS=-Wall $(LIBOSMOCORE_CFLAGS) $(LIBOSMOGSM_CFLAGS) $(LIBOSMOVTY_CFLAGS) \
		$(LIBOSMONETIF_CFLAGS)

noinst_HEADERS = \
	sccp_connection.h \
	sccp_scoc_fsm.h \
	sccp_instance.h \
	sccp_internal.h \
	sccp_user.h \
	ss7_as.h \
	ss7_asp.h \
	ss7_asp_peer.h \
	ss7_combined_linkset.h \
	ss7_instance.h \
	ss7_internal.h \
	ss7_link.h \
	ss7_linkset.h \
	ss7_route.h \
	ss7_route_table.h \
	ss7_user.h \
	ss7_vty.h \
	ss7_xua_srv.h \
	xua_asp_fsm.h \
	xua_as_fsm.h \
	xua_internal.h \
	xua_msg.h \
	xua_types.h \
	$(NULL)

noinst_LIBRARIES = libxua.a

libxua_a_SOURCES = xua_msg.c
# ensure that the file for the static lib is built with different C
# flags, working around automake complaining that xua_msg.o is built
# both with libtool (below) and without (here)
libxua_a_CPPFLAGS = $(AM_CPPFLAGS) -DDUMMY -UDUMMY

lib_LTLIBRARIES = libosmo-sigtran.la

# This is _NOT_ the library release version, it's an API version.
# Please read Chapter 6 "Library interface versions" of the libtool
# documentation before making any modification
LIBVERSION=11:0:0

libosmo_sigtran_la_SOURCES = \
	ipa.c \
	m3ua.c \
	sccp2sua.c \
	sccp_connection.c \
	sccp_helpers.c \
	sccp_instance.c \
	sccp_lbcs.c \
	sccp_sap.c \
	sccp_sclc.c \
	sccp_scmg.c \
	sccp_scrc.c \
	sccp_scoc.c \
	sccp_scoc_fsm.c \
	sccp_types.c \
	sccp_user.c \
	sccp_vty.c \
	ss7.c \
	ss7_as.c \
	ss7_as_vty.c \
	ss7_asp.c \
	ss7_asp_vty.c \
	ss7_asp_peer.c \
	ss7_combined_linkset.c \
	ss7_hmrt.c \
	ss7_instance.c \
	ss7_link.c \
	ss7_linkset.c \
	ss7_vty.c \
	ss7_xua_srv.c \
	ss7_xua_srv_vty.c \
	ss7_route.c \
	ss7_route_table.c \
	ss7_user.c \
	sua.c \
	xua_asp_fsm.c \
	xua_as_fsm.c \
	xua_default_lm_fsm.c \
	xua_msg.c \
	xua_rkm.c \
	xua_shared.c \
	xua_snm.c \
	$(NULL)

libosmo_sigtran_la_LDFLAGS = -version-info $(LIBVERSION) -no-undefined -export-symbols-regex '^osmo_'
libosmo_sigtran_la_LIBADD = \
	$(LIBOSMONETIF_LIBS) \
	$(LIBOSMOGSM_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMOCORE_LIBS) \
	$(LIBSCTP_LIBS) \
	$(NULL)
