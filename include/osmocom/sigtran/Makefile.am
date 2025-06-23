version.h: version.h.tpl
	$(AM_V_GEN)$(MKDIR_P) $(dir $@)
	$(AM_V_GEN)sed \
		-e "s/{{VERSION}}/$$(echo '@VERSION@' | cut -d. -f1-3)/g" \
		-e "s/{{VERSION_MAJOR}}/$$(echo '@VERSION@' | cut -d. -f1)/g" \
		-e "s/{{VERSION_MINOR}}/$$(echo '@VERSION@' | cut -d. -f2)/g" \
		-e "s/{{VERSION_PATCH}}/$$(echo '@VERSION@' | cut -d. -f3)/g" \
		$< > $@

EXTRA_DIST = \
	version.h.tpl \
	$(NULL)

sigtran_HEADERS = \
	mtp_sap.h \
	osmo_ss7.h \
	sccp_helpers.h \
	sccp_sap.h \
	sigtran_sap.h \
	xua_msg.h \
	version.h \
	$(NULL)

sigtrandir = $(includedir)/osmocom/sigtran

sigtran_prot_HEADERS = \
	protocol/sua.h \
	protocol/m2ua.h \
	protocol/m3ua.h \
	protocol/mtp.h \
	protocol/sccp_scmg.h \
	$(NULL)

sigtran_protdir = $(includedir)/osmocom/sigtran/protocol
