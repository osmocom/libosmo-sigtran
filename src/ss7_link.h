#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Linksets
 ***********************************************************************/

struct osmo_ss7_linkset;

enum osmo_ss7_link_adm_state {
	OSMO_SS7_LS_SHUTDOWN,
	OSMO_SS7_LS_INHIBITED,
	OSMO_SS7_LS_ENABLED,
	_NUM_OSMO_SS7_LS
};

struct osmo_ss7_link {
	/*! \ref osmo_ss7_linkset to which we belong */
	struct osmo_ss7_linkset *linkset;
	struct {
		char *name;
		char *description;
		uint32_t id;

		enum osmo_ss7_link_adm_state adm_state;
	} cfg;
};

void ss7_link_destroy(struct osmo_ss7_link *link);
struct osmo_ss7_link *
ss7_link_find_or_create(struct osmo_ss7_linkset *lset, uint32_t id);
