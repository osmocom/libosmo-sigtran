#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Linksets
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_ss7_link;

struct osmo_ss7_linkset {
	struct llist_head list;
	/*! \ref osmo_ss7_instance to which we belong */
	struct osmo_ss7_instance *inst;
	/*! array of \ref osmo_ss7_link */
	struct osmo_ss7_link *links[16];

	struct {
		char *name;
		char *description;
		uint32_t adjacent_pc;
		uint32_t local_pc;
	} cfg;
};

void ss7_linkset_destroy(struct osmo_ss7_linkset *lset);
struct osmo_ss7_linkset *
ss7_linkset_find_by_name(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_linkset *
ss7_linkset_find_or_create(struct osmo_ss7_instance *inst, const char *name, uint32_t pc);
