#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Combined Linkset
 * Set of routes with same destination and priority.
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_ss7_link;

struct osmo_ss7_combined_linkset {
	/*! member in \ref osmo_ss7_route_table.combined_linksets */
	struct llist_head list;

	/*! \ref osmo_ss7_route_table to which we belong */
	struct osmo_ss7_route_table *rtable;

	/*! list of \ref osmo_ss7_route */
	struct llist_head routes;
	unsigned int num_routes;

	struct {
		uint32_t pc;
		uint32_t mask;
		/*! lower priority is higher */
		uint32_t priority;
	} cfg;
};

struct osmo_ss7_combined_linkset *
ss7_combined_linkset_alloc(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask, uint32_t prio);
void
ss7_combined_linkset_free(struct osmo_ss7_combined_linkset *clset);
struct osmo_ss7_linkset *
ss7_combined_linkset_find_or_create(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask, uint32_t prio);

void
ss7_combined_linkset_add_route(struct osmo_ss7_combined_linkset *clset, struct osmo_ss7_route *rt);
void
ss7_combined_linkset_del_route(struct osmo_ss7_route *rt);
