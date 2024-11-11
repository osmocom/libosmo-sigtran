#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Routing Tables
 ***********************************************************************/

struct osmo_ss7_instance;

struct osmo_ss7_route_table {
	/*! member in list of routing tables */
	struct llist_head list;
	/*! \ref osmo_ss7_instance to which we belong */
	struct osmo_ss7_instance *inst;
	/*! list of \ref osmo_ss7_route */
	struct llist_head routes;

	struct {
		char *name;
		char *description;
	} cfg;
};

struct osmo_ss7_route_table *
ss7_route_table_find(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_route_table *
ss7_route_table_find_or_create(struct osmo_ss7_instance *inst, const char *name);
void ss7_route_table_destroy(struct osmo_ss7_route_table *rtbl);

struct osmo_ss7_route *
ss7_route_table_find_route_by_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc);
struct osmo_ss7_route *
ss7_route_table_find_route_by_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
			uint32_t mask);

void ss7_route_table_del_routes_by_as(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_as *as);
void ss7_route_table_del_routes_by_linkset(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_linkset *lset);
