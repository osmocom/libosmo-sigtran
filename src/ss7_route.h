#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Routes
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_ss7_route_table;
struct osmo_ss7_linkset;
struct osmo_ss7_as;

#define OSMO_SS7_ROUTE_PRIO_DEFAULT 5

struct osmo_ss7_route {
	/*! member in \ref osmo_ss7_route_table.routes */
	struct llist_head list;
	/*! \ref osmo_ss7_route_table to which we belong */
	struct osmo_ss7_route_table *rtable;

	struct {
		/*! pointer to linkset (destination) of route */
		struct osmo_ss7_linkset *linkset;
		/*! pointer to Application Server */
		struct osmo_ss7_as *as;
	} dest;

	struct {
		/* FIXME: presence? */
		uint32_t pc;
		uint32_t mask;
		/*! human-specified linkset name */
		char *linkset_name;
		/*! lower priority is higher */
		uint32_t priority;
		uint8_t qos_class;
	} cfg;
};

struct osmo_ss7_route *
ss7_route_alloc(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask);
struct osmo_ss7_route *
ss7_route_create(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
			uint32_t mask, const char *linkset_name);
void ss7_route_destroy(struct osmo_ss7_route *rt);

struct osmo_ss7_route *
ss7_route_find_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc);
struct osmo_ss7_route *
ss7_route_find_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
			     uint32_t mask);

int ss7_route_set_linkset(struct osmo_ss7_route *rt, const char *linkset_name);
int ss7_route_insert(struct osmo_ss7_route *rt);

bool ss7_route_is_available(const struct osmo_ss7_route *rt);
