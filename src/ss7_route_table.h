#pragma once

#include <stdint.h>
#include <unistd.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Routing Tables
 ***********************************************************************/

struct osmo_ss7_instance;

struct osmo_ss7_route_label {
	uint32_t opc;
	uint32_t dpc;
	uint8_t sls;
};
char *ss7_route_label_to_str(char *buf, size_t buf_len, const struct osmo_ss7_instance *inst, const struct osmo_ss7_route_label *rtlb);

struct osmo_ss7_route_table {
	/*! member in list of routing tables */
	struct llist_head list;
	/*! \ref osmo_ss7_instance to which we belong */
	struct osmo_ss7_instance *inst;
	/*! list of \ref osmo_ss7_combined_linksets*/
	struct llist_head combined_linksets;

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
ss7_route_table_find_route_by_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
			uint32_t mask);
struct osmo_ss7_route *
ss7_route_table_lookup_route(struct osmo_ss7_route_table *rtbl, const struct osmo_ss7_route_label *rtlabel);

struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset(struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask, uint32_t prio);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_or_create_combined_linkset(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask, uint32_t prio);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset_by_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset_by_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset(struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask, uint32_t prio);

void ss7_route_table_del_routes_by_as(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_as *as);
void ss7_route_table_del_routes_by_linkset(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_linkset *lset);
