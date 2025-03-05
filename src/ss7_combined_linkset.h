#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Combined Linkset
 * Set of routes with same destination and priority.
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_ss7_link;
struct osmo_ss7_route_label;

#define NUM_EXT_SLS 128
typedef uint8_t ext_sls_t; /* range: 0-127, 7 bit */

struct osmo_ss7_esls_entry {
	/* ITU Q.704 4.2.1: "normal link set (combined link set)" */
	struct osmo_ss7_route *normal_rt;
	/* ITU Q.704 4.2.1: "alternative link set (combined link set)" */
	struct osmo_ss7_route *alt_rt;
};

struct osmo_ss7_combined_linkset {
	/*! member in \ref osmo_ss7_route_table.combined_linksets */
	struct llist_head list;

	/*! \ref osmo_ss7_route_table to which we belong */
	struct osmo_ss7_route_table *rtable;
	struct osmo_ss7_esls_entry esls_table[NUM_EXT_SLS];

	/*! list of \ref osmo_ss7_route */
	struct llist_head routes;
	unsigned int num_routes;
	void *last_route_roundrobin_ass;
	void *last_route_roundrobin_tx;

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
struct osmo_ss7_route *
ss7_combined_linkset_lookup_route(struct osmo_ss7_combined_linkset *clset, const struct osmo_ss7_route_label *rtlabel);

#define LOGPCLSET(clset, subsys, level, fmt, args ...) do { \
	char _pc_str[MAX_PC_STR_LEN]; \
	char _mask_str[MAX_PC_STR_LEN]; \
	_LOGSS7((clset)->rtable->inst, subsys, level, \
		"CombinedLinkset(dpc=%u=%s,mask=0x%x=%s,prio=%u) " fmt, \
		(clset)->cfg.pc, osmo_ss7_pointcode_print_buf(_pc_str, MAX_PC_STR_LEN, (clset)->rtable->inst, (clset)->cfg.pc), \
		(clset)->cfg.mask, osmo_ss7_pointcode_print_buf(_mask_str, MAX_PC_STR_LEN, (clset)->rtable->inst, (clset)->cfg.mask), \
		(clset)->cfg.priority, ## args); \
	} while (0)
