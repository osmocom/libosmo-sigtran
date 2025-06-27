#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Routes
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_ss7_route_table;
struct osmo_ss7_linkset;
struct osmo_ss7_as;

#define OSMO_SS7_ROUTE_PRIO_DEFAULT 5

/* ITU Q.704 3.4 Status of signalling routes */
enum osmo_ss7_route_status {
	OSMO_SS7_ROUTE_STATUS_UNAVAILABLE,
	OSMO_SS7_ROUTE_STATUS_AVAILABLE,
	OSMO_SS7_ROUTE_STATUS_RESTRICTED,
};
extern const struct value_string ss7_route_status_names[];
static inline const char *ss7_route_status_name(enum osmo_ss7_route_status val)
{ return get_value_string(ss7_route_status_names, val); }

struct osmo_ss7_route {
	/*! member in \ref osmo_ss7_combined_linkset.routes */
	struct llist_head list;
	/*! \ref osmo_ss7_route_table to which we belong */
	struct osmo_ss7_route_table *rtable;
	/* Combined linkset this route is part of */
	struct osmo_ss7_combined_linkset *clset;

	enum osmo_ss7_route_status status;

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
		bool dyn_allocated;
	} cfg;
};

struct osmo_ss7_route *
ss7_route_alloc(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask, bool dynamic);
struct osmo_ss7_route *
ss7_route_create(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
		 uint32_t mask, bool dynamic, const char *linkset_name);
void ss7_route_destroy(struct osmo_ss7_route *rt);

struct osmo_ss7_route *
ss7_route_find_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc);
struct osmo_ss7_route *
ss7_route_find_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
			     uint32_t mask);

int ss7_route_set_linkset(struct osmo_ss7_route *rt, const char *linkset_name);
int ss7_route_insert(struct osmo_ss7_route *rt);

bool ss7_route_dest_is_available(const struct osmo_ss7_route *rt);
bool ss7_route_is_available(const struct osmo_ss7_route *rt);

bool ss7_route_is_fully_qualified(const struct osmo_ss7_route *rt);
static inline bool ss7_route_is_summary(const struct osmo_ss7_route *rt)
{
	return !ss7_route_is_fully_qualified(rt);
}

void ss7_route_update_route_status(struct osmo_ss7_route *rt, enum osmo_ss7_route_status status);

#define LOGPRT(rt, subsys, level, fmt, args ...) do { \
	char _pc_str[MAX_PC_STR_LEN]; \
	char _mask_str[MAX_PC_STR_LEN]; \
	_LOGSS7((rt)->rtable->inst, subsys, level, \
		"RT(dpc=%u=%s,mask=0x%x=%s,prio=%u,via=%s,st=%s) " fmt, \
		(rt)->cfg.pc, osmo_ss7_pointcode_print_buf(_pc_str, MAX_PC_STR_LEN, (rt)->rtable->inst, (rt)->cfg.pc), \
		(rt)->cfg.mask, osmo_ss7_pointcode_print_buf(_mask_str, MAX_PC_STR_LEN, (rt)->rtable->inst, (rt)->cfg.mask), \
		(rt)->cfg.priority, \
		(rt)->cfg.linkset_name ? (rt)->cfg.linkset_name : "", \
		ss7_route_status_name((rt)->status), \
		## args); \
	} while (0)
