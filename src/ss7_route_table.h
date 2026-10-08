#pragma once

#include <stdint.h>
#include <unistd.h>
#include <osmocom/core/linuxlist.h>

/***********************************************************************
 * SS7 Routing Tables
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_mtp_transfer_param;
enum osmo_ss7_route_status;

/* Q.703 3.1.4 Message labelling
 * Q.704 2.2 Routing label
 * Q.704 15.2 Label */
#define OSMO_SS7_RTLABEL_SLS_UNSET 0
struct osmo_ss7_route_label {
	uint32_t opc; /* Q.704 2.2.3 */
	uint32_t dpc; /* Q.704 2.2.3 */
	uint8_t sls;  /* Q.704 2.2.4 */
};
char *ss7_route_label_to_str(char *buf, size_t buf_len, const struct osmo_ss7_instance *inst, const struct osmo_ss7_route_label *rtlb);

/* MTP3 Label: SI + Routing Label + User Part specific label
 * Q.703 3.1.4 Message labelling
 * Q.704 2.1.5, 2.1.6, 2.3.1
 * Q.704 14.1 (Common characteristics of message signal unit formats) */
struct osmo_ss7_route_label_mtp3 {
	struct osmo_ss7_route_label rtlabel;
	uint8_t si; /* Q.704 14.2.1 Service indicator */
#if 0
	union { /* Q.704 14.3 Label (User Part labels) */
		struct { /* si = MTP_SI_SCCP */
			uint32_t ssn;
		} sccp;
	} u;
#endif
};
char *ss7_route_label_mtp3_to_str(char *buf, size_t buf_len,
				  const struct osmo_ss7_instance *inst,
				  const struct osmo_ss7_route_label_mtp3 *rtlb);
void mtp_xfer_param_to_route_label_mtp3(struct osmo_ss7_route_label_mtp3 *rtlb,
					const struct osmo_mtp_transfer_param *param);

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
ss7_route_table_find_route_by_dpc_mask(const struct osmo_ss7_route_table *rtbl, uint32_t dpc,
				       uint32_t mask, bool dynamic);
struct osmo_ss7_route *
ss7_route_table_find_route_by_dpc_mask_as(const struct osmo_ss7_route_table *rtbl, uint32_t dpc,
				       uint32_t mask, const struct osmo_ss7_as *as, bool dynamic);
struct osmo_ss7_route *
ss7_route_table_lookup_route(const struct osmo_ss7_route_table *rtbl,
			     const struct osmo_ss7_route_label_mtp3 *rtlabel);
bool ss7_route_table_dpc_is_accessible(const struct osmo_ss7_route_table *rtbl, uint32_t dpc);
bool ss7_route_table_dpc_is_accessible_via_as(const struct osmo_ss7_route_table *rtbl, uint32_t dpc, const struct osmo_ss7_as *as);
bool ss7_route_table_dpc_is_accessible_skip_as(const struct osmo_ss7_route_table *rtbl, uint32_t dpc, const struct osmo_ss7_as *as);

struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset(const struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask, uint32_t prio);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_or_create_combined_linkset(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask, uint32_t prio);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset_by_dpc(const struct osmo_ss7_route_table *rtbl, uint32_t dpc);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset_by_dpc_mask(const struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask);
struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset(const struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask, uint32_t prio);

void ss7_route_table_update_route_status_by_as(const struct osmo_ss7_route_table *rtbl, enum osmo_ss7_route_status status,
					       const struct osmo_ss7_as *as, uint32_t dpc);
void ss7_route_table_del_routes_by_as(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_as *as);
void ss7_route_table_del_routes_by_linkset(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_linkset *lset);
