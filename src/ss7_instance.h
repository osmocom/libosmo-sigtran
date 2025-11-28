#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/timer_compat.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/sigtran/protocol/mtp.h>

/***********************************************************************
 * SS7 Instances
 ***********************************************************************/

struct osmo_ss7_user;
struct osmo_ss7_route_table;
struct osmo_ss7_route_label;
struct osmo_sccp_instance;

enum ss7_instance_xua_timer {
	/* 0 kept unused on purpose since it's handled specially by osmo_fsm */
	SS7_INST_XUA_T8 = 1, /* Q.704 T8 */
	/* This must remain the last item: */
	SS7_INST_XUA_TIMERS_LEN
};
extern const struct value_string ss7_instance_xua_timer_names[];
extern const struct osmo_tdef ss7_instance_xua_timer_defaults[SS7_INST_XUA_TIMERS_LEN];
/* According to SUA RFC3868 Section 8, M3UA RFC4666 Section 4.3.4.1 */
#define SS7_INST_XUA_DEFAULT_T8_MSEC	1000

enum ss7_instance_ctr {
	SS7_INST_CTR_PKT_RX_TOTAL,
	SS7_INST_CTR_PKT_RX_UNKNOWN,
	SS7_INST_CTR_PKT_RX_NI_MISMATCH,
	SS7_INST_CTR_PKT_TX_TOTAL,
};

struct osmo_ss7_pc_fmt {
	char delimiter;
	uint8_t component_len[3];
};

struct osmo_ss7_instance {
	/*! member of global list of instances */
	struct llist_head list;
	/*! list of \ref osmo_ss7_linkset */
	struct llist_head linksets;
	/*! list of \ref osmo_ss7_as */
	struct llist_head as_list;
	/*! list of \ref osmo_ss7_asp */
	struct llist_head asp_list;
	/*! list of \ref osmo_ss7_route_table */
	struct llist_head rtable_list;
	/*! list of \ref osmo_xua_servers */
	struct llist_head xua_servers;
	/* array for faster lookup of user (indexed by service
	 * indicator) */
	struct osmo_ss7_user *user[16];

	struct osmo_ss7_route_table *rtable_system;

	struct osmo_sccp_instance *sccp;

	struct rate_ctr_group *ctrg;

	/* Q.704 Figure 44 and section 13.2: List to store remote PCs with T8 started */
	struct {
		/* list of struct t8_inaccessible_sp_entry, sorted by entry->ts_started */
		struct llist_head list;
		struct osmo_timer_list timer;
	} t8_inaccessible_sp;

	struct {
		uint32_t id;
		char *name;
		char *description;
		uint32_t primary_pc;
		/* capability PCs */
		enum mtp_network_indicator network_indicator;
		struct osmo_ss7_pc_fmt pc_fmt;
		bool permit_dyn_rkm_alloc;
		struct llist_head sccp_address_book;
		uint32_t secondary_pc;
		/* How many bits from ITU OPC/DPC field (starting from least-significant-bit)
		 * to skip for routing decisions (always takes 6 bits).
		 * range 0-8, defaults to 0, which means take least significant 6 bits. */
		uint8_t opc_shift;
		uint8_t dpc_shift;
		/* How many bits from ITU SLS field (starting from least-significant-bit)
		 * to skip for routing decisions.
		 * range 0-3, defaults to 0, which means take all 4 bits. */
		uint8_t sls_shift;

		/* T_defs defined at instance level: */
		struct osmo_tdef *T_defs_xua;
	} cfg;
};

struct osmo_ss7_instance *
ss7_instance_alloc(void *ctx, uint32_t id);

uint32_t ss7_find_free_l_rk_id(struct osmo_ss7_instance *inst);
struct osmo_ss7_route *
ss7_instance_lookup_route(struct osmo_ss7_instance *inst, const struct osmo_ss7_route_label *rtlabel);

#define _LOGSS7(inst, subsys, level, fmt, args ...) \
	LOGP(subsys, level, "%u: " fmt, inst ? (inst)->cfg.id : 0, ## args)
#define LOGSS7(inst, level, fmt, args ...) \
	_LOGSS7(inst, DLSS7, level, fmt, ## args)


/***********************************************************************
 * ITUQ.704 13.2.2: Timer T8 concerning one SP
 ***********************************************************************/
struct t8_inaccessible_sp_entry {
	struct llist_head entry; /* item in (struct osmo_ss7_instance)->t8_inaccessible_sp.list */
	uint32_t dpc; /* SP inaccessible */
	struct timespec ts_started; /* Timestamp T8 was started for this SP */
};
bool ss7_instance_t8_inaccessible_sp_running(const struct osmo_ss7_instance *inst, uint32_t dpc);
void ss7_instance_t8_inaccessible_sp_start(struct osmo_ss7_instance *inst, uint32_t dpc);
