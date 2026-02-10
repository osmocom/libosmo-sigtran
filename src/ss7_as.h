#pragma once

#include "config.h"

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/tdef.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_internal.h"
#include "xua_msg.h"

/***********************************************************************
 * SS7 Application Server
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_ss7_asp;
struct osmo_mtp_transfer_param;
struct xua_msg;

enum osmo_ss7_as_patch_sccp_mode {
	OSMO_SS7_PATCH_NONE,	/* no patching of SCCP */
	OSMO_SS7_PATCH_BOTH,	/* patch both OPC and DPC into SCCP addresses */
};

enum ss7_as_ctr {
	SS7_AS_CTR_RX_MSU_DISCARD,
	SS7_AS_CTR_RX_MSU_TOTAL,
	SS7_AS_CTR_RX_MSU_SLS_0,
	SS7_AS_CTR_RX_MSU_SLS_1,
	SS7_AS_CTR_RX_MSU_SLS_2,
	SS7_AS_CTR_RX_MSU_SLS_3,
	SS7_AS_CTR_RX_MSU_SLS_4,
	SS7_AS_CTR_RX_MSU_SLS_5,
	SS7_AS_CTR_RX_MSU_SLS_6,
	SS7_AS_CTR_RX_MSU_SLS_7,
	SS7_AS_CTR_RX_MSU_SLS_8,
	SS7_AS_CTR_RX_MSU_SLS_9,
	SS7_AS_CTR_RX_MSU_SLS_10,
	SS7_AS_CTR_RX_MSU_SLS_11,
	SS7_AS_CTR_RX_MSU_SLS_12,
	SS7_AS_CTR_RX_MSU_SLS_13,
	SS7_AS_CTR_RX_MSU_SLS_14,
	SS7_AS_CTR_RX_MSU_SLS_15,
	SS7_AS_CTR_TX_MSU_TOTAL,
	SS7_AS_CTR_TX_MSU_SLS_0,
	SS7_AS_CTR_TX_MSU_SLS_1,
	SS7_AS_CTR_TX_MSU_SLS_2,
	SS7_AS_CTR_TX_MSU_SLS_3,
	SS7_AS_CTR_TX_MSU_SLS_4,
	SS7_AS_CTR_TX_MSU_SLS_5,
	SS7_AS_CTR_TX_MSU_SLS_6,
	SS7_AS_CTR_TX_MSU_SLS_7,
	SS7_AS_CTR_TX_MSU_SLS_8,
	SS7_AS_CTR_TX_MSU_SLS_9,
	SS7_AS_CTR_TX_MSU_SLS_10,
	SS7_AS_CTR_TX_MSU_SLS_11,
	SS7_AS_CTR_TX_MSU_SLS_12,
	SS7_AS_CTR_TX_MSU_SLS_13,
	SS7_AS_CTR_TX_MSU_SLS_14,
	SS7_AS_CTR_TX_MSU_SLS_15,
#ifdef WITH_TCAP_LOADSHARING
	SS7_AS_CTR_RX_TCAP_DECODED,
	SS7_AS_CTR_RX_TCAP_FAILED,
	SS7_AS_CTR_TCAP_ASP_SELECTED,
	SS7_AS_CTR_TCAP_ASP_FALLBACK,
	SS7_AS_CTR_TCAP_ASP_FAILED,
#endif /* WITH_TCAP_LOADSHARING */
};

#define NUM_AS_EXT_SLS 128
typedef uint8_t as_ext_sls_t; /* range: 0-127, 7 bit */
struct osmo_ss7_as_esls_entry {
	/* ITU Q.704 4.2.1: "normal signallink link" */
	struct osmo_ss7_asp *normal_asp;
	/* ITU Q.704 4.2.1: "alternative signallink link" */
	struct osmo_ss7_asp *alt_asp;
};

struct ss7_as_asp_assoc {
	/* Entry in (struct osmo_ss7_as*)->assoc_asp_list */
	struct llist_head as_entry;
	struct osmo_ss7_as *as; /* backpointer */
	struct osmo_ss7_asp *asp; /* backpointer */
};

struct osmo_ss7_as {
	/*! entry in 'ref osmo_ss7_instance.as_list */
	struct llist_head list;
	struct osmo_ss7_instance *inst;

	/*! AS FSM */
	struct osmo_fsm_inst *fi;

	/*! Were we dynamically allocated by RKM? */
	bool rkm_dyn_allocated;

	/*! Were we allocated by "simple client" support? */
	bool simple_client_allocated;

	/*! Rate Counter Group */
	struct rate_ctr_group *ctrg;

	/* ASP loadshare: */
	struct osmo_ss7_as_esls_entry aesls_table[NUM_AS_EXT_SLS];

#ifdef WITH_TCAP_LOADSHARING
	struct {
		/* optimisation: true if tid_ranges contains PCs (not only wildcards) */
		bool contains_pc;
		/* optimisation: true if tid_ranges contains SSNs (not only wildcards (0))  */
		bool contains_ssn;
		DECLARE_HASHTABLE(tid_ranges, 10);
		/* gargabe collector timer */
		struct osmo_timer_list gc_timer;
		/* TODO: the hash tables size might not be optimal */
		DECLARE_HASHTABLE(trans_track_own, 10);
		DECLARE_HASHTABLE(trans_track_peer, 10);
	} tcap;
#endif /* WITH_TCAP_LOADSHARING */

	/* used for load-sharing traffic mode (round robin implementation) */
	struct ss7_as_asp_assoc *last_asp_idx_assigned;
	struct ss7_as_asp_assoc *last_asp_idx_sent;

	struct llist_head assoc_asp_list; /* list of struct ss7_as_asp_assoc */
	unsigned int num_assoc_asps; /* amount of ss7_as_asp_assoc/ss7_asp in assoc_asp_list */

	struct {
		char *name;
		char *description;
		enum osmo_ss7_asp_protocol proto;
		struct osmo_ss7_routing_key routing_key;
		enum osmo_ss7_as_traffic_mode mode;
		/* traffic mode was configured by VTY / config file */
		bool mode_set_by_vty;
		/* traffic mode was configured by RKM (routing key management) or first ASPAC */
		bool mode_set_by_peer;
		uint32_t recovery_timeout_msec;
		uint8_t qos_class;
		struct {
			bool opc_enabled;
			bool dpc_enabled;
			uint32_t opc;
			uint32_t dpc;
			enum osmo_ss7_as_patch_sccp_mode sccp_mode;
		} pc_override;

		struct {
			/* How many bits from ITU SLS field (starting from least-significant-bit)
			* to skip for routing decisions.
			* range 0-3, defaults to 0, which means take all 4 bits. */
			uint8_t sls_shift;
			/* Whether to generate a extended-SLS with OPC information, see opc_shift below. */
			bool opc_sls;
			/* How many bits from ITU OPC field (starting from least-significant-bit)
			* to skip for routing decisions (always takes 12 bits).
			* range 0-2, defaults to 0, which means take least significant 12 bits. */
			uint8_t opc_shift;
#ifdef WITH_TCAP_LOADSHARING
			/* Should we do load-sharing based on tcap ids? */
			struct {
				bool enabled;
				unsigned int timeout_s;
				struct ss7_as_asp_assoc *last_asp_idx_sent;
			} tcap;
#endif /* WITH_TCAP_LOADSHARING */
		} loadshare;
	} cfg;
};
struct osmo_ss7_as *ss7_as_alloc(struct osmo_ss7_instance *inst, const char *name,
				 enum osmo_ss7_asp_protocol proto);
struct osmo_ss7_asp *ss7_as_select_asp(struct osmo_ss7_as *as, const struct xua_msg *xua);

int ss7_as_add_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp);
int ss7_as_del_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp);
int ss7_as_get_local_role(const struct osmo_ss7_as *as);
void ss7_as_loadshare_binding_table_reset(struct osmo_ss7_as *as);

void ss7_as_del_asp_update_llist_round_robin(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp, struct ss7_as_asp_assoc **state);
#define ss7_as_asp_assoc_llist_round_robin(as, state) \
	ss7_llist_round_robin(&(as)->assoc_asp_list, (void **)state, struct ss7_as_asp_assoc, as_entry)

#define LOGPAS(as, subsys, level, fmt, args ...) \
	_LOGSS7((as)->inst, subsys, level, "AS(%s) " fmt, (as)->cfg.name, ## args)
