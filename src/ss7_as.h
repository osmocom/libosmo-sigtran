#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/tdef.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_internal.h"

/***********************************************************************
 * SS7 Application Server
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_ss7_asp;
struct osmo_mtp_transfer_param;

enum osmo_ss7_as_patch_sccp_mode {
	OSMO_SS7_PATCH_NONE,	/* no patching of SCCP */
	OSMO_SS7_PATCH_BOTH,	/* patch both OPC and DPC into SCCP addresses */
};

enum ss7_as_ctr {
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
};

#define NUM_AS_EXT_SLS 128
typedef uint8_t as_ext_sls_t; /* range: 0-127, 7 bit */
struct osmo_ss7_as_esls_entry {
	/* ITU Q.704 4.2.1: "normal signallink link" */
	struct osmo_ss7_asp *normal_asp;
	/* ITU Q.704 4.2.1: "alternative signallink link" */
	struct osmo_ss7_asp *alt_asp;
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
			uint32_t dpc;
			enum osmo_ss7_as_patch_sccp_mode sccp_mode;
		} pc_override;

		struct osmo_ss7_asp *asps[16];
		/* used for load-sharing traffic mode (round robin implementation) */
		uint8_t last_asp_idx_assigned;
		uint8_t last_asp_idx_sent;

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
		} loadshare;
	} cfg;
};

struct osmo_ss7_asp *ss7_as_select_asp(struct osmo_ss7_as *as, const struct osmo_mtp_transfer_param *mtp);

unsigned int osmo_ss7_as_count_asp(const struct osmo_ss7_as *as);
int ss7_as_add_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp);

#define LOGPAS(as, subsys, level, fmt, args ...) \
	_LOGSS7((as)->inst, subsys, level, "AS(%s) " fmt, (as)->cfg.name, ## args)
