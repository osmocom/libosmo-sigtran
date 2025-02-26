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

enum osmo_ss7_as_patch_sccp_mode {
	OSMO_SS7_PATCH_NONE,	/* no patching of SCCP */
	OSMO_SS7_PATCH_BOTH,	/* patch both OPC and DPC into SCCP addresses */
};

enum ss7_as_ctr {
	SS7_AS_CTR_RX_MSU_TOTAL,
	SS7_AS_CTR_TX_MSU_TOTAL,
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
		uint8_t last_asp_idx_sent; /* used for load-sharing traffic mode (round robin implementation) */
	} cfg;
};

unsigned int osmo_ss7_as_count_asp(const struct osmo_ss7_as *as);

#define LOGPAS(as, subsys, level, fmt, args ...) \
	_LOGSS7((as)->inst, subsys, level, "as-%s: " fmt, (as)->cfg.name, ## args)
