#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/tdef.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_asp_peer.h"
#include "ss7_internal.h"

/***********************************************************************
 * SS7 Application Server Processes
 ***********************************************************************/

struct osmo_ss7_instance;
struct osmo_xua_layer_manager;

enum ss7_asp_ctr {
	SS7_ASP_CTR_PKT_RX_TOTAL,
	SS7_ASP_CTR_PKT_RX_UNKNOWN,
	SS7_ASP_CTR_PKT_TX_TOTAL,
};

struct osmo_ss7_asp {
	/*! entry in \ref osmo_ss7_instance.asp_list */
	struct llist_head list;
	struct osmo_ss7_instance *inst;

	/*! ASP FSM */
	struct osmo_fsm_inst *fi;

	/*! \ref osmo_xua_server over which we were established */
	struct osmo_xua_server *xua_server;
	struct llist_head siblings;

	/*! osmo_stream / libosmo-netif handles */
	struct osmo_stream_cli *client;
	struct osmo_stream_srv *server;
	/*! pre-formatted human readable local/remote socket name */
	char *sock_name;

	/* ASP Identifier for ASP-UP + NTFY */
	uint32_t asp_id;
	bool asp_id_present;

	/* Layer Manager to which we talk */
	const struct osmo_xua_layer_manager *lm;
	void *lm_priv;

	/*! Were we dynamically allocated */
	bool dyn_allocated;

	/*! Were we allocated by "simple client" support? */
	bool simple_client_allocated;

	/*! Rate Counter Group */
	struct rate_ctr_group *ctrg;

	/*! Pending message for non-blocking IPA read */
	struct msgb *pending_msg;

	struct {
		char *name;
		char *description;
		enum osmo_ss7_asp_protocol proto;
		enum osmo_ss7_asp_admin_state adm_state;
		bool is_server;
		enum osmo_ss7_asp_role role;
		bool role_set_by_vty;
		bool trans_role_set_by_vty;

		struct osmo_ss7_asp_peer local;
		struct osmo_ss7_asp_peer remote;
		uint8_t qos_class;
		uint32_t quirks;

		/* T_defs used by the default_lm: */
		struct osmo_tdef *T_defs_lm;

		struct {
			bool num_ostreams_present;
			bool max_instreams_present;
			bool max_attempts_present;
			bool max_init_timeo_present;
			uint16_t num_ostreams_value;
			uint16_t max_instreams_value;
			uint16_t max_attempts_value;
			uint16_t max_init_timeo_value; /* ms */
		} sctp_init;

		/*! The underlaying transport protocol (one of IPPROTO_*) */
		int trans_proto;
	} cfg;
};

struct osmo_ss7_asp *ss7_asp_alloc(struct osmo_ss7_instance *inst, const char *name,
				   uint16_t remote_port, uint16_t local_port,
				   int trans_proto, enum osmo_ss7_asp_protocol proto);
bool ss7_asp_set_default_peer_hosts(struct osmo_ss7_asp *asp);
bool ss7_asp_is_started(const struct osmo_ss7_asp *asp);
int ss7_asp_get_fd(const struct osmo_ss7_asp *asp);

int ss7_asp_apply_peer_primary_address(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_primary_address(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_new_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx);
int ss7_asp_apply_drop_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx);

#define LOGPASP(asp, subsys, level, fmt, args ...) \
	_LOGSS7((asp)->inst, subsys, level, "asp-%s: " fmt, (asp)->cfg.name, ## args)
