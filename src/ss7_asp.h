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

enum ss7_asp_xua_timer {
	/* 0 kept unused on purpose since it's handled specially by osmo_fsm */
	SS7_ASP_XUA_T_ACK = 1, /* RFC3868 & RFC4666 timer T(ack) */
	SS7_ASP_XUA_T_BEAT, /* RFC3868 & RFC4666 timer T(beat) */
	/* This must remain the last item: */
	SS7_ASP_XUA_TIMERS_LEN
};
extern const struct value_string ss7_asp_xua_timer_names[];
extern const struct osmo_tdef ss7_asp_xua_timer_defaults[SS7_ASP_XUA_TIMERS_LEN];
/* According to SUA RFC3868 Section 8, M3UA RFC4666 Section 4.3.4.1 */
#define SS7_ASP_XUA_DEFAULT_T_ACK_SEC	2
/* According to SUA RFC3868 Section 8 */
#define SS7_ASP_XUA_DEFAULT_T_BEAT_SEC	30

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

	/* ASP Identifier for ASP-UP + NTFY, as received by the peer.
	 * (In IPA ASPs it's used internally to hold 4-bit SLS).
	 * FIXME: This should actually be stored in a AS-ASP relation, since it
	 *        can be different per AS, see RFC4666 3.5.1
	 * "The optional ASP Identifier parameter contains a unique value that
	 *  is locally significant among the ASPs that support an AS".
	 */
	uint32_t remote_asp_id;
	bool remote_asp_id_present;

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

	/* IPA proto ASP specific fields. */
	struct {
		/* Incoming IPA PDUs have no SLS field, hence a potentially
		 * unique one within AS is assigned to this ASP and applied
		 * manually when received. */
		uint8_t sls:4;
		bool sls_assigned;
	} ipa;

	struct {
		char *name;
		char *description;
		enum osmo_ss7_asp_protocol proto;
		enum osmo_ss7_asp_admin_state adm_state;
		bool is_server;
		enum osmo_ss7_asp_role role;
		bool role_set_by_vty;
		bool trans_role_set_by_vty;
		/* Used internally by "asp" node to figure out if "no shutdown"
		 * was done explicitly, in order to avoid automatic asp
		 * reconfiguring/restart at go_parent().
		 * Can be dropped in the future once we make sure everybody uses
		 * "[no] shutdown" explicitly in cfg files. */
		bool explicit_shutdown_state_by_vty_since_node_enter;

		struct osmo_ss7_asp_peer local;
		struct osmo_ss7_asp_peer remote;
		uint8_t qos_class;
		uint32_t quirks;

		/* Whether to Tx xUA DAUD during ASP activation when in ASP role. */
		bool daud_act;

		/* T_defs used by the default_lm: */
		struct osmo_tdef *T_defs_xua;

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

		struct {
			bool keepalive_enable;
			bool keepalive_time_present;
			bool keepalive_intvl_present;
			bool keepalive_probes_present;
			bool user_timeout_present;
			int keepalive_time_value; /* seconds */
			int keepalive_intvl_value; /* seconds */
			int keepalive_probes_value;
			unsigned int user_timeout_value; /* milliseconds */
		} tcp;

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
int ss7_asp_disconnect_stream(struct osmo_ss7_asp *asp);

int ss7_asp_apply_tcp_pars(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_peer_primary_address(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_primary_address(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_new_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx);
int ss7_asp_apply_drop_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx);

void ss7_asp_restart_after_reconfigure(struct osmo_ss7_asp *asp);
void osmo_ss7_asp_remove_default_lm(struct osmo_ss7_asp *asp);

unsigned int ss7_asp_get_all_rctx(const struct osmo_ss7_asp *asp, uint32_t *rctx, unsigned int rctx_size,
				  const struct osmo_ss7_as *excl_as);
unsigned int ss7_asp_get_all_rctx_be(const struct osmo_ss7_asp *asp, uint32_t *rctx, unsigned int rctx_size,
				  const struct osmo_ss7_as *excl_as);

#define LOGPASP(asp, subsys, level, fmt, args ...) \
	_LOGSS7((asp)->inst, subsys, level, "ASP(%s) " fmt, (asp)->cfg.name, ## args)
