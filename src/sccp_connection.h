#pragma once
#include <inttypes.h>

#include <osmocom/core/fsm.h>
#include <osmocom/sigtran/sccp_sap.h>

struct xua_msg;

/* a logical connection within the SCCP instance */
struct sccp_connection {
	/* entry in (struct sccp_instance)->connections */
	struct rb_node node;
	/* which instance are we part of? */
	struct osmo_sccp_instance *inst;
	/* which user owns us? */
	struct osmo_sccp_user *user;

	/* remote point code */
	uint32_t remote_pc;

	/* local/remote addresses and identities */
	struct osmo_sccp_addr calling_addr;
	struct osmo_sccp_addr called_addr;
	/* SCCP connection identifier. Only relevant across the SCCP User SAP,
	 * i.e. between the local application using the SCCP stack provided by
	 * libosmo-sccp.  Never transmitted over the wire! */
	uint32_t conn_id;
	/* SCCP Remote Connection Reference.  Allocated by the remote
	 * SCCP stack to uniquely identify a SCCP connection on its end.
	 * We don't interpret it, but simply cache it here so we can use
	 * it whenever sending data to the peer. Only relevant over the
	 * wire, not to be used across the SCCP user SAP */
	uint32_t remote_ref;

	uint32_t importance;
	uint32_t sccp_class;
	uint32_t release_cause; /* WAIT_CONN_CONF */

	/* SLS to be used to transmit all Connection-oriented messages
	 * (ITU-T Q.714 1.1.2.3 Protocol class 2).
	 * SLS is 4 bits, as described in ITU Q.704 Figure 3 */
	uint8_t tx_co_mtp_sls;

	struct msgb *opt_data_cache;

	/* incoming (true) or outgoing (false) */
	bool incoming;

	/* Osmo FSM Instance of sccp_scoc_fsm */
	struct osmo_fsm_inst *fi;

	/* Connect timer */
	struct osmo_timer_list t_conn;

	/* inactivity timers */
	struct osmo_timer_list t_ias;
	struct osmo_timer_list t_iar;

	/* release timers */
	struct osmo_timer_list t_rel;
	struct osmo_timer_list t_int;
	struct osmo_timer_list t_rep_rel;
};

struct sccp_connection *sccp_conn_alloc(struct osmo_sccp_user *user, uint32_t conn_id);
void sccp_conn_free(struct sccp_connection *conn);

/* timer related: */
void sccp_conn_restart_tx_inact_timer(struct sccp_connection *conn);
void sccp_conn_restart_rx_inact_timer(struct sccp_connection *conn);
void sccp_conn_start_inact_timers(struct sccp_connection *conn);
void sccp_conn_stop_inact_timers(struct sccp_connection *conn);
void sccp_conn_start_rel_timer(struct sccp_connection *conn);
void sccp_conn_start_rep_rel_timer(struct sccp_connection *conn);
void sccp_conn_start_int_timer(struct sccp_connection *conn);
void sccp_conn_stop_release_timers(struct sccp_connection *conn);
void sccp_conn_start_connect_timer(struct sccp_connection *conn);
void sccp_conn_stop_connect_timer(struct sccp_connection *conn);

void sccp_conn_opt_data_send_cache(struct sccp_connection *conn, int exp_type, uint8_t msg_class);

int sccp_conn_xua_gen_encode_and_send(struct sccp_connection *conn, uint32_t event,
				      const struct osmo_scu_prim *prim, int msg_type);
int sccp_conn_xua_gen_relre_and_send(struct sccp_connection *conn, uint32_t cause,
				     struct osmo_scu_prim *prim);
void sccp_conn_scu_gen_encode_and_send(struct sccp_connection *conn, uint32_t event,
				       struct xua_msg *xua, unsigned int primitive,
				       enum osmo_prim_operation operation);


#define _LOGPSCC(scc, subsys, level, fmt, args ...) \
	_LOGPSCU((scc)->user, subsys, level, "CONN(%d,remPC=%u=%s) " fmt, \
		 (conn)->conn_id, (conn)->remote_pc, osmo_ss7_pointcode_print((conn)->inst->ss7, (conn)->remote_pc), ## args)
#define LOGPSCC(scc, level, fmt, args ...) \
	_LOGPSCC(scc, DLSCCP, level, fmt, ## args)
