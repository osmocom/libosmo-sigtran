/* SCCP M3UA / SUA ASP osmo_fsm according to RFC3868 4.3.1 */
/* (C) Copyright 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Based on my earlier Erlang implementation xua_asp_fsm.erl in
 * osmo-ss7.git
 */

#include "config.h"

#include <errno.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/select.h>
#include <osmocom/gsm/ipa.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>
#include "xua_msg.h"
#include <osmocom/sigtran/protocol/sua.h>

#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_internal.h"
#include "ss7_xua_srv.h"
#include "sccp_internal.h"
#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"
#include "xua_internal.h"

#ifdef WITH_TCAP_LOADSHARING
#include "tcap_as_loadshare.h"
#endif /* WITH_TCAP_LOADSHARING */

#define S(x)	(1 << (x))

/* The general idea is:
 * * translate incoming SUA/M3UA msg_class/msg_type to xua_asp_event
 * * propagate state transitions to XUA_AS_FSM via _onenter functions
 * * notify the Layer Management of any relevant changes
 * *
 */

static const struct value_string xua_asp_event_names[] = {
	{ XUA_ASP_E_M_ASP_UP_REQ,	"M-ASP_UP.req" },
	{ XUA_ASP_E_M_ASP_ACTIVE_REQ,	"M-ASP_ACTIVE.req" },
	{ XUA_ASP_E_M_ASP_DOWN_REQ,	"M-ASP_DOWN.req" },
	{ XUA_ASP_E_M_ASP_INACTIVE_REQ,	"M-ASP_INACTIVE.req" },

	{ XUA_ASP_E_SCTP_COMM_DOWN_IND,	"SCTP-COMM_DOWN.ind" },
	{ XUA_ASP_E_SCTP_RESTART_IND,	"SCTP-RESTART.ind" },
	{ XUA_ASP_E_SCTP_EST_IND,	"SCTP-EST.ind" },

	{ XUA_ASP_E_ASPSM_ASPUP,	"ASPSM-ASP_UP" },
	{ XUA_ASP_E_ASPSM_ASPUP_ACK,	"ASPSM-ASP_UP_ACK" },
	{ XUA_ASP_E_ASPTM_ASPAC,	"ASPTM-ASP_AC" },
	{ XUA_ASP_E_ASPTM_ASPAC_ACK,	"ASPTM-ASP_AC_ACK" },
	{ XUA_ASP_E_ASPSM_ASPDN,	"ASPSM-ASP_DN" },
	{ XUA_ASP_E_ASPSM_ASPDN_ACK,	"ASPSM-ASP_DN_ACK" },
	{ XUA_ASP_E_ASPTM_ASPIA,	"ASPTM-ASP_IA" },
	{ XUA_ASP_E_ASPTM_ASPIA_ACK,	"ASPTM_ASP_IA_ACK" },

	{ XUA_ASP_E_ASPSM_BEAT,		"ASPSM_BEAT" },
	{ XUA_ASP_E_ASPSM_BEAT_ACK,	"ASPSM_BEAT_ACK" },

	{ XUA_ASP_E_AS_ASSIGNED,	"AS_ASSIGNED" },

	{ IPA_ASP_E_ID_RESP,		"IPA_CCM_ID_RESP" },
	{ IPA_ASP_E_ID_GET,		"IPA_CCM_ID_GET" },
	{ IPA_ASP_E_ID_ACK,		"IPA_CCM_ID_ACK" },

	{ 0, NULL }
};

/* private data structure for each FSM instance */
struct xua_asp_fsm_priv {
	/* pointer back to ASP to which we belong */
	struct osmo_ss7_asp *asp;

	/* routing context[s]: list of 32bit integers */
	/* ACTIVE: traffic mode type, tid label, drn label ? */

	struct { /* RFC3868 & RFC4666 timer T(ack) */
		struct osmo_timer_list timer;
		int out_event;
	} t_ack;

	/* Timer for tracking HEARTBEAT without HEARTBEAT ACK */
	struct {
		struct osmo_timer_list timer;
		uint32_t unacked_beats;
	} t_beat;
};

struct osmo_xlm_prim *xua_xlm_prim_alloc(enum osmo_xlm_prim_type prim_type,
					 enum osmo_prim_operation op)
{
	struct osmo_xlm_prim *prim;
	struct msgb *msg = msgb_alloc_headroom(2048+128, 128, "xua_asp-xlm msgb");
	if (!msg)
		return NULL;

	prim = (struct osmo_xlm_prim *) msgb_put(msg, sizeof(*prim));
	osmo_prim_init(&prim->oph, XUA_SAP_LM, prim_type, op, msg);

	return prim;
}

/* Send a XUA LM Primitive to the XUA Layer Manager (LM) */
void xua_asp_send_xlm_prim(struct osmo_ss7_asp *asp, struct osmo_xlm_prim *prim)
{
	const struct osmo_xua_layer_manager *lm = asp->lm;

	if (lm && lm->prim_cb)
		lm->prim_cb(&prim->oph, asp);
	else {
		LOGPFSML(asp->fi, LOGL_DEBUG, "No Layer Manager, dropping %s\n",
			 osmo_xlm_prim_name(&prim->oph));
	}

	msgb_free(prim->oph.msg);
}

/* wrapper around send_xlm_prim for primitives without data */
void xua_asp_send_xlm_prim_simple(struct osmo_ss7_asp *asp,
				enum osmo_xlm_prim_type prim_type,
				enum osmo_prim_operation op)
{
	struct osmo_xlm_prim *prim = xua_xlm_prim_alloc(prim_type, op);
	if (!prim)
		return;
	xua_asp_send_xlm_prim(asp, prim);
}

static void send_xlm_prim_simple(struct osmo_fsm_inst *fi,
				 enum osmo_xlm_prim_type prim_type,
				enum osmo_prim_operation op)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	xua_asp_send_xlm_prim_simple(asp, prim_type, op);
}

static void xua_asp_tx_snm_daud_address_book(struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_instance *inst = asp->inst;
	uint32_t rctx[OSMO_SS7_MAX_RCTX_COUNT];
	unsigned int num_rctx;
	uint32_t *aff_pc = NULL;
	unsigned int num_aff_pc = 0;
	struct osmo_sccp_addr_entry *entry;

	num_rctx = ss7_asp_get_all_rctx_be(asp, rctx, ARRAY_SIZE(rctx), NULL);

	/* First count required size of num_aff_pc array: */
	llist_for_each_entry(entry, &inst->cfg.sccp_address_book, list) {
		if (!(entry->addr.presence & OSMO_SCCP_ADDR_T_PC))
			continue;
		if (osmo_ss7_pc_is_local(inst, entry->addr.pc))
			continue;
		num_aff_pc++;
	}
	if (num_aff_pc == 0) {
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Skip Tx DAUD: No SCCP in address book\n");
		return;
	}
	aff_pc = talloc_array(asp, uint32_t, num_aff_pc);
	OSMO_ASSERT(aff_pc);

	num_aff_pc = 0;
	llist_for_each_entry(entry, &inst->cfg.sccp_address_book, list) {
		uint32_t curr_aff_pc;
		unsigned int i;
		if (!(entry->addr.presence & OSMO_SCCP_ADDR_T_PC))
			continue;
		if (osmo_ss7_pc_is_local(inst, entry->addr.pc))
			continue;
		LOGPASP(asp, DLSS7, LOGL_DEBUG, "Tx DAUD: Requesting status of DPC=%u=%s\n",
			entry->addr.pc, osmo_ss7_pointcode_print2(inst, entry->addr.pc));
		curr_aff_pc = htonl(entry->addr.pc); /* mask = 0 */
		for (i = 0; i < num_aff_pc; i++)
			if (aff_pc[i] == curr_aff_pc)
				break;
		if (i == num_aff_pc) /* not found in array */
			aff_pc[num_aff_pc++] = curr_aff_pc;
	}

	xua_tx_snm_daud(asp, rctx, num_rctx, aff_pc, num_aff_pc, "Isolation-ASP-ACTIVE");
	talloc_free(aff_pc);
}

/* add M3UA_IEI_ROUTE_CTX to xua_msg containig all routing keys of ASs within ASP */
static int xua_msg_add_asp_rctx(struct xua_msg *xua, struct osmo_ss7_asp *asp)
{
	uint32_t rctx[OSMO_SS7_MAX_RCTX_COUNT];
	unsigned int cnt;

	cnt = ss7_asp_get_all_rctx_be(asp, rctx, ARRAY_SIZE(rctx), NULL);
	if (cnt > 0)
		xua_msg_add_data(xua, M3UA_IEI_ROUTE_CTX, cnt*sizeof(uint32_t), (uint8_t *)rctx);
	/* return count of routing contexts added */
	return cnt;
}

/* ask the xUA implementation to transmit a specific message */
static int peer_send(struct osmo_fsm_inst *fi, int out_event, struct xua_msg *in)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct xua_msg *xua = xua_msg_alloc();
	struct msgb *msg;
	int rc;

	switch (out_event) {
	case XUA_ASP_E_ASPSM_ASPUP:
		/* RFC 3868 Ch. 3.5.1 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_UP);
		/* Optional: ASP ID */
		if (asp->cfg.local_asp_id_present)
			xua_msg_add_u32(xua, SUA_IEI_ASP_ID, asp->cfg.local_asp_id);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_ASPUP_ACK:
		/* RFC3868 Ch. 3.5.2 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_UP_ACK);
		/* Optional: ASP ID */
		if (asp->cfg.local_asp_id_present)
			xua_msg_add_u32(xua, SUA_IEI_ASP_ID, asp->cfg.local_asp_id);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		/* RFC3868 Ch. 3.5.3 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_DOWN);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_ASPDN_ACK:
		/* RFC3868 Ch. 3.5.4 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_DOWN_ACK);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPSM_BEAT:
		/* RFC3868 Ch. 3.5.5 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_BEAT);
		/* Optional: Heartbeat Data */
		break;
	case XUA_ASP_E_ASPSM_BEAT_ACK:
		/* RFC3868 Ch. 3.5.6 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPSM, SUA_ASPSM_BEAT_ACK);
		/* Optional: Heartbeat Data */
		xua_msg_copy_part(xua, M3UA_IEI_HEARDBT_DATA, in, M3UA_IEI_HEARDBT_DATA);
		break;
	case XUA_ASP_E_ASPTM_ASPAC:
		/* RFC3868 Ch. 3.6.1 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_ACTIVE);
		/* Optional: Traffic Mode Type */
		rc = ss7_asp_determine_traf_mode(asp);
		if (rc >= 0)
			xua_msg_add_u32(xua, M3UA_IEI_TRAF_MODE_TYP, osmo_ss7_tmode_to_xua(rc));
		/* Optional: Routing Context */
		xua_msg_add_asp_rctx(xua, asp);
		/* Optional: TID Label */
		/* Optional: DRN Label */
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPTM_ASPAC_ACK:
		/* RFC3868 Ch. 3.6.2 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_ACTIVE_ACK);
		/* Optional: Traffic Mode Type */
		xua_msg_copy_part(xua, M3UA_IEI_TRAF_MODE_TYP, in, M3UA_IEI_TRAF_MODE_TYP);
		/* Optional: Routing Context */
		xua_msg_copy_part(xua, M3UA_IEI_ROUTE_CTX, in, M3UA_IEI_ROUTE_CTX);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPTM_ASPIA:
		/* RFC3868 Ch. 3.6.3 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_INACTIVE);
		/* Optional: Routing Context */
		xua_msg_add_asp_rctx(xua, asp);
		/* Optional: Info String */
		break;
	case XUA_ASP_E_ASPTM_ASPIA_ACK:
		/* RFC3868 Ch. 3.6.4 */
		xua->hdr = XUA_HDR(SUA_MSGC_ASPTM, SUA_ASPTM_INACTIVE_ACK);
		/* Optional: Routing Context */
		/* Optional: Info String */
		break;
	}

	msg = xua_to_msg(SUA_VERSION, xua);
	xua_msg_free(xua);
	if (!msg)
		return -1;

	return osmo_ss7_asp_send(asp, msg);
}

static int peer_send_error(struct osmo_fsm_inst *fi, uint32_t err_code)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct xua_msg *xua = xua_msg_alloc();
	struct msgb *msg;

	LOGPFSML(fi, LOGL_ERROR, "Tx MGMT_ERR '%s'\n", get_value_string(m3ua_err_names, err_code));

	xua->hdr = XUA_HDR(SUA_MSGC_MGMT, SUA_MGMT_ERR);
	xua->hdr.version = SUA_VERSION;
	xua_msg_add_u32(xua, SUA_IEI_ERR_CODE, err_code);

	msg = xua_to_msg(SUA_VERSION, xua);
	xua_msg_free(xua);
	if (!msg)
		return -1;

	return osmo_ss7_asp_send(asp, msg);
}

static void xua_t_ack_cb(void *data)
{
	struct osmo_fsm_inst *fi = data;
	struct xua_asp_fsm_priv *xafp = fi->priv;
	uint32_t timeout_sec;

	LOGPFSML(fi, LOGL_INFO, "T(ack) callback: re-transmitting event %s\n",
		osmo_fsm_event_name(fi->fsm, xafp->t_ack.out_event));

	/* Re-transmit message */
	peer_send(fi, xafp->t_ack.out_event, NULL);

	/* Re-start the timer */
	timeout_sec = osmo_tdef_get(xafp->asp->cfg.T_defs_xua, SS7_ASP_XUA_T_ACK, OSMO_TDEF_S, -1);
	osmo_timer_schedule(&xafp->t_ack.timer, timeout_sec, 0);
}

static int peer_send_and_start_t_ack(struct osmo_fsm_inst *fi,
				     int out_event)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	uint32_t timeout_sec;
	int rc;

	rc = peer_send(fi, out_event, NULL);
	if (rc < 0)
		return rc;

	xafp->t_ack.out_event = out_event;
	xafp->t_ack.timer.cb = xua_t_ack_cb,
	xafp->t_ack.timer.data = fi;

	timeout_sec = osmo_tdef_get(xafp->asp->cfg.T_defs_xua, SS7_ASP_XUA_T_ACK, OSMO_TDEF_S, -1);
	osmo_timer_schedule(&xafp->t_ack.timer, timeout_sec, 0);

	return rc;
}

static const uint32_t evt_ack_map[_NUM_XUA_ASP_E] = {
	[XUA_ASP_E_ASPSM_ASPUP] = XUA_ASP_E_ASPSM_ASPUP_ACK,
	[XUA_ASP_E_ASPTM_ASPAC] = XUA_ASP_E_ASPTM_ASPAC_ACK,
	[XUA_ASP_E_ASPSM_ASPDN] = XUA_ASP_E_ASPSM_ASPDN_ACK,
	[XUA_ASP_E_ASPTM_ASPIA] = XUA_ASP_E_ASPTM_ASPIA_ACK,
	[XUA_ASP_E_ASPSM_BEAT] = XUA_ASP_E_ASPSM_BEAT_ACK,
};

/* Helper function to dispatch an ASP->AS event to all AS of which this
 * ASP is a memmber.  Ignores routing contexts for now. */
static void dispatch_to_all_as(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct ss7_as_asp_assoc *assoc;

	llist_for_each_entry(assoc, &asp->assoc_as_list, asp_entry)
		osmo_fsm_inst_dispatch(assoc->as->fi, event, data);
}

/* check if expected message was received + stop t_ack */
static void check_stop_t_ack(struct osmo_fsm_inst *fi, uint32_t event)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	int exp_ack;

	if (event >= ARRAY_SIZE(evt_ack_map))
		return;

	exp_ack = evt_ack_map[xafp->t_ack.out_event];
	if (exp_ack && event == exp_ack) {
		LOGPFSML(fi, LOGL_DEBUG, "T(ack) stopped\n");
		osmo_timer_del(&xafp->t_ack.timer);
	}
}

static void xua_t_beat_stop(struct osmo_fsm_inst *fi)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;

	LOGPFSML(fi, LOGL_DEBUG, "T(beat) stopped\n");
	osmo_timer_del(&xafp->t_beat.timer);
	xafp->t_beat.unacked_beats = 0;
}

static void xua_t_beat_send(struct osmo_fsm_inst *fi)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	uint32_t timeout_sec;

	timeout_sec = osmo_tdef_get(xafp->asp->cfg.T_defs_xua, SS7_ASP_XUA_T_BEAT, OSMO_TDEF_S, -1);

	/* T(beat) disabled */
	if (timeout_sec == 0) {
		xua_t_beat_stop(fi);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG, "Tx HEARTBEAT (%u unacked)\n", xafp->t_beat.unacked_beats);

	/* Avoid increasing in case some extra gratuitous PING is transmitted: */
	if (!osmo_timer_pending(&xafp->t_beat.timer))
		xafp->t_beat.unacked_beats++;

	/* (re-)arm T(beat): */
	osmo_timer_schedule(&xafp->t_beat.timer, timeout_sec, 0);

	/* Send HEARTBEAT: */
	peer_send(fi, XUA_ASP_E_ASPSM_BEAT, NULL);

}

static void xua_t_beat_cb(void *_fi)
{
	struct osmo_fsm_inst *fi = _fi;
	struct xua_asp_fsm_priv *xafp = fi->priv;

	if (xafp->t_beat.unacked_beats < 2) {
		if (xafp->t_beat.unacked_beats == 1)
			LOGPFSML(fi, LOGL_NOTICE,
				 "Peer didn't respond to HEARTBEAT with HEARTBEAT ACK, retrying once more\n");
		xua_t_beat_send(fi);
		return;
	}

	/* RFC4666 4.3.4.6: If no Heartbeat Ack message (or any other M3UA
	 * message) is received from the M3UA peer within 2*T(beat), the remote
	 * M3UA peer is considered unavailable.  Transmission of Heartbeat
	 * messages is stopped, and the signalling process SHOULD attempt to
	 * re-establish communication if it is configured as the client for the
	 * disconnected M3UA peer.
	 */
	LOGPFSML(fi, LOGL_NOTICE, "Peer didn't respond to HEARTBEAT with HEARTBEAT ACK and became disconnected\n");
	ss7_asp_disconnect_stream(xafp->asp);

}

static void common_asp_fsm_down_onenter(struct osmo_ss7_asp *asp)
{
	struct ss7_as_asp_assoc *assoc, *assoc2;

	/* First notify all AS associated to the ASP that it went down: */
	dispatch_to_all_as(asp->fi, XUA_ASPAS_ASP_DOWN_IND, asp);

	/* Implicit clean up tasks: */
	llist_for_each_entry_safe(assoc, assoc2, &asp->assoc_as_list, asp_entry) {
		struct osmo_ss7_as *as = assoc->as;
#ifdef WITH_TCAP_LOADSHARING
			tcap_as_del_asp(as, asp);
#endif

		if (as->rkm_dyn_allocated) {
			/* RFC 4666 4.4.2: "An ASP SHOULD deregister from all Application Servers
			 * of which it is a member before attempting to move to the ASP-Down state [...]
			 * If a Deregistration results in no more ASPs in an Application Server,
			 * an SG MAY delete the Routing Key data."
			 * In case it didn't deregsitrer explicitly, make sure to implicitly deregister it:
			 */
			ss7_as_del_asp(as, asp);
		}
	}
}

#define ENSURE_ROLE_COND(fi, event, cond)				\
	do {								\
		struct xua_asp_fsm_priv *_xafp = fi->priv;		\
		enum osmo_ss7_asp_role _role = _xafp->asp->cfg.role;	\
		if (!(cond)) {		\
			LOGPFSML(fi, LOGL_ERROR, "event %s not permitted " \
				 "in role %s\n",			\
				 osmo_fsm_event_name(fi->fsm, event),	\
				 get_value_string(osmo_ss7_asp_role_names, _role));\
			return;						\
		}							\
	} while (0)

#define ENSURE_IPSP(fi, event) \
	ENSURE_ROLE_COND(fi, event, _role == OSMO_SS7_ASP_ROLE_IPSP)

#define ENSURE_ASP_OR_IPSP(fi, event) \
	ENSURE_ROLE_COND(fi, event, _role == OSMO_SS7_ASP_ROLE_ASP || _role == OSMO_SS7_ASP_ROLE_IPSP)

#define ENSURE_SG_OR_IPSP(fi, event) \
	ENSURE_ROLE_COND(fi, event, _role == OSMO_SS7_ASP_ROLE_SG || _role == OSMO_SS7_ASP_ROLE_IPSP)


/***************
** FSM states **
***************/

static void xua_asp_fsm_down_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	xua_t_beat_stop(fi);
	common_asp_fsm_down_onenter(asp);
}

static void xua_asp_fsm_down(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct xua_msg_part *asp_id_ie;

	check_stop_t_ack(fi, event);

	switch (event) {
	case XUA_ASP_E_M_ASP_UP_REQ:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* Send M3UA_MSGT_ASPSM_ASPUP and start t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPSM_ASPUP);
		break;
	case XUA_ASP_E_ASPSM_ASPUP_ACK:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* Optional ASP Identifier */
		if ((asp_id_ie = xua_msg_find_tag(data, SUA_IEI_ASP_ID))) {
			asp->remote_asp_id = xua_msg_part_get_u32(asp_id_ie);
			asp->remote_asp_id_present = true;
		}
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		/* inform layer manager */
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_UP, PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPSM_ASPUP:
		ENSURE_SG_OR_IPSP(fi, event);
		/* Optional ASP Identifier: Store for NTFY */
		if ((asp_id_ie = xua_msg_find_tag(data, SUA_IEI_ASP_ID))) {
			asp->remote_asp_id = xua_msg_part_get_u32(asp_id_ie);
			asp->remote_asp_id_present = true;
		}
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPUP_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_UP,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		ENSURE_SG_OR_IPSP(fi, event);
		/* The SGP MUST send an ASP Down Ack message in response
		 * to a received ASP Down message from the ASP even if
		 * the ASP is already marked as ASP-DOWN at the SGP. */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPDN_ACK, NULL);
		break;
	case XUA_ASP_E_SCTP_EST_IND:
		break;
	}
}

static void xua_asp_fsm_inactive_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	bool went_up = (prev_state == XUA_ASP_S_DOWN);

	if (went_up) {
		/* Now we are done with IPA handshake, Start Hearbeat Procedure, T(beat): */
		xua_t_beat_send(fi);
	}

	/* RFC4666 4.3.4.5: "When an ASP moves from ASP-DOWN to ASP-INACTIVE within a
	 * particular AS, a Notify message SHOULD be sent, by the ASP-UP receptor,
	 * after sending the ASP-UP-ACK, in order to inform the ASP of the current AS
	 * state."
	 * NOTIFY is only transmitted by roles SG and IPSP.
	 */
	struct xua_as_event_asp_inactive_ind_pars pars = {
		.asp = asp,
		.asp_requires_notify = (asp->cfg.role != OSMO_SS7_ASP_ROLE_ASP) &&
				       went_up,
	};
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_INACTIVE_IND, &pars);
}

static void xua_asp_fsm_inactive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	struct osmo_ss7_as *as;
	struct xua_msg_part *asp_id_ie;
	struct xua_msg *xua_in;
	uint32_t traf_mode = 0;
	struct xua_msg_part *part;
	int i;

	check_stop_t_ack(fi, event);
	switch (event) {
	case XUA_ASP_E_M_ASP_ACTIVE_REQ:
		/* send M3UA_MSGT_ASPTM_ASPAC and start t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPTM_ASPAC);
		break;
	case XUA_ASP_E_M_ASP_DOWN_REQ:
		/* send M3UA_MSGT_ASPSM_ASPDN and start t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPSM_ASPDN);
		break;
	case XUA_ASP_E_ASPSM_ASPUP_ACK:
		/* This may come in IPSP if we received ASPUP from peer before it answered our ASPUP: */
		ENSURE_IPSP(fi, event);
		/* Optional ASP Identifier */
		if ((asp_id_ie = xua_msg_find_tag(data, SUA_IEI_ASP_ID))) {
			asp->remote_asp_id = xua_msg_part_get_u32(asp_id_ie);
			asp->remote_asp_id_present = true;
		}
		/* inform layer manager */
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_UP, PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPTM_ASPAC_ACK:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_ACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_ACTIVE,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPSM_ASPDN_ACK:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPTM_ASPAC:
		xua_in = data;
		ENSURE_SG_OR_IPSP(fi, event);
		if (xua_msg_find_tag(xua_in, M3UA_IEI_TRAF_MODE_TYP)) {
			traf_mode = xua_msg_get_u32(xua_in, M3UA_IEI_TRAF_MODE_TYP);
			if (traf_mode != M3UA_TMOD_OVERRIDE &&
			    traf_mode != M3UA_TMOD_LOADSHARE &&
			    traf_mode != M3UA_TMOD_BCAST) {
				peer_send_error(fi, M3UA_ERR_UNSUPP_TRAF_MOD_TYP);
				return;
			}
		}
		if ((part = xua_msg_find_tag(xua_in, M3UA_IEI_ROUTE_CTX))) {
			for (i = 0; i < part->len / sizeof(uint32_t); i++) {
				uint32_t rctx = osmo_load32be(&part->dat[i * sizeof(uint32_t)]);
				as = osmo_ss7_as_find_by_rctx(asp->inst, rctx);
				if (!as) {
					LOGPFSML(fi, LOGL_NOTICE,
						 "ASPAC: Couldn't find any AS with rctx=%u. Check your config!\n",
						 rctx);
					peer_send_error(fi, M3UA_ERR_INVAL_ROUT_CTX);
					return;
				}
			}
		}

		if (traf_mode) { /* if the peer has specified a traffic mode at all */
			enum osmo_ss7_as_traffic_mode tmode = osmo_ss7_tmode_from_xua(traf_mode);
			struct ss7_as_asp_assoc *assoc;
			llist_for_each_entry(assoc, &asp->assoc_as_list, asp_entry) {
				as = assoc->as;
				if (!as->cfg.mode_set_by_peer && !as->cfg.mode_set_by_vty) {
					as->cfg.mode = tmode;
					LOGPAS(as, DLSS7, LOGL_INFO,
						"ASPAC: Traffic mode set dynamically by peer to %s\n",
						osmo_ss7_as_traffic_mode_name(as->cfg.mode));
				} else if (!osmo_ss7_as_tmode_compatible_xua(as, traf_mode)) {
					peer_send_error(fi, M3UA_ERR_UNSUPP_TRAF_MOD_TYP);
					return;
				}
				as->cfg.mode_set_by_peer = true;
			}
		}

		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPTM_ASPAC_ACK, xua_in);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_ACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_ACTIVE,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPDN_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPUP:
		ENSURE_SG_OR_IPSP(fi, event);
		/* If an ASP Up message is received and internally the
		 * remote ASP is already in the ASP-INACTIVE state, an
		 * ASP Up Ack message is returned and no further action
		 * is taken. */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPUP_ACK, NULL);
		break;
	case XUA_ASP_E_ASPTM_ASPIA:
		ENSURE_SG_OR_IPSP(fi, event);
		peer_send(fi, XUA_ASP_E_ASPTM_ASPIA_ACK, NULL);
		break;
	}
}

static void xua_asp_fsm_active_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;

	if (asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP && asp->cfg.daud_act) {
		/* RFC4666 4.6, RFC3868 4.6: "The ASP MAY choose to audit the availability
		 * of unavailable destinations by sending DAUD messages.
		 * This would be the case when, for example, an AS becomes active at an ASP
		 * and does not have current destination statuses."
		 * See also RFC4666 4.5.3, RFC3868 4.5.3 "ASP Auditing".
		 * See also RFC4666 5.5.1.1.3 "Support for ASP Querying of SS7 Destination States"
		 */
		LOGPFSML(fi, LOGL_INFO, "Tx DAUD\n");
		xua_asp_tx_snm_daud_address_book(asp);
	}

	dispatch_to_all_as(fi, XUA_ASPAS_ASP_ACTIVE_IND, asp);
}

static void xua_asp_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_msg *xua_in;
	check_stop_t_ack(fi, event);
	switch (event) {
	case XUA_ASP_E_ASPTM_ASPAC_ACK:
		/* This may come in IPSP if we received ASPAC from peer before it answered our ASPAC: */
		ENSURE_IPSP(fi, event);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_ACTIVE, PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPSM_ASPDN_ACK:
		ENSURE_ASP_OR_IPSP(fi, event);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		/* inform layer manager */
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_ASPTM_ASPIA_ACK:
		ENSURE_ASP_OR_IPSP(fi, event);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		/* inform layer manager */
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_INACTIVE,
				     PRIM_OP_CONFIRM);
		break;
	case XUA_ASP_E_M_ASP_DOWN_REQ:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* send M3UA_MSGT_ASPSM_ASPDN and star t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPSM_ASPDN);
		break;
	case XUA_ASP_E_M_ASP_INACTIVE_REQ:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* send M3UA_MSGT_ASPTM_ASPIA and star t_ack */
		peer_send_and_start_t_ack(fi, XUA_ASP_E_ASPTM_ASPIA);
		break;
	case XUA_ASP_E_ASPTM_ASPIA:
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPTM_ASPIA_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_INACTIVE,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPDN:
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPSM_ASPDN_ACK, NULL);
		/* transition state and inform layer manager */
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_ASPUP:
		ENSURE_SG_OR_IPSP(fi, event);
		/* an ASP Up Ack message is returned, as well as
		 * an Error message ("Unexpected Message), and the
		 * remote ASP state is changed to ASP-INACTIVE in all
		 * relevant Application Servers */
		peer_send_error(fi, M3UA_ERR_UNEXPECTED_MSG);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_INACTIVE, 0, 0);
		peer_send(fi, XUA_ASP_E_ASPSM_ASPUP_ACK, NULL);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_INACTIVE,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPTM_ASPAC:
		xua_in = data;
		ENSURE_SG_OR_IPSP(fi, event);
		/* send ACK */
		peer_send(fi, XUA_ASP_E_ASPTM_ASPAC_ACK, xua_in);
		break;
	}
}

static void xua_asp_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct xua_msg *xua;

	switch (event) {
	case XUA_ASP_E_SCTP_COMM_DOWN_IND:
	case XUA_ASP_E_SCTP_RESTART_IND:
		osmo_timer_del(&xafp->t_ack.timer);
		osmo_fsm_inst_state_chg(fi, XUA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_BEAT:
		xua = data;
		peer_send(fi, XUA_ASP_E_ASPSM_BEAT_ACK, xua);
		break;
	case XUA_ASP_E_ASPSM_BEAT_ACK:
		LOGPFSML(fi, LOGL_DEBUG, "Rx HEARTBEAT ACK\n");
		xafp->t_beat.unacked_beats = 0;
		break;
	case XUA_ASP_E_AS_ASSIGNED:
		/* Ignore, only used in IPA asps so far. */
		break;
	default:
		break;
	}
}

static int xua_asp_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	/* We don't use the fsm timer, so any calls to this are an error */
	OSMO_ASSERT(0);
	return 0;
}

static void xua_asp_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;

	if (!xafp)
		return;

	osmo_timer_del(&xafp->t_ack.timer);
	xua_t_beat_stop(fi);

	if (xafp->asp)
		xafp->asp->fi = NULL;
}

static const struct osmo_fsm_state xua_asp_states[] = {
	[XUA_ASP_S_DOWN] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_UP_REQ) |
				 S(XUA_ASP_E_ASPSM_ASPUP) |
				 S(XUA_ASP_E_ASPSM_ASPUP_ACK) |
				 S(XUA_ASP_E_ASPSM_ASPDN) |
				 S(XUA_ASP_E_SCTP_EST_IND),
		.out_state_mask = S(XUA_ASP_S_INACTIVE) |
		                  S(XUA_ASP_S_DOWN),
		.name = "ASP_DOWN",
		.action = xua_asp_fsm_down,
		.onenter = xua_asp_fsm_down_onenter,
	},
	[XUA_ASP_S_INACTIVE] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_ACTIVE_REQ) |
				 S(XUA_ASP_E_M_ASP_DOWN_REQ) |
				 S(XUA_ASP_E_ASPSM_ASPUP_ACK) |
				 S(XUA_ASP_E_ASPTM_ASPAC) |
				 S(XUA_ASP_E_ASPTM_ASPAC_ACK) |
				 S(XUA_ASP_E_ASPTM_ASPIA) |
				 S(XUA_ASP_E_ASPSM_ASPDN) |
				 S(XUA_ASP_E_ASPSM_ASPDN_ACK) |
				 S(XUA_ASP_E_ASPSM_ASPUP),
		.out_state_mask = S(XUA_ASP_S_DOWN) |
				  S(XUA_ASP_S_ACTIVE),
		.name = "ASP_INACTIVE",
		.action = xua_asp_fsm_inactive,
		.onenter = xua_asp_fsm_inactive_onenter,
	},
	[XUA_ASP_S_ACTIVE] = {
		.in_event_mask = S(XUA_ASP_E_ASPSM_ASPDN) |
				 S(XUA_ASP_E_ASPSM_ASPDN_ACK) |
				 S(XUA_ASP_E_ASPSM_ASPUP) |
				 S(XUA_ASP_E_ASPTM_ASPAC_ACK) |
				 S(XUA_ASP_E_ASPTM_ASPIA) |
				 S(XUA_ASP_E_ASPTM_ASPIA_ACK) |
				 S(XUA_ASP_E_ASPTM_ASPAC) |
				 S(XUA_ASP_E_M_ASP_DOWN_REQ) |
				 S(XUA_ASP_E_M_ASP_INACTIVE_REQ),
		.out_state_mask = S(XUA_ASP_S_INACTIVE) |
				  S(XUA_ASP_S_DOWN),
		.name = "ASP_ACTIVE",
		.action = xua_asp_fsm_active,
		.onenter = xua_asp_fsm_active_onenter,
	},
};


struct osmo_fsm xua_asp_fsm = {
	.name = "XUA_ASP",
	.states = xua_asp_states,
	.num_states = ARRAY_SIZE(xua_asp_states),
	.timer_cb = xua_asp_fsm_timer_cb,
	.log_subsys = DLSS7,
	.event_names = xua_asp_event_names,
	.allstate_event_mask = S(XUA_ASP_E_SCTP_COMM_DOWN_IND) |
			       S(XUA_ASP_E_SCTP_RESTART_IND) |
			       S(XUA_ASP_E_ASPSM_BEAT) |
			       S(XUA_ASP_E_ASPSM_BEAT_ACK) |
			       S(XUA_ASP_E_AS_ASSIGNED),
	.allstate_action = xua_asp_allstate,
	.cleanup = xua_asp_fsm_cleanup,
};

static int ipa_asp_fsm_start(struct osmo_ss7_asp *asp, int log_level);

/*! \brief Start a new ASP finite state machine for given ASP (stored in asp->fi)
 *  \param[in] asp Application Server Process for which to start FSM
 *  \param[in] log_level Logging Level for ASP FSM logging
 *  \returns 0 on success; negative on error */
int xua_asp_fsm_start(struct osmo_ss7_asp *asp, int log_level)
{
	struct osmo_fsm_inst *fi;
	struct xua_asp_fsm_priv *xafp;

	if (asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
		return ipa_asp_fsm_start(asp, log_level);

	/* allocate as child of AS? */
	fi = osmo_fsm_inst_alloc(&xua_asp_fsm, asp, NULL, log_level, asp->cfg.name);
	if (!fi)
		return -EINVAL;

	xafp = talloc_zero(fi, struct xua_asp_fsm_priv);
	if (!xafp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return -ENOMEM;
	}
	xafp->asp = asp;

	osmo_timer_setup(&xafp->t_beat.timer, xua_t_beat_cb, fi);

	fi->priv = xafp;

	/* Attach FSM to ASP: */
	asp->fi = fi;

	return 0;
}





/***********************************************************************
 * IPA Compatibility FSM
 ***********************************************************************/

/* The idea here is to have a FSM that handles an IPA / SCCPlite link in
 * a way that the higher-layer code considers it the same like an M3UA
 * or SUA link.  We have a couple of different states and some
 * additional events. */

enum ipa_asp_state {
	IPA_ASP_S_DOWN = XUA_ASP_S_DOWN,
	IPA_ASP_S_INACTIVE = XUA_ASP_S_INACTIVE,
	IPA_ASP_S_ACTIVE = XUA_ASP_S_ACTIVE,
	IPA_ASP_S_WAIT_ID_RESP,		/* Waiting for ID_RESP from peer */
	IPA_ASP_S_WAIT_ID_GET,		/* Waiting for ID_GET from peer */
	IPA_ASP_S_WAIT_ID_ACK,		/* Waiting for ID_ACK from peer */
	IPA_ASP_S_WAIT_ID_ACK2,		/* Waiting for ID_ACK (of ACK) from peer */
};

/* private data structure for each FSM instance */
struct ipa_asp_fsm_priv {
	/* pointer back to ASP to which we belong */
	struct osmo_ss7_asp *asp;

	/* Structure holding parsed data of the IPA CCM ID exchange */
	struct ipaccess_unit *ipa_unit;
	/* Timer for tracking PING without PONG response */
	struct {
		struct osmo_timer_list timer;
		uint32_t unacked_beats;
	} t_beat;
	/* Did we receive IPA ID ACK before IPA ID RESP ? */
	bool ipa_id_ack_rcvd;
};

enum ipa_asp_fsm_t {
	T_WAIT_ID_RESP	= 1,
	T_WAIT_ID_ACK,
	T_WAIT_ID_GET,
};

/* get the file descriptor related to a given ASP */
static int get_fd_from_iafp(struct ipa_asp_fsm_priv *iafp)
{
	struct osmo_ss7_asp *asp = iafp->asp;
	int fd;

	if (asp->server)
		fd = osmo_stream_srv_get_fd(asp->server);
	else if (asp->client)
		fd = osmo_stream_cli_get_fd(asp->client);
	else
		return -1;

	return fd;
}

static void ipa_t_beat_stop(struct osmo_fsm_inst *fi)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;

	LOGPFSML(fi, LOGL_DEBUG, "T(beat) stopped\n");
	osmo_timer_del(&iafp->t_beat.timer);
	iafp->t_beat.unacked_beats = 0;
}

static void ipa_t_beat_send(struct osmo_fsm_inst *fi)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct msgb *msg;
	uint32_t timeout_sec;

	timeout_sec = osmo_tdef_get(iafp->asp->cfg.T_defs_xua, SS7_ASP_XUA_T_BEAT, OSMO_TDEF_S, -1);

	/* T(beat) disabled */
	if (timeout_sec == 0) {
		ipa_t_beat_stop(fi);
		return;
	}

	LOGPFSML(fi, LOGL_DEBUG, "Tx HEARTBEAT (%u unacked)\n", iafp->t_beat.unacked_beats);

	/* Avoid increasing in case some extra gratuitous PING is transmitted: */
	if (!osmo_timer_pending(&iafp->t_beat.timer))
		iafp->t_beat.unacked_beats++;

	/* (re-)arm T(beat): */
	osmo_timer_schedule(&iafp->t_beat.timer, timeout_sec, 0);

	/* Send PING: */
	if ((msg = ipa_gen_ping()))
		osmo_ss7_asp_send(iafp->asp, msg);
	/* we don't own msg anymore in any case here */
}

static void ipa_t_beat_cb(void *_fi)
{
	struct osmo_fsm_inst *fi = _fi;
	struct ipa_asp_fsm_priv *iafp = fi->priv;

	if (iafp->t_beat.unacked_beats < 2) {
		if (iafp->t_beat.unacked_beats == 1)
			LOGPFSML(fi, LOGL_NOTICE,
				 "Peer didn't respond to PING with PONG, retrying once more\n");
		ipa_t_beat_send(fi);
		return;
	}

	/* RFC4666 4.3.4.6: If no Heartbeat Ack message (or any other M3UA
	 * message) is received from the M3UA peer within 2*T(beat), the remote
	 * M3UA peer is considered unavailable.  Transmission of Heartbeat
	 * messages is stopped, and the signalling process SHOULD attempt to
	 * re-establish communication if it is configured as the client for the
	 * disconnected M3UA peer.
	 */
	LOGPFSML(fi, LOGL_NOTICE, "Peer didn't respond to PING with PONG and became disconnected\n");
	ss7_asp_disconnect_stream(iafp->asp);

}

/***************
** FSM states **
***************/

/* Server + Client: Initial State, wait for M-ASP-UP.req */
static void ipa_asp_fsm_down_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct xua_asp_fsm_priv *xafp = fi->priv;
	struct osmo_ss7_asp *asp = xafp->asp;
	ipa_t_beat_stop(fi);
	common_asp_fsm_down_onenter(asp);
}

static void ipa_asp_fsm_down(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	int fd = get_fd_from_iafp(iafp);

	switch (event) {
	case XUA_ASP_E_M_ASP_UP_REQ:
	case XUA_ASP_E_SCTP_EST_IND:
		if (iafp->asp->cfg.role == OSMO_SS7_ASP_ROLE_SG) {
			/* Server: Transmit IPA ID GET + Wait for Response */
			if (fd >= 0) {
				ipa_ccm_send_id_req(fd);
				osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_RESP, 10, T_WAIT_ID_RESP);
			}
		} else {
			/* Client: We simply wait for an ID GET */
			osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_GET, 10, T_WAIT_ID_GET);
		}
		break;
	}
}

/* Server: We're waiting for an ID RESP */
static void ipa_asp_fsm_wait_id_resp(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_asp *asp = iafp->asp;
	int fd = get_fd_from_iafp(iafp);
	struct osmo_ss7_as *as;
	struct tlv_parsed tp;
	struct msgb *msg;
	int rc;

	switch (event) {
	case IPA_ASP_E_ID_RESP:
		/* resolve the AS based on the identity provided by peer. */
		msg = data;
			rc = ipa_ccm_id_resp_parse(&tp, msgb_l2(msg)+1, msgb_l2len(msg)-1);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR, "Error %d parsing ID_RESP TLV: %s\n", rc,
				 msgb_hexdump(msg));
			goto out_err;
		}
		rc = ipa_ccm_tlv_to_unitdata(iafp->ipa_unit, &tp);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR, "Error %d parsing ID_RESP: %s\n", rc, msgb_hexdump(msg));
			goto out_err;
		}
		if (!iafp->ipa_unit->unit_name) {
			LOGPFSML(fi, LOGL_NOTICE, "No Unit Name specified by client\n");
			goto out_err;
		}
		as = osmo_ss7_as_find_by_name(asp->inst, iafp->ipa_unit->unit_name);
		if (!as) {
			LOGPFSML(fi, LOGL_NOTICE, "Cannot find any AS definition for IPA Unit Name '%s'\n",
				iafp->ipa_unit->unit_name);
			goto out_err;
		}
		rc = ss7_as_add_asp(as, asp);
		if (rc < 0) {
			LOGPFSML(fi, LOGL_ERROR, "Cannot add ASP '%s' to AS '%s'\n", asp->cfg.name, as->cfg.name);
			goto out_err;
		}
		/* TODO: OAP Authentication? */
		/* Send ID_ACK */
		if (fd >= 0) {
			ipaccess_send_id_ack(fd);
			osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_ACK2, 10, T_WAIT_ID_ACK);
			/* If we received the ACK beforehand, submit it now */
			if (iafp->ipa_id_ack_rcvd) {
				iafp->ipa_id_ack_rcvd = false;
				osmo_fsm_inst_dispatch(fi, IPA_ASP_E_ID_ACK, NULL);
			}
		}
		break;
	case IPA_ASP_E_ID_ACK:
		/* Since there's no official spec for IPA and some
		   implementations seem to like sending the IPA ID ACK before
		   the IPA ID RESP, let's catch it and feed it after we receive
		   the IPA ID RESP and we are in correct state */
		iafp->ipa_id_ack_rcvd = true;
		break;
	}
	return;
out_err:
	osmo_ss7_asp_disconnect(asp);
	return;
}

/* Server: We're waiting for an ID ACK */
static void ipa_asp_fsm_wait_id_ack2(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case IPA_ASP_E_ID_ACK:
		/* ACK received, we can go to active state now.  The
		 * ACTIVE onenter function will inform the AS */
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_ACTIVE, 0, 0);
		break;
	}
}

/* Client: We're waiting for an ID GET */
static void ipa_asp_fsm_wait_id_get(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_asp *asp = iafp->asp;
	struct msgb *msg_get, *msg_resp;
	const uint8_t *req_data;
	int data_len;
	int fd;

	switch (event) {
	case IPA_ASP_E_ID_GET:
		msg_get = data;
		req_data = msgb_l2(msg_get)+1;
		data_len = msgb_l2len(msg_get)-1;
		LOGPFSM(fi, "Received IPA CCM IDENTITY REQUEST for IEs %s\n",
			osmo_hexdump(req_data, data_len));
		/* avoid possible unsigned integer underflow, as ipa_ccm_make_id_resp_from_req()
		 * expects an unsigned integer, and in case of a zero-length L2 message we might
		 * have data_len == -1 here */
		if (data_len < 0)
			data_len = 0;
		/* Send ID_RESP to server */
		msg_resp = ipa_ccm_make_id_resp_from_req(iafp->ipa_unit, req_data, data_len);
		if (!msg_resp) {
			LOGPFSML(fi, LOGL_ERROR, "Error building IPA CCM IDENTITY RESPONSE\n");
			break;
		}
		osmo_ss7_asp_send(asp, msg_resp);
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_WAIT_ID_ACK, 10, T_WAIT_ID_ACK);
		break;
	case IPA_ASP_E_ID_ACK:
		/* Some SCCPLite MSCs are known to send an ACK directly instead
		 * of GET. Support them and skip the GET+RESP handshake by
		 * sending ACK2 to server directly */
		fd = get_fd_from_iafp(iafp);
		if (fd >= 0) {
			ipaccess_send_id_ack(fd);
			osmo_fsm_inst_state_chg(fi, IPA_ASP_S_ACTIVE, 0, 0);
		}
		break;
	}
}

/* Client: We're waiting for an ID ACK */
static void ipa_asp_fsm_wait_id_ack(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	int fd;

	switch (event) {
	case IPA_ASP_E_ID_ACK:
		/* Send ACK2 to server */
		fd = get_fd_from_iafp(iafp);
		if (fd >= 0) {
			ipaccess_send_id_ack(fd);
			osmo_fsm_inst_state_chg(fi, IPA_ASP_S_ACTIVE, 0, 0);
		}
		break;
	}
}

static void ipa_asp_fsm_active_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_asp *asp = iafp->asp;
	struct xua_as_event_asp_inactive_ind_pars pars = {
		.asp = asp,
		.asp_requires_notify = false,
	};

	/* Now we are done with IPA handshake, Start Hearbeat Procedure, T(beat): */
	ipa_t_beat_send(fi);

	dispatch_to_all_as(fi, XUA_ASPAS_ASP_INACTIVE_IND, &pars);
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_ACTIVE_IND, asp);
}

/* Server + Client: We're actively transmitting user data */
static void ipa_asp_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case XUA_ASP_E_M_ASP_DOWN_REQ:
	case XUA_ASP_E_M_ASP_INACTIVE_REQ:
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_DOWN, 0, 0);
		break;
	}
}

static void ipa_asp_fsm_inactive_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct xua_as_event_asp_inactive_ind_pars pars = {
		.asp = iafp->asp,
		.asp_requires_notify = false,
	};
	dispatch_to_all_as(fi, XUA_ASPAS_ASP_INACTIVE_IND, &pars);
}

static void ipa_asp_fsm_inactive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case XUA_ASP_E_M_ASP_DOWN_REQ:
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_DOWN, 0, 0);
		break;
	}
}

/* Assign a 4 bit SLS (as unqiue as possible) for incoming IPA PDUs.*/
static void _ipa_asp_pick_unused_sls(struct osmo_ss7_asp *asp, const struct osmo_ss7_as *as)
{
	for (unsigned int sls = 0; sls <= 0x0f; sls++) {
		bool used = false;
		struct ss7_as_asp_assoc *assoc;
		llist_for_each_entry(assoc, &as->assoc_asp_list, as_entry) {
			struct osmo_ss7_asp *asp_it = assoc->asp;
			if (asp_it == asp)
				continue;
			if (!asp_it->ipa.sls_assigned)
				continue;
			if (asp_it->ipa.sls == sls) {
				used = true;
				break;
			}
		}
		if (used)
			continue;
		/* Found an unused SLS, use it: */
		asp->ipa.sls = sls;
		asp->ipa.sls_assigned = true;
		LOGPASP(asp, DLSS7, LOGL_DEBUG, "Assigned unsued SLS = %u\n", sls);
		return;
	}
	LOGPASP(asp, DLSS7, LOGL_INFO, "All SLS in IPA AS picked, unique SLS not possible, picking random one\n");
	asp->ipa.sls = rand() & 0x0f;
	asp->ipa.sls_assigned = true;
}

static void ipa_asp_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;
	struct osmo_ss7_as *as;
	int fd;

	switch (event) {
	case XUA_ASP_E_SCTP_COMM_DOWN_IND:
	case XUA_ASP_E_SCTP_RESTART_IND:
		osmo_fsm_inst_state_chg(fi, IPA_ASP_S_DOWN, 0, 0);
		send_xlm_prim_simple(fi, OSMO_XLM_PRIM_M_ASP_DOWN,
				     PRIM_OP_INDICATION);
		break;
	case XUA_ASP_E_ASPSM_BEAT:
		/* PING -> PONG */
		fd = get_fd_from_iafp(iafp);
		if (fd >= 0)
			ipaccess_send_pong(fd);
		break;
	case XUA_ASP_E_ASPSM_BEAT_ACK:
		LOGPFSML(fi, LOGL_DEBUG, "Rx HEARTBEAT ACK\n");
		iafp->t_beat.unacked_beats = 0;
		break;
	case XUA_ASP_E_AS_ASSIGNED:
		as = data;
		osmo_talloc_replace_string(iafp->ipa_unit, &iafp->ipa_unit->unit_name, as->cfg.name);
		/* Now that AS is known, try picking an unused SLS inside the AS.
		 * It will be applied to PDUs received from the IPA socket. */
		_ipa_asp_pick_unused_sls(iafp->asp, as);
		/* Now that the AS is known, start the client side: */
		if (iafp->asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP && fi->state == IPA_ASP_S_DOWN) {
			LOGPFSML(fi, LOGL_NOTICE, "Bringing up ASP now once it has been assigned to an AS\n");
			osmo_fsm_inst_dispatch(fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
		}
		break;
	default:
		break;
	}
}

static int ipa_asp_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;

	LOGPFSML(fi, LOGL_ERROR, "Timeout waiting for peer response\n");
	/* kill ASP and (wait for) re-connect */
	osmo_ss7_asp_disconnect(iafp->asp);
	return -1;
}

static void ipa_asp_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct ipa_asp_fsm_priv *iafp = fi->priv;

	if (!iafp)
		return;

	ipa_t_beat_stop(fi);

	if (iafp->asp)
		iafp->asp->fi = NULL;
}

static const struct osmo_fsm_state ipa_asp_states[] = {
	[IPA_ASP_S_DOWN] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_UP_REQ) |
				 S(XUA_ASP_E_SCTP_EST_IND),
		.out_state_mask = S(IPA_ASP_S_WAIT_ID_GET) |
				  S(IPA_ASP_S_WAIT_ID_RESP),
		.name = "ASP_DOWN",
		.action = ipa_asp_fsm_down,
		.onenter = ipa_asp_fsm_down_onenter,
	},
	/* Server Side */
	[IPA_ASP_S_WAIT_ID_RESP] = {
		.in_event_mask = S(IPA_ASP_E_ID_RESP) |
				 S(IPA_ASP_E_ID_ACK),
		.out_state_mask = S(IPA_ASP_S_WAIT_ID_ACK2) |
				  S(IPA_ASP_S_DOWN),
		.name = "WAIT_ID_RESP",
		.action = ipa_asp_fsm_wait_id_resp,
	},
	/* Server Side */
	[IPA_ASP_S_WAIT_ID_ACK2] = {
		.in_event_mask = S(IPA_ASP_E_ID_ACK),
		.out_state_mask = S(IPA_ASP_S_ACTIVE) |
				  S(IPA_ASP_S_DOWN),
		.name = "WAIT_ID_ACK2",
		.action = ipa_asp_fsm_wait_id_ack2,
	},
	/* Client Side */
	[IPA_ASP_S_WAIT_ID_GET] = {
		.in_event_mask = S(IPA_ASP_E_ID_GET) |
				 S(IPA_ASP_E_ID_ACK), /* support broken MSCs skipping GET+RESP */
		.out_state_mask = S(IPA_ASP_S_WAIT_ID_ACK) |
				  S(IPA_ASP_S_ACTIVE),  /* support broken MSCs skipping GET+RESP */
		.name = "WAIT_ID_GET",
		.action = ipa_asp_fsm_wait_id_get,
	},
	/* Client Side */
	[IPA_ASP_S_WAIT_ID_ACK] = {
		.in_event_mask = S(IPA_ASP_E_ID_ACK),
		.out_state_mask = S(IPA_ASP_S_ACTIVE) |
				  S(IPA_ASP_S_DOWN),
		.name = "WAIT_ID_ACK",
		.action = ipa_asp_fsm_wait_id_ack,
	},
	[IPA_ASP_S_ACTIVE] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_DOWN_REQ) |
				 S(XUA_ASP_E_M_ASP_INACTIVE_REQ),
		.out_state_mask = S(IPA_ASP_S_DOWN) |
				  S(IPA_ASP_S_INACTIVE),
		.name = "ASP_ACTIVE",
		.action = ipa_asp_fsm_active,
		.onenter = ipa_asp_fsm_active_onenter,
	},
	[IPA_ASP_S_INACTIVE] = {
		.in_event_mask = S(XUA_ASP_E_M_ASP_DOWN_REQ),
		.out_state_mask = S(IPA_ASP_S_DOWN) |
				  S(IPA_ASP_S_ACTIVE),
		.name = "ASP_INACTIVE",
		.action = ipa_asp_fsm_inactive,
		.onenter = ipa_asp_fsm_inactive_onenter,
	},
};

struct osmo_fsm ipa_asp_fsm = {
	.name = "IPA_ASP",
	.states = ipa_asp_states,
	.num_states = ARRAY_SIZE(ipa_asp_states),
	.timer_cb = ipa_asp_fsm_timer_cb,
	.log_subsys = DLSS7,
	.event_names = xua_asp_event_names,
	.allstate_event_mask = S(XUA_ASP_E_SCTP_COMM_DOWN_IND) |
			       S(XUA_ASP_E_SCTP_RESTART_IND) |
			       S(XUA_ASP_E_ASPSM_BEAT) |
			       S(XUA_ASP_E_ASPSM_BEAT_ACK) |
			       S(XUA_ASP_E_AS_ASSIGNED),
	.allstate_action = ipa_asp_allstate,
	.cleanup = ipa_asp_fsm_cleanup,
};


/*! \brief Start a new ASP finite state machine for given ASP (stored on asp->fi)
 *  \param[in] asp Application Server Process for which to start FSM
 *  \param[in] log_level Logging Level for ASP FSM logging
 *  \returns 0 on success; negative on error */
static int ipa_asp_fsm_start(struct osmo_ss7_asp *asp, int log_level)
{
	struct osmo_fsm_inst *fi;
	struct ipa_asp_fsm_priv *iafp;
	struct osmo_ss7_as *as = ss7_asp_get_first_as(asp);
	const char *unit_name;
	bool can_start = true;

	/* allocate as child of AS? */
	fi = osmo_fsm_inst_alloc(&ipa_asp_fsm, asp, NULL, log_level, asp->cfg.name);
	if (!fi)
		return -EINVAL;

	iafp = talloc_zero(fi, struct ipa_asp_fsm_priv);
	if (!iafp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return -ENOMEM;
	}

	if (as) {
		unit_name = as->cfg.name;
		/* Allocacate potentially unique SLS within AS since AS is already known: */
		_ipa_asp_pick_unused_sls(asp, as);
	} else if (asp->dyn_allocated) {
		LOGPFSML(fi, LOGL_INFO, "Dynamic ASP is not assigned to any AS, "
			 "using ASP name instead of AS name as ipa_unit_name\n");
		unit_name = asp->cfg.name;
		/* asp->ipa.sls will be assigned together with AS unit_name during XUA_ASP_E_AS_ASSIGNED. */
	} else {
		/* ASP in client mode will be brought up when this ASP is added
		 * to an AS, see XUA_ASP_E_AS_ASSIGNED. */
		if (asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP) {
			LOGPFSML(fi, LOGL_NOTICE, "ASP is not assigned to any AS. ASP bring up delayed\n");
			can_start = false;
		}
		unit_name = asp->cfg.name;
		/* asp->ipa.sls will be assigned together with AS unit_name during XUA_ASP_E_AS_ASSIGNED. */
	}

	iafp->asp = asp;
	iafp->ipa_unit = talloc_zero(iafp, struct ipaccess_unit);
	iafp->ipa_unit->unit_name = talloc_strdup(iafp->ipa_unit, unit_name);
	osmo_timer_setup(&iafp->t_beat.timer, ipa_t_beat_cb, fi);

	fi->priv = iafp;

	/* Attach FSM to ASP: */
	asp->fi = fi;

	if (can_start && asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP)
		osmo_fsm_inst_dispatch(fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);

	return 0;
}
