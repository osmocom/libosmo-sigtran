/* Default XUA Layer Manager */
/* (C) 2017-2021 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* The idea of this default Layer Manager is as follows:
 * - we wait until a SCTP connection is established
 * - we issue the ASP-UP request and wait for the ASP being in UP state
 * - we wait if we receive a M-NOTIFY indication about any AS in this ASP
 * - if that's not received, we use RKM to register a routing context
 *   for our locally configured ASP and expect a positive registration
 *   result as well as a NOTIFY indication about AS-ACTIVE afterwards.
 */

#include <errno.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "xua_internal.h"
#include "xua_asp_fsm.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_xua_srv.h"

#define S(x)	(1 << (x))

enum lm_state {
	/* idle state, SCTP not connected */
	S_IDLE,
	/* we're waiting for the ASP-UP to be confirmed */
	S_WAIT_ASP_UP,
	/* we are waiting for any NOTIFY about an AS in this ASP */
	S_WAIT_NOTIFY,
	/* we've sent a RK REG REQ and wait for the result */
	S_RKM_REG,
	/* all systems up, we're communicating */
	S_ACTIVE,
};

enum lm_event {
	LM_E_SCTP_EST_IND,
	LM_E_ASP_UP_CONF,
	LM_E_ASP_UP_IND,
	LM_E_ASP_ACT_IND,
	LM_E_ASP_INACT_IND,
	LM_E_NOTIFY_IND,
	LM_E_AS_INACTIVE_IND,
	LM_E_AS_ACTIVE_IND,
	LM_E_AS_STATUS_IND,
	LM_E_RKM_REG_CONF,
	LM_E_SCTP_DISC_IND,
};

static const struct value_string lm_event_names[] = {
	{ LM_E_SCTP_EST_IND,	"SCTP-ESTABLISH.ind" },
	{ LM_E_ASP_UP_CONF,	"ASP-UP.conf" },
	{ LM_E_ASP_UP_IND,	"ASP-UP.ind" },
	{ LM_E_ASP_ACT_IND,	"ASP-ACT.ind" },
	{ LM_E_ASP_INACT_IND,	"ASP-INACT.ind" },
	{ LM_E_NOTIFY_IND,	"NOTIFY.ind" },
	{ LM_E_AS_INACTIVE_IND,	"AS-INACTIVE.ind" },
	{ LM_E_AS_ACTIVE_IND,	"AS-ACTIVE.ind" },
	{ LM_E_AS_STATUS_IND,	"AS-STATUS.ind" },
	{ LM_E_RKM_REG_CONF,	"RKM_REG.conf" },
	{ LM_E_SCTP_DISC_IND,	"SCTP-RELEASE.ind" },
	{ 0, NULL }
};

/***********************************************************************
 * Timer Handling
 ***********************************************************************/

const struct osmo_tdef ss7_asp_lm_timer_defaults[SS7_ASP_LM_TIMERS_LEN] = {
	{ .T = SS7_ASP_LM_T_WAIT_ASP_UP,	.default_val = 20,	.unit = OSMO_TDEF_S,
	  .desc = "Restart ASP after timeout waiting for ASP UP (SG role) / ASP UP ACK (ASP role) (s)" },
	{ .T = SS7_ASP_LM_T_WAIT_NOTIFY,	.default_val = 2,	.unit = OSMO_TDEF_S,
	  .desc = "Restart ASP after timeout waiting for NOTIFY (s)" },
	{ .T = SS7_ASP_LM_T_WAIT_NOTIY_RKM,	.default_val = 20,	.unit = OSMO_TDEF_S,
	  .desc = "Restart ASP after timeout waiting for NOTIFY after RKM registration (s)" },
	{ .T = SS7_ASP_LM_T_WAIT_RK_REG_RESP,	.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Restart ASP after timeout waiting for RK_REG_RESP (s)" },
	{}
};

/* Appendix C.4 of ITU-T Q.714 */
const struct value_string ss7_asp_lm_timer_names[] = {
	{ SS7_ASP_LM_T_WAIT_ASP_UP, "wait_asp_up" },
	{ SS7_ASP_LM_T_WAIT_NOTIFY, "wait_notify" },
	{ SS7_ASP_LM_T_WAIT_NOTIY_RKM, "wait_notify_rkm" },
	{ SS7_ASP_LM_T_WAIT_RK_REG_RESP, "wait_rk_reg_resp" },
	{}
};

osmo_static_assert(ARRAY_SIZE(ss7_asp_lm_timer_defaults) == (SS7_ASP_LM_TIMERS_LEN) &&
		   ARRAY_SIZE(ss7_asp_lm_timer_names) == (SS7_ASP_LM_TIMERS_LEN),
		   assert_ss7_asp_lm_timer_count);

static const struct osmo_tdef_state_timeout lm_fsm_timeouts[32] = {
	[S_IDLE]	= { },
	[S_WAIT_ASP_UP]	= { .T = SS7_ASP_LM_T_WAIT_ASP_UP },
	[S_WAIT_NOTIFY]	= { .T = SS7_ASP_LM_T_WAIT_NOTIFY }, /* SS7_ASP_LM_T_WAIT_NOTIY_RKM if coming from S_RKM_REG */
	[S_RKM_REG]	= { .T = SS7_ASP_LM_T_WAIT_RK_REG_RESP },
	[S_ACTIVE]	= { },
};

struct xua_layer_manager_default_priv {
	struct osmo_ss7_asp *asp;
	struct osmo_fsm_inst *fi;
};

#define lm_fsm_state_chg(fi, NEXT_STATE) \
	osmo_tdef_fsm_inst_state_chg(fi, NEXT_STATE, \
				     lm_fsm_timeouts, \
				    ((struct xua_layer_manager_default_priv *)(fi->priv))->asp->cfg.T_defs_lm, \
				     -1)

#define ENSURE_ROLE_COND(fi, event, cond)						\
	do {									\
		struct xua_layer_manager_default_priv *_lmp = fi->priv;		\
		enum osmo_ss7_asp_role _role = _lmp->asp->cfg.role;		\
		if (!(cond)) {				\
			LOGPFSML(fi, LOGL_ERROR, "event %s not permitted "	\
				 "in role %s\n",				\
				 osmo_fsm_event_name(fi->fsm, event),		\
				 get_value_string(osmo_ss7_asp_role_names, _role));\
			return;							\
		}								\
	} while (0)

#define ENSURE_IPSP(fi, event) \
	ENSURE_ROLE_COND(fi, event, _role == OSMO_SS7_ASP_ROLE_IPSP)

#define ENSURE_ASP_OR_IPSP(fi, event) \
	ENSURE_ROLE_COND(fi, event, _role == OSMO_SS7_ASP_ROLE_ASP || _role == OSMO_SS7_ASP_ROLE_IPSP)

#define ENSURE_SG_OR_IPSP(fi, event) \
	ENSURE_ROLE_COND(fi, event, _role == OSMO_SS7_ASP_ROLE_SG || _role == OSMO_SS7_ASP_ROLE_IPSP)

/* handle an incoming RKM registration response */
static int handle_reg_conf(struct osmo_fsm_inst *fi, uint32_t l_rk_id, uint32_t rctx)
{
	struct xua_layer_manager_default_priv *lmp = fi->priv;
	struct osmo_ss7_asp *asp = lmp->asp;
	struct osmo_ss7_as *as;

	/* update the application server with the routing context as
	 * allocated/registered by the SG */
	as = osmo_ss7_as_find_by_l_rk_id(asp->inst, l_rk_id);
	if (!as) {
		LOGPFSM(fi, "RKM Result for unknown l_rk_id %u\n", l_rk_id);
		return -EINVAL;
	}
	as->cfg.routing_key.context = rctx;

	return 0;
}

static void reg_req_all_assoc_as(struct osmo_ss7_asp *asp)
{
	struct ss7_as_asp_assoc *assoc;
	llist_for_each_entry(assoc, &asp->assoc_as_list, asp_entry) {
		struct osmo_ss7_as *as = assoc->as;
		struct osmo_xlm_prim *prim;
		prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_REQUEST);
		OSMO_ASSERT(prim);
		prim->u.rk_reg.key = as->cfg.routing_key;
		prim->u.rk_reg.traf_mode = as->cfg.mode;
		osmo_xlm_sap_down(asp, &prim->oph);
	}
}

static void lm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_layer_manager_default_priv *lmp = fi->priv;

	switch (event) {
	case LM_E_SCTP_EST_IND:
		if (lmp->asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP ||
		    lmp->asp->cfg.role == OSMO_SS7_ASP_ROLE_IPSP) {
			/* Try to transition to ASP-UP, wait to receive message for a few seconds */
			lm_fsm_state_chg(fi, S_WAIT_ASP_UP);
			osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
		}
		/* role SG: Unimplemented, do nothing, stay in this state forever. */
		break;
	}
}

static void lm_wait_asp_up(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case LM_E_ASP_UP_CONF:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* ASP is up, wait for some time if any NOTIFY
		 * indications about AS in this ASP are received */
		lm_fsm_state_chg(fi, S_WAIT_NOTIFY);
		break;
	case LM_E_ASP_UP_IND:
		ENSURE_SG_OR_IPSP(fi, event);
		/* ASP is up, wait for some time if any NOTIFY
		* indications about AS in this ASP are received.
		*/
		lm_fsm_state_chg(fi, S_WAIT_NOTIFY);
		break;
	}
}

static void lm_wait_notify(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_layer_manager_default_priv *lmp = fi->priv;
	struct osmo_xlm_prim *oxp = data;

	switch (event) {
	case LM_E_ASP_UP_CONF:
		ENSURE_ASP_OR_IPSP(fi, event);
		/* in IPSP, we may receive a ASP-UP ACK for the ASP-UP we sent,
		 * _after_ we received the ASP-UP from the peer in state
		 * WAIT_ASP_UP. Ignore it. */
		break;
	case LM_E_NOTIFY_IND:
		ENSURE_ASP_OR_IPSP(fi, event);
		OSMO_ASSERT(oxp->oph.primitive == OSMO_XLM_PRIM_M_NOTIFY);
		OSMO_ASSERT(oxp->oph.operation == PRIM_OP_INDICATION);

		/* Not handling/interested in other status changes for now. */
		if (oxp->u.notify.status_type != M3UA_NOTIFY_T_STATCHG)
			break;

		/* Don't change active ASP if there's already one active. */
		if (ss7_asp_determine_traf_mode(lmp->asp) == OSMO_SS7_AS_TMOD_OVERRIDE &&
		    oxp->u.notify.status_info == M3UA_NOTIFY_I_AS_ACT)
			break;

		lm_fsm_state_chg(fi, S_ACTIVE);
		osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		break;
	case LM_E_ASP_ACT_IND:
		ENSURE_SG_OR_IPSP(fi, event);
		lm_fsm_state_chg(fi, S_ACTIVE);
		break;
	case LM_E_AS_INACTIVE_IND:
		/* we now know that an AS is associated with this ASP at
		 * the SG, and that this AS is currently inactive */
		/* request the ASP to go into active state (which
		 * hopefully will bring the AS to active, too) */
		lm_fsm_state_chg(fi, S_ACTIVE);
		if (lmp->asp->cfg.role != OSMO_SS7_ASP_ROLE_SG)
			osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		break;
	}
};

static void lm_rkm_reg(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_layer_manager_default_priv *lmp = fi->priv;
	struct osmo_xlm_prim *oxp;
	int rc;

	switch (event) {
	case LM_E_RKM_REG_CONF:
		oxp = data;
		if (oxp->u.rk_reg.status != M3UA_RKM_REG_SUCCESS) {
			LOGPFSML(fi, LOGL_NOTICE, "Received RKM_REG_RSP with negative result\n");
			ss7_asp_disconnect_stream(lmp->asp);
		} else {
			unsigned long timeout_sec;
			rc = handle_reg_conf(fi, oxp->u.rk_reg.key.l_rk_id, oxp->u.rk_reg.key.context);
			if (rc < 0)
				ss7_asp_disconnect_stream(lmp->asp);
			/* RKM registration was successful, we can transition to WAIT_NOTIFY
			 * state and assume that an NOTIFY/AS-INACTIVE arrives within
			 * T_WAIT_NOTIFY_RKM seconds */
			timeout_sec = osmo_tdef_get(lmp->asp->cfg.T_defs_lm, SS7_ASP_LM_T_WAIT_NOTIY_RKM, OSMO_TDEF_S, -1);
			osmo_fsm_inst_state_chg(fi, S_WAIT_NOTIFY, timeout_sec, SS7_ASP_LM_T_WAIT_NOTIY_RKM);
		}
		break;
	}
}

static void lm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_layer_manager_default_priv *lmp = fi->priv;
	struct osmo_xlm_prim *oxp;

	switch (event) {
	case LM_E_ASP_ACT_IND:
		/* This may come in IPSP if we received ASPAC from peer before it answered our ASPAC: */
		ENSURE_IPSP(fi, event);
		break;
	case LM_E_AS_INACTIVE_IND:
		/* request the ASP to go into active state */
		osmo_fsm_inst_dispatch(lmp->asp->fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		break;
	case LM_E_NOTIFY_IND:
		oxp = data;
		OSMO_ASSERT(oxp->oph.primitive == OSMO_XLM_PRIM_M_NOTIFY);
		OSMO_ASSERT(oxp->oph.operation == PRIM_OP_INDICATION);
		if (oxp->u.notify.status_type == M3UA_NOTIFY_T_STATCHG &&
		    oxp->u.notify.status_info != M3UA_NOTIFY_I_AS_ACT)
			lm_fsm_state_chg(fi, S_IDLE);
		break;
	}
}

static void lm_allstate(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case LM_E_SCTP_DISC_IND:
		lm_fsm_state_chg(fi, S_IDLE);
		break;
	}
}

static int lm_timer_cb(struct osmo_fsm_inst *fi)
{
	struct xua_layer_manager_default_priv *lmp = fi->priv;

	switch (fi->T) {
	case SS7_ASP_LM_T_WAIT_ASP_UP:
		/* we have been waiting for the ASP to come up, but it
		 * failed to do so */
		LOGPFSML(fi, LOGL_NOTICE, "Peer didn't send any ASP_UP in time! Restarting ASP\n");
		ss7_asp_disconnect_stream(lmp->asp);
		break;
	case SS7_ASP_LM_T_WAIT_NOTIFY:
		if (lmp->asp->cfg.quirks & OSMO_SS7_ASP_QUIRK_NO_NOTIFY) {
			/* some implementations don't send the NOTIFY which they SHOULD
			 * according to RFC4666 (see OS#5145) */
			LOGPFSM(fi, "quirk no_notify active; locally emulate AS-INACTIVE.ind\n");
			osmo_fsm_inst_dispatch(fi, LM_E_AS_INACTIVE_IND, NULL);
			break;
		}
		/* No AS has reported via NOTIFY that is was
		 * (statically) configured at the SG for this ASP, so
		 * let's dynamically register */
		lm_fsm_state_chg(fi, S_RKM_REG);
		reg_req_all_assoc_as(lmp->asp);
		break;
	case SS7_ASP_LM_T_WAIT_NOTIY_RKM:
		/* No AS has reported via NOTIFY even after dynamic RKM
		 * configuration */
		ss7_asp_disconnect_stream(lmp->asp);
		break;
	case SS7_ASP_LM_T_WAIT_RK_REG_RESP:
		/* timeout of registration of routing key */
		ss7_asp_disconnect_stream(lmp->asp);
		break;
	}
	return 0;
}

static const struct osmo_fsm_state lm_states[] = {
	[S_IDLE] = {
		.in_event_mask = S(LM_E_SCTP_EST_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_WAIT_ASP_UP),
		.name = "IDLE",
		.action = lm_idle,
	},
	[S_WAIT_ASP_UP] = {
		.in_event_mask = S(LM_E_ASP_UP_CONF) |
				 S(LM_E_ASP_UP_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_WAIT_NOTIFY),
		.name = "WAIT_ASP_UP",
		.action = lm_wait_asp_up,
	},
	[S_WAIT_NOTIFY] = {
		.in_event_mask = S(LM_E_AS_INACTIVE_IND) |
				 S(LM_E_ASP_ACT_IND) |
				 S(LM_E_NOTIFY_IND) |
				 S(LM_E_ASP_UP_CONF),
		.out_state_mask = S(S_IDLE) |
				  S(S_RKM_REG) |
				  S(S_ACTIVE),
		.name = "WAIT_NOTIFY",
		.action = lm_wait_notify,
	},
	[S_RKM_REG] = {
		.in_event_mask = S(LM_E_RKM_REG_CONF),
		.out_state_mask = S(S_IDLE) |
				  S(S_WAIT_NOTIFY),
		.name = "RKM_REG",
		.action = lm_rkm_reg,
	},
	[S_ACTIVE] = {
		.in_event_mask = S(LM_E_ASP_ACT_IND) |
				 S(LM_E_AS_INACTIVE_IND) |
				 S(LM_E_NOTIFY_IND),
		.out_state_mask = S(S_IDLE),
		.name = "ACTIVE",
		.action = lm_active,
	},
};

/* Map from incoming XLM SAP primitives towards FSM events */
static const struct osmo_prim_event_map lm_event_map[] = {
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_SCTP_ESTABLISH, PRIM_OP_INDICATION, LM_E_SCTP_EST_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_INDICATION, LM_E_SCTP_DISC_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_ASP_UP, PRIM_OP_CONFIRM, LM_E_ASP_UP_CONF },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_ASP_UP, PRIM_OP_INDICATION, LM_E_ASP_UP_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_ASP_ACTIVE, PRIM_OP_INDICATION, LM_E_ASP_ACT_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_ASP_INACTIVE, PRIM_OP_INDICATION, LM_E_ASP_INACT_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_AS_STATUS, PRIM_OP_INDICATION, LM_E_AS_STATUS_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_NOTIFY, PRIM_OP_INDICATION, LM_E_NOTIFY_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_AS_INACTIVE, PRIM_OP_INDICATION, LM_E_AS_INACTIVE_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_AS_ACTIVE, PRIM_OP_INDICATION, LM_E_AS_ACTIVE_IND },
	{ XUA_SAP_LM, OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_CONFIRM, LM_E_RKM_REG_CONF },
	{ 0, 0, 0, OSMO_NO_EVENT },
};


struct osmo_fsm xua_default_lm_fsm = {
	.name = "xua_default_lm",
	.states = lm_states,
	.num_states = ARRAY_SIZE(lm_states),
	.timer_cb = lm_timer_cb,
	.event_names = lm_event_names,
	.allstate_event_mask = S(LM_E_SCTP_DISC_IND),
	.allstate_action = lm_allstate,
	.log_subsys = DLSS7,
};


/* layer manager primitive call-back function, registered osmo_ss7 */
static int default_lm_prim_cb(struct osmo_prim_hdr *oph, void *_asp)
{
	struct osmo_ss7_asp *asp = _asp;
	struct xua_layer_manager_default_priv *lmp = asp->lm->priv;
	struct osmo_fsm_inst *fi = lmp->fi;
	uint32_t event = osmo_event_for_prim(oph, lm_event_map);
	char *prim_name = osmo_xlm_prim_name(oph);

	LOGPFSM(fi, "Received primitive %s\n", prim_name);

	if (event == OSMO_NO_EVENT) {
		LOGPFSML(fi, LOGL_NOTICE, "Ignoring primitive %s\n", prim_name);
		return 0;
	}

	osmo_fsm_inst_dispatch(fi, event, oph);

	return 0;
}

void xua_layer_manager_default_free(struct osmo_xua_layer_manager *lm)
{
	if (!lm)
		return;
	if (lm->priv) {
		struct xua_layer_manager_default_priv *lmp = lm->priv;
		osmo_fsm_inst_term(lmp->fi, OSMO_FSM_TERM_ERROR, NULL);
		talloc_free(lmp);
		lm->priv = NULL;
	}
	talloc_free(lm);
}

struct osmo_xua_layer_manager *xua_layer_manager_default_alloc(struct osmo_ss7_asp *asp)
{
	struct osmo_xua_layer_manager *lm;
	struct xua_layer_manager_default_priv *lmp;

	lm = talloc_zero(asp, struct osmo_xua_layer_manager);
	OSMO_ASSERT(lm);

	lmp = talloc_zero(lm, struct xua_layer_manager_default_priv);
	OSMO_ASSERT(lmp);
	lmp->asp = asp;
	lmp->fi = osmo_fsm_inst_alloc(&xua_default_lm_fsm, lmp, lmp, LOGL_DEBUG, asp->cfg.name);
	if (!lmp->fi) {
		talloc_free(lm);
		return NULL;
	}

	lm->prim_cb = default_lm_prim_cb;
	lm->free_func = xua_layer_manager_default_free;
	lm->priv = lmp;

	return lm;
}
