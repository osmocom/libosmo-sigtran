/* SCCP M3UA / SUA AS osmo_fsm according to RFC3868 4.3.1 / RFC4666 4.3.2 */
/* (C) Copyright 2017 by Harald Welte <laforge@gnumonks.org>
 *
 * All Rights reserved.
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * Based on Erlang implementation xua_as_fsm.erl in osmo-ss7.git
 */

#include <string.h>
#include <arpa/inet.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>
#include "xua_msg.h"
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <sys/types.h>

#include "sccp_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_combined_linkset.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"
#include "xua_internal.h"

static struct msgb *encode_notify(const struct osmo_xlm_prim_notify *npar)
{
	struct xua_msg *xua = m3ua_encode_notify(npar);
	struct msgb *msg = xua_to_msg(M3UA_VERSION, xua);
	xua_msg_free(xua);
	return msg;
}

static int fill_notify_route_ctx(const struct osmo_ss7_asp *asp, struct osmo_xlm_prim_notify *npar)
{
	npar->route_ctx_count = ss7_asp_get_all_rctx(asp, npar->route_ctx, ARRAY_SIZE(npar->route_ctx), NULL);
	if (npar->route_ctx_count > 0)
		npar->presence |= NOTIFY_PAR_P_ROUTE_CTX;
	return 0;
}

static void tx_notify(struct osmo_ss7_asp *asp, struct osmo_xlm_prim_notify *npar)
{
	const char *type_name, *info_name, *info_str;
	type_name = get_value_string(m3ua_ntfy_type_names, npar->status_type);
	info_name = m3ua_ntfy_info_name(npar->status_type, npar->status_info);
	info_str = npar->info_string ? npar->info_string : "";

	LOGPASP(asp, DLSS7, LOGL_INFO, "Tx NOTIFY Type %s:%s (%s)\n",
		type_name, info_name, info_str);
	fill_notify_route_ctx(asp, npar);
	struct msgb *msg = encode_notify(npar);
	osmo_ss7_asp_send(asp, msg);
}

/* RFC 4666 4.5.1: "For the particular case that an ASP becomes active for an AS and
 * destinations normally accessible to the AS are inaccessible, restricted, or congested,
 * the SG MAY send DUNA, DRST, or SCON messages for the inaccessible, restricted, or
 * congested destinations to the ASP newly active for the AS to prevent the ASP from
 * sending traffic for destinations that it might not otherwise know that are inaccessible,
 * restricted, or congested" */
static void as_tx_duna_during_asp_act(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_instance *inst = as->inst;
	struct osmo_ss7_route_table *rtbl = inst->rtable_system;
	struct osmo_ss7_as *as_it;
	uint32_t aff_pc[32];
	unsigned int num_aff_pc = 0;
	uint32_t rctx_be = htonl(as->cfg.routing_key.context);

	/* Send up to 32 PC per DUNA: */
	llist_for_each_entry(as_it, &inst->as_list, list) {
		if (as == as_it)
			continue;
		if (ss7_route_table_dpc_is_accessible_skip_as(rtbl, as_it->cfg.routing_key.pc, as))
			continue;
		aff_pc[num_aff_pc++] = htonl(as_it->cfg.routing_key.pc); /* mask = 0 */
		if (num_aff_pc == ARRAY_SIZE(aff_pc)) {
			xua_tx_snm_available(asp, &rctx_be, 1,
					     aff_pc, num_aff_pc,
					     "RFC4666 4.5.1", false);
			num_aff_pc = 0;
		}
	}
	if (num_aff_pc > 0)
		xua_tx_snm_available(asp, &rctx_be, 1,
				     aff_pc, num_aff_pc,
				     "RFC4666 4.5.1", false);
}

static int as_notify_all_asp(struct osmo_ss7_as *as, struct osmo_xlm_prim_notify *npar)
{
	struct msgb *msg;
	unsigned int i, sent = 0;
	const char *type_name, *info_name, *info_str;

	/* we don't send notify to IPA peers! */
	if (as->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
		return 0;

	type_name = get_value_string(m3ua_ntfy_type_names, npar->status_type);
	info_name = m3ua_ntfy_info_name(npar->status_type, npar->status_info);
	info_str = npar->info_string ? npar->info_string : "";
	LOGPFSM(as->fi, "Broadcasting NOTIFY Type %s:%s (%s) to all non-DOWN ASPs\n",
		type_name, info_name, info_str);

	/* iterate over all non-DOWN ASPs and send them the message */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];

		if (!asp)
			continue;

		/* NOTIFY are only sent by SG or IPSP role */
		if (asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP)
			continue;

		if (!asp->fi || asp->fi->state == XUA_ASP_S_DOWN)
			continue;

		/* Optional: ASP Identifier (if sent in ASP-UP) */
		if (asp->remote_asp_id_present) {
			npar->presence |= NOTIFY_PAR_P_ASP_ID;
			npar->asp_id = asp->remote_asp_id;
		} else
			npar->presence &= ~NOTIFY_PAR_P_ASP_ID;

		/* TODO: Optional Routing Context */

		LOGPASP(asp, DLSS7, LOGL_INFO, "Tx NOTIFY Type %s:%s (%s)\n",
			type_name, info_name, info_str);
		fill_notify_route_ctx(asp, npar);
		msg = encode_notify(npar);
		osmo_ss7_asp_send(asp, msg);
		sent++;
	}

	return sent;
}

static struct msgb *xua_as_encode_msg(const struct osmo_ss7_as *as, struct xua_msg *xua)
{
	switch (as->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		return m3ua_to_msg(xua);
	case OSMO_SS7_ASP_PROT_IPA:
		return ipa_to_msg(xua);
	default:
		OSMO_ASSERT(0);
	}
}

int xua_as_transmit_msg_broadcast(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;
	struct msgb *msg;
	struct msgb *msg_cpy;
	bool sent = false;

	msg = xua_as_encode_msg(as, xua);
	OSMO_ASSERT(msg);

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (!asp || !osmo_ss7_asp_active(asp))
			continue;
		msg_cpy = msgb_copy(msg, "xua_bcast_cpy");
		if (osmo_ss7_asp_send(asp, msg_cpy) == 0)
			sent = true;
	}

	msgb_free(msg);
	xua_msg_free(xua);
	return sent ? 0 : -1;
}

/* actually transmit a message through this AS */
int xua_as_transmit_msg(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct osmo_ss7_asp *asp = NULL;
	struct msgb *msg;

	switch (as->cfg.mode) {
	case OSMO_SS7_AS_TMOD_OVERRIDE:
	case OSMO_SS7_AS_TMOD_LOADSHARE:
		/* TODO: OSMO_SS7_AS_TMOD_LOADSHARE: actually use the SLS value
		 * in xua->mtp.sls to ensure same SLS goes through same ASP. Not
		 * strictly required by M3UA RFC, but would fit the overall
		 * principle. */
	case OSMO_SS7_AS_TMOD_ROUNDROBIN:
		asp = ss7_as_select_asp(as, xua);
		break;
	case OSMO_SS7_AS_TMOD_BCAST:
		return xua_as_transmit_msg_broadcast(as, xua);
	case _NUM_OSMO_SS7_ASP_TMOD:
		OSMO_ASSERT(false);
	}

	if (!asp) {
		LOGPFSM(as->fi, "No ASP in AS, dropping message\n");
		xua_msg_free(xua);
		return -1;
	}

	msg = xua_as_encode_msg(as, xua);
	OSMO_ASSERT(msg);
	xua_msg_free(xua);
	return osmo_ss7_asp_send(asp, msg);
}


/***********************************************************************
 * Actual FSM
 ***********************************************************************/

#define S(x)	(1 << (x))

#define MSEC_TO_S_US(x)		(x/1000), ((x%1000)*10)

static const struct value_string xua_as_event_names[] = {
	{ XUA_ASPAS_ASP_INACTIVE_IND, 	"ASPAS-ASP_INACTIVE.ind" },
	{ XUA_ASPAS_ASP_DOWN_IND,	"ASPAS-ASP_DOWN.ind" },
	{ XUA_ASPAS_ASP_ACTIVE_IND,	"ASPAS-ASP_ACTIVE.ind" },
	{ XUA_AS_E_RECOVERY_EXPD,	"AS-T_REC_EXPD.ind" },
	{ XUA_AS_E_TRANSFER_REQ,	"AS-TRANSFER.req" },
	{ 0, NULL }
};

struct xua_as_fsm_priv {
	struct osmo_ss7_as *as;
	struct { /* RFC4666 recovery timer T(r) */
		struct osmo_timer_list t_r;
		struct llist_head queued_xua_msgs;
	} recovery;
};

static void fill_notify_statchg_pars(const struct osmo_fsm_inst *fi, struct osmo_xlm_prim_notify *npar)
{
	*npar = (struct osmo_xlm_prim_notify){
		.status_type = M3UA_NOTIFY_T_STATCHG,
	};

	switch (fi->state) {
	case XUA_AS_S_INACTIVE:
		npar->status_info = M3UA_NOTIFY_I_AS_INACT;
		break;
	case XUA_AS_S_ACTIVE:
		npar->status_info = M3UA_NOTIFY_I_AS_ACT;
		break;
	case XUA_AS_S_PENDING:
		npar->status_info = M3UA_NOTIFY_I_AS_PEND;
		break;
	case XUA_AS_S_DOWN:
	default:
		/* Nothing will be sent anyway... */
		return;
	}
}

/* is any other ASP in this AS in state != DOWN? */
static bool check_any_other_asp_not_down(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp_cmp)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;

		if (asp_cmp == asp)
			continue;

		if (asp->fi && asp->fi->state != XUA_ASP_S_DOWN)
			return true;
	}

	return false;
}

/* is any other ASP in this AS in state ACTIVE? */
static bool check_any_other_asp_in_active(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp_cmp)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;

		if (asp_cmp == asp)
			continue;

		if (asp->fi && asp->fi->state == XUA_ASP_S_ACTIVE)
			return true;
	}

	return false;
}

/* RFC4666 4.3.4.3 "Alternate ASP_Active":
 * Tell other previously-active ASPs that a new ASP has been activated and mark
 * them as inactive. Used in override mode when an ASP becomes active."
 * */
static void notify_any_other_active_asp_as_inactive(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp_cmp)
{
	unsigned int i;
	struct msgb *msg;
	struct osmo_xlm_prim_notify npar = {
		.status_type = M3UA_NOTIFY_T_OTHER,
		.status_info = M3UA_NOTIFY_I_OT_ALT_ASP_ACT,
	};

	if (asp_cmp->remote_asp_id_present)
		npar.asp_id = asp_cmp->remote_asp_id;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp || !osmo_ss7_asp_active(asp))
			continue;

		if (asp_cmp == asp)
			continue;

		if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
			msg = encode_notify(&npar);
			osmo_ss7_asp_send(asp, msg);
		}

		osmo_fsm_inst_state_chg(asp->fi, XUA_ASP_S_INACTIVE, 0, 0);
	}

	return;
}

static void t_r_callback(void *_fi)
{
	struct osmo_fsm_inst *fi = _fi;
	osmo_fsm_inst_dispatch(fi, XUA_AS_E_RECOVERY_EXPD, NULL);
}

static void xua_as_fsm_down(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case XUA_ASPAS_ASP_INACTIVE_IND:
		/* one ASP transitions into ASP-INACTIVE */
		osmo_fsm_inst_state_chg(fi, XUA_AS_S_INACTIVE, 0, 0);
		break;
	case XUA_ASPAS_ASP_DOWN_IND:
		/* ignore */
		break;
	}
}

/* AS became inactive, trigger SNM PC unavailability for PCs it served: */
static void as_snm_pc_unavailable(struct osmo_ss7_as *as)
{
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_ss7_route_table *rtbl = s7i->rtable_system;
	struct osmo_ss7_combined_linkset *clset;
	struct osmo_ss7_route *rt;
	uint32_t aff_pc;

	LOGPAS(as, DLSS7, LOGL_INFO, "AS became inactive, some routes to remote PCs may have become unavailable\n");
	/* we assume the combined_links are sorted by mask length, i.e. more
	 * specific combined links first, and less specific combined links with shorter
	 * mask later */
	llist_for_each_entry(clset, &rtbl->combined_linksets, list) {
		llist_for_each_entry(rt, &clset->routes, list) {
			if (rt->dest.as != as)
				continue;
			if (rt->status == OSMO_SS7_ROUTE_STATUS_UNAVAILABLE)
				continue; /* Route was not available before regardless of AS state... */
			if (ss7_route_is_summary(rt))
				continue; /* Only announce changes for fully qualified routes */
			/* We found a PC served by the AS which went down. If no
			 * alternative route is still in place now towards that PC, announce unavailability
			 * to upper layers. */
			if (ss7_route_table_dpc_is_accessible(rtbl, rt->cfg.pc))
				continue;
			LOGPAS(as, DLSS7, LOGL_INFO, "AS became inactive => remote pc=%u=%s is now unavailable\n",
			       rt->cfg.pc, osmo_ss7_pointcode_print(s7i, rt->cfg.pc));
			aff_pc = htonl(rt->cfg.pc);
			xua_snm_pc_available(as, &aff_pc, 1, NULL, false);
		}
	}

	/* Generate PC unavailability indications for PCs in the sccp address-book.
	 * These are generally PCs the user wants to get information about, and
	 * they may have no fully-qualified route because:
	 * - user may have not configured such fully qualified route, but a
	 *   summary route (eg. 0.0.0/0 default route).
	 * - peer SG may have not announced them (DAVA/DUNA).
	 */
	struct osmo_sccp_addr_entry *entry;
	llist_for_each_entry(entry, &s7i->cfg.sccp_address_book, list) {
		if (!(entry->addr.presence & OSMO_SCCP_ADDR_T_PC))
			continue;
		if (osmo_ss7_pc_is_local(s7i, entry->addr.pc))
			continue;
		/* Still available: */
		if (ss7_route_table_dpc_is_accessible_skip_as(rtbl, entry->addr.pc, as))
			continue;
		LOGPAS(as, DLSS7, LOGL_INFO, "AS became inactive => address-book pc=%u=%s is now unavailable\n",
		       entry->addr.pc, osmo_ss7_pointcode_print(s7i, entry->addr.pc));
		aff_pc = htonl(entry->addr.pc);
		xua_snm_pc_available(as, &aff_pc, 1, NULL, false);
	}
}

/* AS became active, trigger SNM PC availability for PCs it served: */
static void as_snm_pc_available(struct osmo_ss7_as *as)
{
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_ss7_route_table *rtbl = s7i->rtable_system;
	struct osmo_ss7_combined_linkset *clset;
	struct osmo_ss7_route *rt;
	uint32_t aff_pc;

	LOGPAS(as, DLSS7, LOGL_INFO, "AS became active, some routes to remote PCs may have become available\n");
	/* we assume the combined_links are sorted by mask length, i.e. more
	 * specific combined links first, and less specific combined links with shorter
	 * mask later */
	llist_for_each_entry(clset, &rtbl->combined_linksets, list) {
		llist_for_each_entry(rt, &clset->routes, list) {
			if (rt->dest.as != as)
				continue;
			if (ss7_route_is_summary(rt))
				continue; /* Only announce changes for fully qualified routes */
			/* We found a PC served by the AS which went up. If there's
			 * a route now in place towards that PC, announce availability
			 * to upper layers. */
			if (!ss7_route_table_dpc_is_accessible(rtbl, rt->cfg.pc))
				continue;
			LOGPAS(as, DLSS7, LOGL_INFO, "AS became active => remote pc=%u=%s is now available\n",
			       rt->cfg.pc, osmo_ss7_pointcode_print(s7i, rt->cfg.pc));
			aff_pc = htonl(rt->cfg.pc);
			xua_snm_pc_available(as, &aff_pc, 1, NULL, true);
		}
	}

	/* Generate PC availability indications for PCs in the sccp address-book.
	 * These are generally PCs the user wants to get information about, and
	 * they may have no fully-qualified route because:
	 * - user may have not configured such fully qualified route, but a
	 *   summary route (eg. 0.0.0/0 default route).
	 * - peer SG may have not announced them (DAVA/DUNA).
	 */
	struct osmo_sccp_addr_entry *entry;
	llist_for_each_entry(entry, &s7i->cfg.sccp_address_book, list) {
		if (!(entry->addr.presence & OSMO_SCCP_ADDR_T_PC))
			continue;
		if (osmo_ss7_pc_is_local(s7i, entry->addr.pc))
			continue;
		/* PC was already available: */
		if (ss7_route_table_dpc_is_accessible_skip_as(rtbl, entry->addr.pc, as))
			continue;
		/* Try to find if there's an available route via the AS matching this PC. */
		if (!ss7_route_table_dpc_is_accessible_via_as(rtbl, entry->addr.pc, as))
			continue;
		LOGPAS(as, DLSS7, LOGL_INFO, "AS became active => address-book pc=%u=%s is now available\n",
			entry->addr.pc, osmo_ss7_pointcode_print(s7i, entry->addr.pc));
		aff_pc = htonl(entry->addr.pc);
		xua_snm_pc_available(as, &aff_pc, 1, NULL, true);
	}
}

/* onenter call-back responsible of transmitting NTFY to all ASPs in
 * case of AS state changes */
static void xua_as_fsm_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_as *as = xafp->as;
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_xlm_prim_notify npar;

	switch (fi->state) {
	case XUA_AS_S_INACTIVE:
		/* continue below */
		break;
	case XUA_AS_S_ACTIVE:
		/* continue below */
		break;
	case XUA_AS_S_PENDING:
		/* continue below */
		break;
	case XUA_AS_S_DOWN:
		/* RFC4666 sec 4.3.2 AS States:
		   If we end up here, it means no ASP is ACTIVE or INACTIVE,
		   meaning no ASP can have already configured the traffic mode
		   in ASPAC or REG REQ. Hence, we can clear traffic mode defined
		   by peers and allow next first peer to request a new traffic
		   mode. */
		as->cfg.mode_set_by_peer = false;
		if (!as->cfg.mode_set_by_vty)
			as->cfg.mode = OSMO_SS7_AS_TMOD_OVERRIDE;
		return;
	default:
		return;
	}

	fill_notify_statchg_pars(fi, &npar);

	/* TODO: ASP-Id of ASP triggering this state change */

	as_notify_all_asp(xafp->as, &npar);

	bool became_available = (old_state != XUA_AS_S_ACTIVE && fi->state == XUA_AS_S_ACTIVE);
	bool became_unavailable = (old_state == XUA_AS_S_ACTIVE && fi->state != XUA_AS_S_ACTIVE);
	int role = ss7_as_get_local_role(xafp->as);

	switch (role) {
	case OSMO_SS7_ASP_ROLE_ASP:
		if (s7i->sccp) {
			if (became_available)
				as_snm_pc_available(as);
			else if (became_unavailable)
				as_snm_pc_unavailable(as);
		}
		break;
	case OSMO_SS7_ASP_ROLE_SG:
		/* only if we are the SG, we must start broadcasting availability information
		 * to everyone else */
		/* advertise availability of the routing key to others */
		if (became_available || became_unavailable) {
			uint32_t aff_pc = htonl(as->cfg.routing_key.pc);
			xua_snm_pc_available(as, &aff_pc, 1, NULL, became_available);
		}
		break;
	case OSMO_SS7_ASP_ROLE_IPSP:
		/* TODO */
		break;
	}
};

static void xua_as_fsm_inactive(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_asp *asp;
	struct xua_as_event_asp_inactive_ind_pars *inact_ind_pars;
	struct osmo_xlm_prim_notify npar;

	switch (event) {
	case XUA_ASPAS_ASP_DOWN_IND:
		asp = data;
		/* one ASP transitions into ASP-DOWN */
		if (check_any_other_asp_not_down(xafp->as, asp)) {
			/* ignore, we stay AS_INACTIVE */
		} else
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_DOWN, 0, 0);
		break;
	case XUA_ASPAS_ASP_ACTIVE_IND:
		asp = data;
		/* one ASP transitions into ASP-ACTIVE */
		osmo_fsm_inst_state_chg(fi, XUA_AS_S_ACTIVE, 0, 0);
		if (asp->cfg.role == OSMO_SS7_ASP_ROLE_SG)
			as_tx_duna_during_asp_act(xafp->as, asp);
		break;
	case XUA_ASPAS_ASP_INACTIVE_IND:
		inact_ind_pars = data;
		if (inact_ind_pars->asp_requires_notify) {
			fill_notify_statchg_pars(fi, &npar);
			tx_notify(inact_ind_pars->asp, &npar);
		}
		break;
	}
}

static void xua_as_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_asp *asp;
	struct xua_as_event_asp_inactive_ind_pars *inact_ind_pars;
	struct xua_msg *xua;
	struct osmo_xlm_prim_notify npar;

	switch (event) {
	case XUA_ASPAS_ASP_DOWN_IND:
		asp = data;
		if (!check_any_other_asp_in_active(xafp->as, asp)) {
			uint32_t recovery_msec = xafp->as->cfg.recovery_timeout_msec;
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_PENDING, 0, 0);
			/* Start T(r) */
			osmo_timer_schedule(&xafp->recovery.t_r, MSEC_TO_S_US(recovery_msec));
			/* FIXME: Queue all signalling messages until
			 * recovery or T(r) expiry */
		}
		break;
	case XUA_ASPAS_ASP_INACTIVE_IND:
		inact_ind_pars = data;
		if (!check_any_other_asp_in_active(xafp->as, inact_ind_pars->asp)) {
			uint32_t recovery_msec = xafp->as->cfg.recovery_timeout_msec;
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_PENDING, 0, 0);
			/* Start T(r) */
			osmo_timer_schedule(&xafp->recovery.t_r, MSEC_TO_S_US(recovery_msec));
			/* FIXME: Queue all signalling messages until
			 * recovery or T(r) expiry */
		} else if (inact_ind_pars->asp_requires_notify) {
			fill_notify_statchg_pars(fi, &npar);
			tx_notify(inact_ind_pars->asp, &npar);
		}
		break;
	case XUA_ASPAS_ASP_ACTIVE_IND:
		asp = data;
		/* RFC466 sec 4.3.4.3 ASP Active Procedures */
		if (xafp->as->cfg.mode == OSMO_SS7_AS_TMOD_OVERRIDE)
			notify_any_other_active_asp_as_inactive(xafp->as, asp);
		/* SG role: No need to send DUNA for unknown destinations here
		 * (see as_tx_duna_during_asp_act()), since the AS was already
		 * active so the peer should know current status. */
		break;
	case XUA_AS_E_TRANSFER_REQ:
		/* message for transmission */
		xua = data;
		xua_as_transmit_msg(xafp->as, xua);
		break;
	}
}

static void xua_as_fsm_pending(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;
	struct osmo_ss7_asp *asp;
	struct xua_as_event_asp_inactive_ind_pars *inact_ind_pars;
	struct xua_msg *xua;
	struct osmo_xlm_prim_notify npar;

	switch (event) {
	case XUA_ASPAS_ASP_ACTIVE_IND:
		asp = data;
		/* one ASP transitions into ASP-ACTIVE */
		osmo_timer_del(&xafp->recovery.t_r);
		osmo_fsm_inst_state_chg(fi, XUA_AS_S_ACTIVE, 0, 0);
		if (asp->cfg.role == OSMO_SS7_ASP_ROLE_SG)
			as_tx_duna_during_asp_act(xafp->as, asp);
		/* push out any pending queued messages */
		while (!llist_empty(&xafp->recovery.queued_xua_msgs)) {
			struct xua_msg *xua;
			xua = llist_first_entry(&xafp->recovery.queued_xua_msgs, struct xua_msg, entry);
			llist_del(&xua->entry);
			xua_as_transmit_msg(xafp->as, xua);
		}
		break;
	case XUA_ASPAS_ASP_INACTIVE_IND:
		inact_ind_pars = data;
		if (inact_ind_pars->asp_requires_notify) {
			fill_notify_statchg_pars(fi, &npar);
			tx_notify(inact_ind_pars->asp, &npar);
		}
		break;
	case XUA_ASPAS_ASP_DOWN_IND:
		/* ignore */
		break;
	case XUA_AS_E_RECOVERY_EXPD:
		LOGPFSM(fi, "T(r) expired; dropping queued messages\n");
		while (!llist_empty(&xafp->recovery.queued_xua_msgs)) {
			struct xua_msg *xua;
			xua = llist_first_entry(&xafp->recovery.queued_xua_msgs, struct xua_msg, entry);
			llist_del(&xua->entry);
			xua_msg_free(xua);
		}
		if (check_any_other_asp_not_down(xafp->as, NULL))
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_INACTIVE, 0, 0);
		else
			osmo_fsm_inst_state_chg(fi, XUA_AS_S_DOWN, 0, 0);
		break;
	case XUA_AS_E_TRANSFER_REQ:
		/* enqueue the to-be-transferred message */
		xua = data;
		llist_add_tail(&xua->entry, &xafp->recovery.queued_xua_msgs);
		break;
	}
}

static void xua_as_fsm_cleanup(struct osmo_fsm_inst *fi, enum osmo_fsm_term_cause cause)
{
	struct xua_as_fsm_priv *xafp = (struct xua_as_fsm_priv *) fi->priv;

	osmo_timer_del(&xafp->recovery.t_r);
}

static const struct osmo_fsm_state xua_as_fsm_states[] = {
	[XUA_AS_S_DOWN] = {
		.in_event_mask = S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_DOWN_IND),
		.out_state_mask = S(XUA_AS_S_DOWN) |
				  S(XUA_AS_S_INACTIVE),
		.name = "AS_DOWN",
		.action = xua_as_fsm_down,
		.onenter = xua_as_fsm_onenter,
	},
	[XUA_AS_S_INACTIVE] = {
		.in_event_mask = S(XUA_ASPAS_ASP_DOWN_IND) |
				 S(XUA_ASPAS_ASP_ACTIVE_IND) |
				 S(XUA_ASPAS_ASP_INACTIVE_IND),
		.out_state_mask = S(XUA_AS_S_DOWN) |
				  S(XUA_AS_S_INACTIVE) |
				  S(XUA_AS_S_ACTIVE),
		.name = "AS_INACTIVE",
		.action = xua_as_fsm_inactive,
		.onenter = xua_as_fsm_onenter,
	},
	[XUA_AS_S_ACTIVE] = {
		.in_event_mask = S(XUA_ASPAS_ASP_DOWN_IND) |
				 S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_ACTIVE_IND) |
				 S(XUA_AS_E_TRANSFER_REQ),
		.out_state_mask = S(XUA_AS_S_ACTIVE) |
				  S(XUA_AS_S_PENDING),
		.name = "AS_ACTIVE",
		.action = xua_as_fsm_active,
		.onenter = xua_as_fsm_onenter,
	},
	[XUA_AS_S_PENDING] = {
		.in_event_mask = S(XUA_ASPAS_ASP_INACTIVE_IND) |
				 S(XUA_ASPAS_ASP_DOWN_IND) |
				 S(XUA_ASPAS_ASP_ACTIVE_IND) |
				 S(XUA_AS_E_TRANSFER_REQ) |
				 S(XUA_AS_E_RECOVERY_EXPD),
		.out_state_mask = S(XUA_AS_S_DOWN) |
				  S(XUA_AS_S_INACTIVE) |
				  S(XUA_AS_S_ACTIVE) |
				  S(XUA_AS_S_PENDING),
		.name = "AS_PENDING",
		.action = xua_as_fsm_pending,
		.onenter = xua_as_fsm_onenter,
	},
};

struct osmo_fsm xua_as_fsm = {
	.name = "XUA_AS",
	.states = xua_as_fsm_states,
	.num_states = ARRAY_SIZE(xua_as_fsm_states),
	.log_subsys = DLSS7,
	.event_names = xua_as_event_names,
	.cleanup = xua_as_fsm_cleanup,
};

/*! \brief Start an AS FSM for a given Application Server
 *  \param[in] as Application Server for which to start the AS FSM
 *  \param[in] log_level Logging level for logging of this FSM
 *  \returns FSM instance in case of success; NULL in case of error */
struct osmo_fsm_inst *xua_as_fsm_start(struct osmo_ss7_as *as, int log_level)
{
	struct osmo_fsm_inst *fi;
	struct xua_as_fsm_priv *xafp;

	fi = osmo_fsm_inst_alloc(&xua_as_fsm, as, NULL, log_level, as->cfg.name);
	if (!fi)
		return NULL;

	xafp = talloc_zero(fi, struct xua_as_fsm_priv);
	if (!xafp) {
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_ERROR, NULL);
		return NULL;
	}
	xafp->as = as;
	xafp->recovery.t_r.cb = t_r_callback;
	xafp->recovery.t_r.data = fi;
	INIT_LLIST_HEAD(&xafp->recovery.queued_xua_msgs);

	fi->priv = xafp;

	return fi;
}
