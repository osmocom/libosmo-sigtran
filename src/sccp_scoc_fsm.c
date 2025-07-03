/* SCCP Connection Oriented (SCOC) FSM according to ITU-T Q.713/Q.714 */

/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights reserved
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
 *
 */

/* This code is a bit of a hybrid between the ITU-T Q.71x specifications
 * for SCCP (particularly its connection-oriented part), and the IETF
 * RFC 3868 (SUA).  The idea here is to have one shared code base of the
 * state machines for SCCP Connection Oriented, and use those both from
 * SCCP and SUA.
 */

#include <errno.h>
#include <string.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/linuxrbtree.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/fsm.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sccp/sccp_types.h>

#include "xua_internal.h"
#include "sccp_connection.h"
#include "sccp_scoc_fsm.h"
#include "sccp_internal.h"
#include "sccp_user.h"
#include "ss7_internal.h"
#include "ss7_instance.h"

/***********************************************************************
 * Actual SCCP Connection Oriented Control (SCOC) Finite State Machine
 ***********************************************************************/

#define S(x)	(1 << (x))

static const struct value_string scoc_event_names[] = {
	/* Primitives from SCCP-User */
	{ SCOC_E_SCU_N_CONN_REQ,	"N-CONNECT.req" },
	{ SCOC_E_SCU_N_CONN_RESP,	"N-CONNECT.resp" },
	{ SCOC_E_SCU_N_DISC_REQ,	"N-DISCONNECT.req" },
	{ SCOC_E_SCU_N_DATA_REQ,	"N-DATA.req" },
	{ SCOC_E_SCU_N_EXP_DATA_REQ,	"N-EXPEDITED_DATA.req" },

	/* Events from RCOC (Routing for Connection Oriented) */
	{ SCOC_E_RCOC_CONN_IND,		"RCOC-CONNECT.ind" },
	{ SCOC_E_RCOC_ROUT_FAIL_IND,	"RCOC-ROUT_FAIL.ind" },
	{ SCOC_E_RCOC_RLSD_IND,		"RCOC-RELEASED.ind" },
	{ SCOC_E_RCOC_REL_COMPL_IND,	"RCOC-RELEASE_COMPLETE.ind" },
	{ SCOC_E_RCOC_CREF_IND,		"RCOC-CONNECT_REFUSED.ind" },
	{ SCOC_E_RCOC_CC_IND,		"RCOC-CONNECT_CONFIRM.ind" },
	{ SCOC_E_RCOC_DT1_IND,		"RCOC-DT1.ind" },
	{ SCOC_E_RCOC_DT2_IND,		"RCOC-DT2.ind" },
	{ SCOC_E_RCOC_IT_IND,		"RCOC-IT.ind" },
	{ SCOC_E_RCOC_OTHER_NPDU,	"RCOC-OTHER_NPDU.ind" },
	{ SCOC_E_RCOC_ERROR_IND,	"RCOC-ERROR.ind" },

	{ SCOC_E_T_IAR_EXP,		"T(iar)_expired" },
	{ SCOC_E_T_IAS_EXP,		"T(ias)_expired" },
	{ SCOC_E_CONN_TMR_EXP,		"T(conn)_expired" },
	{ SCOC_E_T_REL_EXP,		"T(rel)_expired" },
	{ SCOC_E_T_INT_EXP,		"T(int)_expired" },
	{ SCOC_E_T_REP_REL_EXP,		"T(rep_rel)_expired" },

	{ 0, NULL }
};

/* Figure C.2/Q.714 (sheet 1 of 7) and C.3/Q.714 (sheet 1 of 6) */
static void scoc_fsm_idle(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;
	struct osmo_scu_connect_param *uconp;
	struct xua_msg *xua = NULL;
	int rc;

	switch (event) {
	case SCOC_E_SCU_N_CONN_REQ:
		prim = data;
		uconp = &prim->u.connect;
		/* copy relevant parameters from prim to conn */
		conn->called_addr = uconp->called_addr;
		conn->calling_addr = uconp->calling_addr;
		conn->sccp_class = uconp->sccp_class;
		/* generate + send CR PDU to SCRC */
		rc = sccp_conn_xua_gen_encode_and_send(conn, event, prim, SUA_CO_CORE);
		if (rc < 0)
			LOGPFSML(fi, LOGL_ERROR, "Failed to initiate connection: %s\n", strerror(-rc));
		else {
			/* start connection timer */
			sccp_conn_start_connect_timer(conn);
			osmo_fsm_inst_state_chg(fi, S_CONN_PEND_OUT, 0, 0);
		}
		break;
#if 0
	case SCOC_E_SCU_N_TYPE1_REQ:
		/* ?!? */
		break;
#endif
	case SCOC_E_RCOC_RLSD_IND:
		/* send release complete to SCRC */
		sccp_conn_xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		break;
	case SCOC_E_RCOC_REL_COMPL_IND:
		/* do nothing */
		break;
	case SCOC_E_RCOC_OTHER_NPDU:
#if 0
		if (src_ref) {
			(void)src_ref;
			/* FIXME: send ERROR to SCRC */
		}
#endif
		break;
	/* destination node / incoming connection */
	/* Figure C.3 / Q.714 (sheet 1 of 6) */
	case SCOC_E_RCOC_CONN_IND:
		xua = data;
		/* copy relevant parameters from xua to conn */
		conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
		conn->sccp_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) & 3;
		conn->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);

		rc = sua_addr_parse(&conn->calling_addr, xua, SUA_IEI_SRC_ADDR);
		if (rc < 0) {
			LOGPSCC(conn, LOGL_ERROR, "XUA Message %s without valid SRC_ADDR\n",
				xua_hdr_dump(xua, &xua_dialect_sua));
			goto refuse_destroy_conn;
		}
		/* 3.1.6.1 The originating node of the CR message
		 * (identified by the OPC in the calling party address
		 * or by default by the OPC in the MTP label, [and the
		 * MTP-SAP instance]) is associated with the incoming
		 * connection section. */
		if (conn->calling_addr.presence & OSMO_SCCP_ADDR_T_PC)
			conn->remote_pc = conn->calling_addr.pc;
		else {
			/* Hack to get the MTP label here ?!? */
			conn->remote_pc = xua->mtp.opc;
		}

		rc = sua_addr_parse(&conn->called_addr, xua, SUA_IEI_DEST_ADDR);
		if (rc < 0) {
			LOGPSCC(conn, LOGL_ERROR, "XUA Message %s without valid DEST_ADDR\n",
				xua_hdr_dump(xua, &xua_dialect_sua));
			goto refuse_destroy_conn;
		}

		osmo_fsm_inst_state_chg(fi, S_CONN_PEND_IN, 0, 0);
		/* N-CONNECT.ind to User */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION);
		break;
	}
	return;

refuse_destroy_conn:
	sccp_conn_xua_gen_encode_and_send(conn, event, NULL, SUA_CO_COREF);
	osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
}

static void scoc_fsm_idle_onenter(struct osmo_fsm_inst *fi, uint32_t old_state)
{
	sccp_conn_free(fi->priv);
}

/* Figure C.3 / Q.714 (sheet 2 of 6) */
static void scoc_fsm_conn_pend_in(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;

	switch (event) {
	case SCOC_E_SCU_N_CONN_RESP:
		prim = data;
		/* FIXME: assign local reference (only now?) */
		/* FIXME: assign sls, protocol class and credit */
		sccp_conn_xua_gen_encode_and_send(conn, event, prim, SUA_CO_COAK);
		/* start inactivity timers */
		sccp_conn_start_inact_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_ACTIVE, 0, 0);
		sccp_conn_opt_data_send_cache(conn, SUA_CO_COAK, SUA_MSGC_CO);
		break;
	case SCOC_E_SCU_N_DISC_REQ:
		prim = data;
		/* release resources: implicit */
		sccp_conn_xua_gen_encode_and_send(conn, event, prim, SUA_CO_COREF);
		/* N. B: we've ignored CREF sending errors as there's no recovery option anyway */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	}
}

/* Figure C.2/Q.714 (sheet 2 of 7) */
static void scoc_fsm_conn_pend_out(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;
	struct xua_msg *xua = NULL;

	switch (event) {
	case SCOC_E_SCU_N_DISC_REQ:
		prim = data;
		conn->release_cause = prim->u.disconnect.cause;
		osmo_fsm_inst_state_chg(fi, S_WAIT_CONN_CONF, 0, 0);
		/* keep conn timer running(!) */
		break;
	case SCOC_E_CONN_TMR_EXP:
		/* N-DISCONNECT.ind to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, NULL,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		/* below implicitly releases resources + local ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_ROUT_FAIL_IND:
	case SCOC_E_RCOC_CREF_IND:
		xua = data;
		/* stop conn timer */
		sccp_conn_stop_connect_timer(conn);
		/* release local res + ref (implicit by going to idle) */
		/* N-DISCONNECT.ind to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		/* below implicitly releases resources + local ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_RLSD_IND:
		xua = data;
		/* RLC to SCRC */
		sccp_conn_xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		/* stop conn timer */
		sccp_conn_stop_connect_timer(conn);
		/* release local res + ref (implicit) */
		/* N-DISCONNECT.ind to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_OTHER_NPDU:
		xua = data;
		sccp_conn_start_connect_timer(conn);
		/* release local res + ref (implicit) */
		/* N-DISCONNECT.ind to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_CC_IND:
		xua = data;
		/* stop conn timer */
		sccp_conn_stop_connect_timer(conn);
		/* start inactivity timers */
		sccp_conn_start_inact_timers(conn);
		/* TODO: assign PCU and credit */
		/* associate remote ref to conn */
		conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
		/* 3.1.4.2 The node sending the CC message (identified
		 * by the parameter OPC contained in the
		 * MTP-TRANSFER.indication primitive which conveyed the
		 * CC message [plus the MTP-SAP instance]) is associated
		 * with the connection section. */
		conn->remote_pc = xua->mtp.opc;

		osmo_fsm_inst_state_chg(fi, S_ACTIVE, 0, 0);
		/* If CR which was used to initiate this connection had excessive Optional Data which we had to cache,
		 * now is the time to send it: the connection is already active but we hadn't notified upper layers about it
		 * so we have the connection all to ourselves and can use it to transmit "leftover" data via DT1 */
		sccp_conn_opt_data_send_cache(conn, SUA_CO_CORE, xua->hdr.msg_class);

		/* N-CONNECT.conf to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM);
		break;
	}
}

/* Figure C.2/Q.714 (sheet 3 of 7) */
static void scoc_fsm_wait_conn_conf(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;
	struct xua_msg *xua = NULL;

	switch (event) {
	case SCOC_E_RCOC_RLSD_IND:
		xua = data;
		/* release complete to SCRC */
		sccp_conn_xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		/* stop conn timer */
		sccp_conn_stop_connect_timer(conn);
		/* release local res + ref (implicit) */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_CC_IND:
		xua = data;
		/* stop conn timer */
		sccp_conn_stop_connect_timer(conn);
		/* associate rem ref to conn */
		conn->remote_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
		/* 3.1.4.2 The node sending the CC message (identified
		 * by the parameter OPC contained in the
		 * MTP-TRANSFER.indication primitive which conveyed the
		 * CC message [plus the MTP-SAP instance]) is associated
		 * with the connection section. */
		conn->remote_pc = xua->mtp.opc;

		/* released to SCRC */
		sccp_conn_xua_gen_relre_and_send(conn, conn->release_cause, NULL);
		/* start rel timer */
		sccp_conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	case SCOC_E_RCOC_OTHER_NPDU:
	case SCOC_E_RCOC_CREF_IND:
	case SCOC_E_RCOC_ROUT_FAIL_IND:
		xua = data;
		/* stop conn timer */
		sccp_conn_stop_connect_timer(conn);
		/* release local res + ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_CONN_TMR_EXP:
		/* release local res + ref */
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	}
}

/* C.2/Q.714 (sheet 4+5 of 7) and C.3/Q714 (sheet 3+4 of 6) */
static void scoc_fsm_active(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct xua_msg *xua = data;
	struct sccp_connection *conn = fi->priv;
	struct osmo_scu_prim *prim = NULL;

	switch (event) {
#pragma message("TODO: internal disco: send N-DISCONNECT.ind to user")
		/* send N-DISCONNECT.ind to user */
		/*sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						    OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);*/
		/* fall-through */
	case SCOC_E_SCU_N_DISC_REQ:
		prim = data;
		/* stop inact timers */
		sccp_conn_stop_inact_timers(conn);
		/* send RLSD to SCRC */
		sccp_conn_xua_gen_encode_and_send(conn, event, prim, SUA_CO_RELRE);
		/* start rel timer */
		sccp_conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	case SCOC_E_RCOC_CREF_IND:
	case SCOC_E_RCOC_CC_IND:
	case SCOC_E_RCOC_REL_COMPL_IND:
		/* do nothing */
		break;
	case SCOC_E_RCOC_RLSD_IND:
		/* send N-DISCONNECT.ind to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		/* release res + local ref (implicit) */
		/* stop inact timers */
		sccp_conn_stop_inact_timers(conn);
		/* RLC to SCRC */
		sccp_conn_xua_gen_encode_and_send(conn, event, NULL, SUA_CO_RELCO);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_ERROR_IND:
		xua = data;
		/* FIXME: check for cause service_class_mismatch */
		/* release res + local ref (implicit) */
		/* send N-DISCONNECT.ind to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		/* stop inact timers */
		sccp_conn_stop_inact_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_T_IAR_EXP:
		/* stop inact timers */
		sccp_conn_stop_inact_timers(conn);
		xua = xua_msg_alloc();
		xua_msg_add_u32(xua, SUA_IEI_CAUSE,
				SUA_CAUSE_T_RELEASE | SCCP_RELEASE_CAUSE_EXPIRATION_INACTIVE);
		xua_msg_add_u32(xua, SUA_IEI_IMPORTANCE, conn->importance);
		/* Send N-DISCONNECT.ind to local user */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		talloc_free(xua);
		/* Send RLSD to peer */
		sccp_conn_xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_EXPIRATION_INACTIVE, NULL);
		/* start release timer */
		sccp_conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	case SCOC_E_RCOC_ROUT_FAIL_IND:
		/* send N-DISCONNECT.ind to user */
		sccp_conn_scu_gen_encode_and_send(conn, event, NULL,
						  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
		/* stop inact timers */
		sccp_conn_stop_inact_timers(conn);
		/* start release timer */
		sccp_conn_start_rel_timer(conn);
		osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		break;
	/* Figure C.4/Q.714 */
	case SCOC_E_SCU_N_DATA_REQ:
	case SCOC_E_SCU_N_EXP_DATA_REQ:
		prim = data;
		sccp_conn_xua_gen_encode_and_send(conn, event, prim, SUA_CO_CODT);
		sccp_conn_restart_tx_inact_timer(conn);
		break;
	case SCOC_E_RCOC_DT1_IND:
		/* restart receive inactivity timer */
		sccp_conn_restart_rx_inact_timer(conn);
		/* TODO: M-bit */
		sccp_conn_scu_gen_encode_and_send(conn, event, xua,
						  OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION);
		break;
	/* Figure C.4/Q.714 (sheet 4 of 4) */
	case SCOC_E_RCOC_IT_IND:
		xua = data;
		/* check if remote reference is what we expect */
		/* check class is what we expect */
		if (xua_msg_get_u32(xua, SUA_IEI_SRC_REF) != conn->remote_ref ||
		    xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) != conn->sccp_class) {
			/* Release connection */
			/* Stop inactivity Timers */
			sccp_conn_stop_inact_timers(conn);
			xua = xua_msg_alloc();
			xua_msg_add_u32(xua, SUA_IEI_CAUSE,
					SUA_CAUSE_T_RELEASE | SCCP_RELEASE_CAUSE_INCONSISTENT_CONN_DATA);
			xua_msg_add_u32(xua, SUA_IEI_IMPORTANCE, conn->importance);
			/* send N-DISCONNECT.ind to user */
			sccp_conn_scu_gen_encode_and_send(conn, event, xua,
							  OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION);
			talloc_free(xua);
			/* Send RLSD to SCRC */
			sccp_conn_xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_INCONSISTENT_CONN_DATA, NULL);
			talloc_free(xua);
			/* Start release timer */
			sccp_conn_start_rel_timer(conn);
			osmo_fsm_inst_state_chg(fi, S_DISCONN_PEND, 0, 0);
		}
		sccp_conn_restart_rx_inact_timer(conn);
		break;
	case SCOC_E_T_IAS_EXP:
		/* Send IT to peer */
		sccp_conn_xua_gen_encode_and_send(conn, event, NULL, SUA_CO_COIT);
		sccp_conn_restart_tx_inact_timer(conn);
		break;
	}
}

/* C.2/Q.714 (sheet 6+7 of 7) and C.3/Q.714 (sheet 5+6 of 6) */
static void scoc_fsm_disconn_pend(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct sccp_connection *conn = fi->priv;

	switch (event) {
	case SCOC_E_RCOC_REL_COMPL_IND:
	case SCOC_E_RCOC_RLSD_IND:
		/* release res + local ref (implicit) */
		/* freeze local ref */
		/* stop release + interval timers */
		sccp_conn_stop_release_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_RCOC_ROUT_FAIL_IND:
	case SCOC_E_RCOC_OTHER_NPDU:
		/* do nothing */
		break;
	case SCOC_E_T_REL_EXP: /* release timer exp */
		/* send RLSD */
		sccp_conn_xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_UNQUALIFIED, NULL);
		/* start interval timer */
		sccp_conn_start_int_timer(conn);
		/* start repeat release timer */
		sccp_conn_start_rep_rel_timer(conn);
		break;
	case SCOC_E_T_INT_EXP: /* interval timer exp */
		/* TODO: Inform maintenance */
		/* stop release and interval timers */
		sccp_conn_stop_release_timers(conn);
		osmo_fsm_inst_state_chg(fi, S_IDLE, 0, 0);
		break;
	case SCOC_E_T_REP_REL_EXP: /* repeat release timer exp */
		/* send RLSD */
		sccp_conn_xua_gen_relre_and_send(conn, SCCP_RELEASE_CAUSE_UNQUALIFIED, NULL);
		/* re-start repeat release timer */
		sccp_conn_start_rep_rel_timer(conn);
		break;
	}
}

static const struct osmo_fsm_state sccp_scoc_states[] = {
	[S_IDLE] = {
		.name = "IDLE",
		.action = scoc_fsm_idle,
		.onenter = scoc_fsm_idle_onenter,
		.in_event_mask = S(SCOC_E_SCU_N_CONN_REQ) |
				 //S(SCOC_E_SCU_N_TYPE1_REQ) |
				 S(SCOC_E_RCOC_CONN_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_REL_COMPL_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU),
		.out_state_mask = S(S_IDLE) |
				  S(S_CONN_PEND_OUT) |
				  S(S_CONN_PEND_IN),
	},
	[S_CONN_PEND_IN] = {
		.name = "CONN_PEND_IN",
		.action = scoc_fsm_conn_pend_in,
		.in_event_mask = S(SCOC_E_SCU_N_CONN_RESP) |
				 S(SCOC_E_SCU_N_DISC_REQ),
		.out_state_mask = S(S_IDLE) |
				  S(S_ACTIVE),
	},
	[S_CONN_PEND_OUT] = {
		.name = "CONN_PEND_OUT",
		.action = scoc_fsm_conn_pend_out,
		.in_event_mask = S(SCOC_E_SCU_N_DISC_REQ) |
				 S(SCOC_E_CONN_TMR_EXP) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU) |
				 S(SCOC_E_RCOC_CREF_IND) |
				 S(SCOC_E_RCOC_CC_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_ACTIVE) |
				  S(S_WAIT_CONN_CONF),
	},
	[S_ACTIVE] = {
		.name = "ACTIVE",
		.action = scoc_fsm_active,
		.in_event_mask = S(SCOC_E_SCU_N_DISC_REQ) |
				/* internal disconnect */
				 S(SCOC_E_RCOC_CREF_IND) |
				 S(SCOC_E_RCOC_REL_COMPL_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_ERROR_IND) |
				 S(SCOC_E_T_IAR_EXP) |
				 S(SCOC_E_T_IAS_EXP) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND) |
				 S(SCOC_E_SCU_N_DATA_REQ) |
				 S(SCOC_E_SCU_N_EXP_DATA_REQ) |
				 S(SCOC_E_RCOC_DT1_IND) |
				 S(SCOC_E_RCOC_IT_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_DISCONN_PEND),
	},
	[S_DISCONN_PEND] = {
		.name = "DISCONN_PEND",
		.action = scoc_fsm_disconn_pend,
		.in_event_mask = S(SCOC_E_RCOC_REL_COMPL_IND) |
				 S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU) |
				 S(SCOC_E_T_REL_EXP) |
				 S(SCOC_E_T_INT_EXP) |
				 S(SCOC_E_T_REP_REL_EXP),
		.out_state_mask = S(S_IDLE),
	},
	[S_RESET_IN] = {
		.name = "RESET_IN",
	},
	[S_RESET_OUT] = {
		.name = "RESET_OUT",
	},
	[S_BOTHWAY_RESET] = {
		.name = "BOTHWAY_RESET",
	},
	[S_WAIT_CONN_CONF] = {
		.name = "WAIT_CONN_CONF",
		.action = scoc_fsm_wait_conn_conf,
		.in_event_mask = S(SCOC_E_RCOC_RLSD_IND) |
				 S(SCOC_E_RCOC_CC_IND) |
				 S(SCOC_E_RCOC_OTHER_NPDU) |
				 S(SCOC_E_CONN_TMR_EXP) |
				 S(SCOC_E_RCOC_CREF_IND) |
				 S(SCOC_E_RCOC_ROUT_FAIL_IND),
		.out_state_mask = S(S_IDLE) |
				  S(S_DISCONN_PEND),
	},
};

struct osmo_fsm sccp_scoc_fsm = {
	.name = "SCCP-SCOC",
	.states = sccp_scoc_states,
	.num_states = ARRAY_SIZE(sccp_scoc_states),
	/* ".log_subsys = DLSCCP" doesn't work as DLSCCP is not a constant */
	.event_names = scoc_event_names,
};
