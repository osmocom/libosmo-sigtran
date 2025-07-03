/* SCCP Connection related routines */

/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * based on my 2011 Erlang implementation osmo_ss7/src/sua_sccp_conv.erl
 *
 * References: ITU-T Q.713 and IETF RFC 3868
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

#include <errno.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sccp/sccp_types.h>

#include "sccp_instance.h"
#include "sccp_internal.h"
#include "sccp_connection.h"
#include "sccp_scoc_fsm.h"
#include "sccp_user.h"
#include "ss7_instance.h"
#include "xua_msg.h"
#include "xua_internal.h"

static void sccp_conn_opt_data_clear_cache(struct sccp_connection *conn);

#define INIT_TIMER(x, fn, priv)		do { (x)->cb = fn; (x)->data = priv; } while (0)

/* T(ias) has expired, send a COIT message to the peer */
static void tx_inact_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_IAS_EXP, NULL);
}

/* T(iar) has expired, notify the FSM about it */
static void rx_inact_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_IAR_EXP, NULL);
}

/* T(rel) has expired, notify the FSM about it */
static void rel_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_REL_EXP, NULL);
}

/* T(int) has expired, notify the FSM about it */
static void int_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_INT_EXP, NULL);
}

/* T(repeat_rel) has expired, notify the FSM about it */
static void rep_rel_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_T_REP_REL_EXP, NULL);
}

/* T(conn) has expired, notify the FSM about it */
static void conn_tmr_cb(void *data)
{
	struct sccp_connection *conn = data;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_CONN_TMR_EXP, NULL);
}

/* Generate an SLS to be used for Connection-oriented messages on this SCCP connection.
 * SLS is 4 bits, as described in ITU Q.704 Figure 3.
 * ITU-T Q.714 1.1.2.3 Protocol class 2:
 *  "Messages belonging to a given signalling connection shall contain the same
 *  value of the SLS field to ensure sequencing as described in 1.1.2.2"
 */
static uint8_t sccp_conn_gen_tx_co_mtp_sls(const struct sccp_connection *conn)
{
	/* Implementation: Derive the SLS from conn->conn_id. */
	const uint32_t id = conn->conn_id;
	uint8_t sls;

	/* First shrink it to 1 byte: */
	sls = ((id >> (3*8)) ^ (id >> (2*8)) ^ (id >> (1*8)) ^ (id)) & 0xff;
	/* Now shrink it 8 -> 4 bits: */
	sls = ((sls >> 4) ^ sls) & 0x0f;

	return sls;
}

static int conn_add_node(struct osmo_sccp_instance *inst, struct sccp_connection *conn)
{
	struct rb_node **n = &(inst->connections.rb_node);
	struct rb_node *parent = NULL;

	while (*n) {
		struct sccp_connection *it;

		it = container_of(*n, struct sccp_connection, node);

		parent = *n;
		if (conn->conn_id < it->conn_id) {
			n = &((*n)->rb_left);
		} else if (conn->conn_id > it->conn_id) {
			n = &((*n)->rb_right);
		} else {
			LOGPSCI(inst, LOGL_ERROR, "Trying to reserve already reserved conn_id %u\n",
				conn->conn_id);
			return -EEXIST;
		}
	}

	rb_link_node(&conn->node, parent, n);
	rb_insert_color(&conn->node, &inst->connections);
	return 0;
}

/* allocate + init a SCCP Connection with given ID */
struct sccp_connection *sccp_conn_alloc(struct osmo_sccp_user *user, uint32_t conn_id)
{
	struct sccp_connection *conn = talloc_zero(user->inst, struct sccp_connection);
	char name[16];

	conn->conn_id = conn_id;
	conn->inst = user->inst;
	conn->user = user;

	if (conn_add_node(user->inst, conn) < 0) {
		talloc_free(conn);
		return NULL;
	}

	INIT_TIMER(&conn->t_conn, conn_tmr_cb, conn);
	INIT_TIMER(&conn->t_ias, tx_inact_tmr_cb, conn);
	INIT_TIMER(&conn->t_iar, rx_inact_tmr_cb, conn);
	INIT_TIMER(&conn->t_rel, rel_tmr_cb, conn);
	INIT_TIMER(&conn->t_int, int_tmr_cb, conn);
	INIT_TIMER(&conn->t_rep_rel, rep_rel_tmr_cb, conn);

	conn->tx_co_mtp_sls = sccp_conn_gen_tx_co_mtp_sls(conn);

	/* this might change at runtime, as it is not a constant :/ */
	sccp_scoc_fsm.log_subsys = DLSCCP;

	/* we simply use the connection ID as FSM instance name */
	snprintf(name, sizeof(name), "%u", conn->conn_id);
	conn->fi = osmo_fsm_inst_alloc(&sccp_scoc_fsm, conn, conn,
					LOGL_DEBUG, name);
	if (!conn->fi) {
		rb_erase(&conn->node, &user->inst->connections);
		talloc_free(conn);
		return NULL;
	}

	return conn;
}

/* destroy a SCCP connection state, releasing all timers, terminating
 * FSM and releasing associated memory */
void sccp_conn_free(struct sccp_connection *conn)
{
	if (!conn)
		return;
	sccp_conn_opt_data_clear_cache(conn);

	sccp_conn_stop_connect_timer(conn);
	sccp_conn_stop_inact_timers(conn);
	sccp_conn_stop_release_timers(conn);
	rb_erase(&conn->node, &conn->inst->connections);

	osmo_fsm_inst_term(conn->fi, OSMO_FSM_TERM_REQUEST, NULL);

	talloc_free(conn);
}

/* allocate a message buffer for an SCCP User Primitive */
static struct msgb *scu_msgb_alloc(void)
{
	#define SCU_MSGB_SIZE	1024
	return msgb_alloc(SCU_MSGB_SIZE, "SCCP User Primitive");
}

/* allocate a SCU primitive to be sent to the user */
static struct osmo_scu_prim *scu_prim_alloc(unsigned int primitive, enum osmo_prim_operation operation)
{
	struct msgb *upmsg = scu_msgb_alloc();
	struct osmo_scu_prim *prim;

	prim = (struct osmo_scu_prim *) msgb_put(upmsg, sizeof(*prim));
	osmo_prim_init(&prim->oph, SCCP_SAP_USER,
			primitive, operation, upmsg);
	upmsg->l2h = upmsg->tail;
	return prim;
}

/* high-level function to generate a SCCP User primitive of requested
 * type based on the connection and currently processed XUA message */
void sccp_conn_scu_gen_encode_and_send(struct sccp_connection *conn, uint32_t event,
				       struct xua_msg *xua, unsigned int primitive,
				       enum osmo_prim_operation operation)
{
	struct osmo_scu_prim *scu_prim;
	struct osmo_scu_disconn_param *udisp;
	struct osmo_scu_connect_param *uconp;
	struct osmo_scu_data_param *udatp;
	struct xua_msg_part *data_ie;

	scu_prim = scu_prim_alloc(primitive, operation);

	switch (OSMO_PRIM_HDR(&scu_prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_INDICATION):
		udisp = &scu_prim->u.disconnect;
		udisp->conn_id = conn->conn_id;
		udisp->responding_addr = conn->called_addr;
		udisp->importance = conn->importance;
		udisp->originator = OSMO_SCCP_ORIG_UNDEFINED;
		//udisp->in_sequence_control;
		if (xua) {
			udisp->cause = xua_msg_get_u32(xua, SUA_IEI_CAUSE);
			if (xua_msg_find_tag(xua, SUA_IEI_SRC_ADDR)) {
				if (sua_addr_parse(&udisp->responding_addr, xua, SUA_IEI_SRC_ADDR) < 0) {
					LOGPSCC(conn, LOGL_ERROR, "XUA Message %s without valid SRC_ADDR\n",
						xua_hdr_dump(xua, &xua_dialect_sua));
					talloc_free(scu_prim->oph.msg);
					return;
				}
			}
			data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
			udisp->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
			if (data_ie) {
				struct msgb *upmsg = scu_prim->oph.msg;
				upmsg->l2h = msgb_put(upmsg, data_ie->len);
				memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
			}
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_INDICATION):
		uconp = &scu_prim->u.connect;
		uconp->conn_id = conn->conn_id;
		uconp->called_addr = conn->called_addr;
		uconp->calling_addr = conn->calling_addr;
		uconp->sccp_class = conn->sccp_class;
		uconp->importance = conn->importance;
		if (xua) {
			data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
			if (data_ie) {
				struct msgb *upmsg = scu_prim->oph.msg;
				upmsg->l2h = msgb_put(upmsg, data_ie->len);
				memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
			}
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_CONFIRM):
		uconp = &scu_prim->u.connect;
		uconp->conn_id = conn->conn_id;
		uconp->called_addr = conn->called_addr;
		uconp->calling_addr = conn->calling_addr;
		//scu_prim->u.connect.in_sequence_control
		uconp->sccp_class = xua_msg_get_u32(xua, SUA_IEI_PROTO_CLASS) & 3;
		uconp->importance = xua_msg_get_u32(xua, SUA_IEI_IMPORTANCE);
		data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
		if (data_ie) {
			struct msgb *upmsg = scu_prim->oph.msg;
			upmsg->l2h = msgb_put(upmsg, data_ie->len);
			memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_INDICATION):
		udatp = &scu_prim->u.data;
		udatp->conn_id = conn->conn_id;
		udatp->importance = conn->importance;
		data_ie = xua_msg_find_tag(xua, SUA_IEI_DATA);
		if (data_ie) {
			struct msgb *upmsg = scu_prim->oph.msg;
			upmsg->l2h = msgb_put(upmsg, data_ie->len);
			memcpy(upmsg->l2h, data_ie->dat, data_ie->len);
		}
		break;
	default:
		LOGPFSML(conn->fi, LOGL_ERROR, "Unsupported primitive %u:%u\n",
			 scu_prim->oph.primitive, scu_prim->oph.operation);
		talloc_free(scu_prim->oph.msg);
		return;
	}

	sccp_user_prim_up(conn->user, scu_prim);
}

static void sccp_timer_schedule(const struct sccp_connection *conn,
				struct osmo_timer_list *timer,
				enum osmo_sccp_timer timer_name)
{
	const unsigned long val_sec = osmo_tdef_get(conn->inst->tdefs, timer_name, OSMO_TDEF_S, -1);
	osmo_timer_schedule(timer, val_sec, 0);
}

/* Re-start the Tx inactivity timer */
void sccp_conn_restart_tx_inact_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_ias, OSMO_SCCP_TIMER_IAS);
}

/* Re-start the Rx inactivity timer */
void sccp_conn_restart_rx_inact_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_iar, OSMO_SCCP_TIMER_IAR);
}

/* Re-start both Rx and Tx inactivity timers */
void sccp_conn_start_inact_timers(struct sccp_connection *conn)
{
	sccp_conn_restart_tx_inact_timer(conn);
	sccp_conn_restart_rx_inact_timer(conn);
}

/* Stop both Rx and Tx inactivity timers */
void sccp_conn_stop_inact_timers(struct sccp_connection *conn)
{
	osmo_timer_del(&conn->t_ias);
	osmo_timer_del(&conn->t_iar);
}

/* Start release timer T(rel) */
void sccp_conn_start_rel_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_rel, OSMO_SCCP_TIMER_REL);
}

/* Start repeat release timer T(rep_rel) */
void sccp_conn_start_rep_rel_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_rep_rel, OSMO_SCCP_TIMER_REPEAT_REL);
}

/* Start interval timer T(int) */
void sccp_conn_start_int_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_int, OSMO_SCCP_TIMER_INT);
}

/* Stop all release related timers: T(rel), T(int) and T(rep_rel) */
void sccp_conn_stop_release_timers(struct sccp_connection *conn)
{
	osmo_timer_del(&conn->t_rel);
	osmo_timer_del(&conn->t_int);
	osmo_timer_del(&conn->t_rep_rel);
}

/* Start connect timer T(conn) */
void sccp_conn_start_connect_timer(struct sccp_connection *conn)
{
	sccp_timer_schedule(conn, &conn->t_conn, OSMO_SCCP_TIMER_CONN_EST);
}

/* Stop connect timer T(conn) */
void sccp_conn_stop_connect_timer(struct sccp_connection *conn)
{
	osmo_timer_del(&conn->t_conn);
}

static void sccp_conn_opt_data_clear_cache(struct sccp_connection *conn)
{
	if (conn->opt_data_cache) {
		msgb_free(conn->opt_data_cache);
		conn->opt_data_cache = NULL;
	}
}

/* Send cached optional data (if any) from expected message type and clear cache */
void sccp_conn_opt_data_send_cache(struct sccp_connection *conn, int exp_type, uint8_t msg_class)
{
	const struct xua_dialect *dialect = &xua_dialect_sua;
	const struct xua_msg_class *xmc = dialect->class[msg_class];

	if (!conn->opt_data_cache)
		return;

	if (conn->opt_data_cache->cb[0] != exp_type) {
		/* Caller (from the FSM) knows what was the source of Optional Data we're sending.
		 * Compare this information with source of Optional Data recorded while caching
		 * to make sure we're on the same page.
		 */
		LOGPSCC(conn, LOGL_ERROR, "unexpected message type %s != cache source %s\n",
			xua_class_msg_name(xmc, exp_type),
			xua_class_msg_name(xmc, conn->opt_data_cache->cb[0]));
	} else {
		osmo_sccp_tx_data(conn->user, conn->conn_id, msgb_data(conn->opt_data_cache), msgb_length(conn->opt_data_cache));
	}

	sccp_conn_opt_data_clear_cache(conn);
}
