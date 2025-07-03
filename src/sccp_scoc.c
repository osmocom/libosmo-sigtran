/* SCCP Connection Oriented (SCOC) according to ITU-T Q.713/Q.714 */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
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
 *
 * To do so, all SCCP messages are translated to SUA messages in the
 * input side, and all generated SUA messages are translated to SCCP on
 * the output side.
 *
 * The Choice of going for SUA messages as the "native" format was based
 * on their easier parseability, and the fact that there are features in
 * SUA which classic SCCP cannot handle (like IP addresses in GT).
 * However, all SCCP features can be expressed in SUA.
 *
 * The code only supports Class 2.  No support for Class 3 is intended,
 * but patches are of course always welcome.
 *
 * Missing other features:
 *  * Segmentation/Reassembly support
 *  * T(guard) after (re)start
 *  * freezing of local references
 *  * parsing/encoding of IPv4/IPv6 addresses
 *  * use of multiple Routing Contexts in SUA case
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
#include "sccp_instance.h"
#include "sccp_internal.h"
#include "sccp_user.h"
#include "ss7_internal.h"
#include "ss7_instance.h"

/***********************************************************************
 * SCCP connection table
 ***********************************************************************/

/* how to map a SCCP CO message to an event */
static const struct xua_msg_event_map sua_scoc_event_map[] = {
	{ SUA_MSGC_CO, SUA_CO_CORE, SCOC_E_RCOC_CONN_IND },
	{ SUA_MSGC_CO, SUA_CO_RELRE, SCOC_E_RCOC_RLSD_IND },
	{ SUA_MSGC_CO, SUA_CO_RELCO, SCOC_E_RCOC_REL_COMPL_IND },
	{ SUA_MSGC_CO, SUA_CO_COREF, SCOC_E_RCOC_CREF_IND },
	{ SUA_MSGC_CO, SUA_CO_COAK, SCOC_E_RCOC_CC_IND },
	{ SUA_MSGC_CO, SUA_CO_CODT, SCOC_E_RCOC_DT1_IND },
	{ SUA_MSGC_CO, SUA_CO_COIT, SCOC_E_RCOC_IT_IND },
	{ SUA_MSGC_CO, SUA_CO_COERR, SCOC_E_RCOC_ERROR_IND },
};

/***********************************************************************
 * SUA Instance and Connection handling
 ***********************************************************************/

struct sccp_connection *sccp_find_conn_by_id(const struct osmo_sccp_instance *inst, uint32_t id)
{
	struct sccp_connection *conn;
	const struct rb_node *node = inst->connections.rb_node;

	while (node) {
		conn = container_of(node, struct sccp_connection, node);
		if (id < conn->conn_id)
			node = node->rb_left;
		else if (id > conn->conn_id)
			node = node->rb_right;
		else
			return conn;
	}
	return NULL;
}

bool osmo_sccp_conn_id_exists(const struct osmo_sccp_instance *inst, uint32_t id)
{
	return sccp_find_conn_by_id(inst, id) ? true : false;
}

/* Return an unused SCCP connection ID.
 * Callers should check the returned value: on negative return value, there are no unused IDs available.
 * \param[in] sccp  The SCCP instance to determine a new connection ID for.
 * \return unused ID on success (range [0x0, 0x00fffffe]) or negative on elapsed max_attempts without an unused id (<0).
 */
int osmo_sccp_instance_next_conn_id(struct osmo_sccp_instance *sccp)
{
	int max_attempts = 0x00FFFFFE;

	/* SUA: RFC3868 sec 3.10.4:
	*    The source reference number is a 4 octet long integer.
	*    This is allocated by the source SUA instance.
	* M3UA/SCCP: ITU-T Q.713 sec 3.3:
	*    The "source local reference" parameter field is a three-octet field containing a
	*    reference number which is generated and used by the local node to identify the
	*    connection section after the connection section is set up.
	*    The coding "all ones" is reserved for future use.
	* Hence, as we currently use the connection ID also as local reference,
	* let's simply use 24 bit ids to fit all link types (excluding 0x00ffffff).
	*/
	while (OSMO_LIKELY((max_attempts--) > 0)) {
		/* Optimized modulo operation (% 0x00FFFFFE) using bitwise AND plus CMP: */
		sccp->next_id = (sccp->next_id + 1) & 0x00FFFFFF;
		if (OSMO_UNLIKELY(sccp->next_id == 0x00FFFFFF))
			sccp->next_id = 0;

		if (!sccp_find_conn_by_id(sccp, sccp->next_id))
			return sccp->next_id;
	}

	return -1;
}

/* Search for next free connection ID and allocate conn */
static struct sccp_connection *conn_create(struct osmo_sccp_user *user)
{
	int conn_id = osmo_sccp_instance_next_conn_id(user->inst);
	if (conn_id < 0)
		return NULL;
	return sccp_conn_alloc(user, conn_id);
}

/* generate a RELRE (release request) xua_msg for given conn */
static struct xua_msg *xua_gen_relre(struct sccp_connection *conn,
				     uint32_t cause,
				     struct osmo_scu_prim *prim)
{
	struct xua_msg *xua = xua_msg_alloc();

	if (!xua)
		return NULL;

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RELEASE | cause);
	/* optional: importance */
	if (prim && msgb_l2(prim->oph.msg))
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));

	return xua;
}

/* generate xua_msg, encode it and send it to SCRC */
int sccp_conn_xua_gen_relre_and_send(struct sccp_connection *conn, uint32_t cause,
				     struct osmo_scu_prim *prim)
{
	struct xua_msg *xua;

	xua = xua_gen_relre(conn, cause, prim);
	if (!xua)
		return -1;

	/* amend this with point code information; The SUA RELRE
	 * includes neither called nor calling party address! */
	xua->mtp.dpc = conn->remote_pc;
	sccp_scrc_rx_scoc_conn_msg(conn->inst, xua);
	xua_msg_free(xua);
	return 0;
}

/* Check if optional data should be dropped, log given error message if so */
static bool xua_opt_data_check_drop(const struct osmo_scu_prim *prim, unsigned lim, const char *message)
{
	if (msgb_l2len(prim->oph.msg) > lim) {
		LOGP(DLSCCP, LOGL_ERROR,
			 "%s: dropping optional data with length %u > %u - %s\n",
			 osmo_scu_prim_name(&prim->oph), msgb_l2len(prim->oph.msg), lim, message);
		return true;
	}
	return false;
}

/* Cache the optional data (if necessary)
 * returns true if Optional Data should be kept while encoding the message */
static bool xua_opt_data_cache_keep(struct sccp_connection *conn, const struct osmo_scu_prim *prim, int msg_type)
{
	uint8_t *buf;
	uint32_t max_optional_data = conn->inst->max_optional_data;

	if (xua_opt_data_check_drop(prim, SCCP_MAX_DATA, "cache overrun"))
		return false;

	if (msgb_l2len(prim->oph.msg) > max_optional_data) {
		if (conn->opt_data_cache) {
			/* Caching optional data, but there already is optional data occupying the cache: */
			LOGPSCC(conn, LOGL_ERROR, "replacing unsent %u bytes of optional data cache with %s optional data\n",
				msgb_length(conn->opt_data_cache), osmo_scu_prim_name(&prim->oph));
			msgb_trim(conn->opt_data_cache, 0);
		} else {
			conn->opt_data_cache = msgb_alloc_c(conn, SCCP_MAX_DATA, "SCCP optional data cache for CR/CC/RLSD");
		}

		buf = msgb_put(conn->opt_data_cache, msgb_l2len(prim->oph.msg));
		memcpy(buf, msgb_l2(prim->oph.msg), msgb_l2len(prim->oph.msg));

		conn->opt_data_cache->cb[0] = msg_type;

		return false;
	}
	return true;
}

/* Check optional Data size limit, cache if necessary, return indication whether original opt data should be sent */
static bool xua_opt_data_length_lim(struct sccp_connection *conn, const struct osmo_scu_prim *prim, int msg_type)
{
	uint32_t max_optional_data = conn->inst->max_optional_data;

	if (!(prim && msgb_l2(prim->oph.msg) && msgb_l2len(prim->oph.msg)))
		return false;

	switch (msg_type) {
	case SUA_CO_CORE: /* §4.2 Connection request (CR) */
	case SUA_CO_COAK: /* §4.3 Connection confirm (CC) */
		return xua_opt_data_cache_keep(conn, prim, msg_type);
	case SUA_CO_COREF: /* §4.4 Connection refused (CREF) */
		if (xua_opt_data_check_drop(prim, max_optional_data, "over ITU-T Rec. Q.713 §4.4 limit")) {
			/* From the state diagrams in ITU-T Rec Q.714, there's no way to send DT1 neither before nor after CREF
			 * at this point, so the only option we have is to drop optional data:
			 * see Figure C.3 / Q.714 (sheet 2 of 6) */
			return false;
		}
		break;
	case SUA_CO_RELRE: /* §4.5 Released (RLSD) */
		if (msgb_l2len(prim->oph.msg) > max_optional_data) {
			if (xua_opt_data_check_drop(prim, SCCP_MAX_DATA, "protocol error"))
				return false;
			/* There's no need to cache the optional data since the connection is still active at this point:
			 * Send the Optional Data in a DT1 ahead of the RLSD, because it is too large to be sent in one message.
			 */
			osmo_sccp_tx_data(conn->user, conn->conn_id, msgb_l2(prim->oph.msg), msgb_l2len(prim->oph.msg));
			return false;
		}
		break;
	default:
		return true;
	}

	return true;
}

/* generate a 'struct xua_msg' of requested type from connection +
 * primitive data */
static struct xua_msg *xua_gen_msg_co(struct sccp_connection *conn, uint32_t event,
				      const struct osmo_scu_prim *prim, int msg_type)
{
	bool encode_opt_data = xua_opt_data_length_lim(conn, prim, msg_type);
	struct xua_msg *xua = xua_msg_alloc();

	if (!xua)
		return NULL;

	/* amend this with point code information; Many CO msgs
	 * includes neither called nor calling party address! */
	xua->mtp.dpc = conn->remote_pc;

	/* Apply SLS calculated for the connection (ITU-T Q.714 1.1.2.3). */
	xua->mtp.sls = conn->tx_co_mtp_sls;

	switch (msg_type) {
	case SUA_CO_CORE: /* Connect Request == SCCP CR */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CORE);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, conn->sccp_class);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &conn->called_addr);
		xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, 0); /* TODO */
		/* optional: sequence number (class 3 only) */
		if (conn->calling_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &conn->calling_addr);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: hop count */
		/* optional: importance */
		break;
	case SUA_CO_COAK: /* Connect Acknowledge == SCCP CC */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COAK);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, conn->sccp_class);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_u32(xua, SUA_IEI_SEQ_CTRL, 0); /* TODO */
		/* optional: sequence number (class 3 only) */
		if (conn->called_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &conn->called_addr);
		/* optional: hop count; importance; priority */
		/* FIXME: destination address will [only] be present in
		 * case the CORE message conveys the source address
		 * parameter */
		if (conn->calling_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &conn->calling_addr);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: importance */
		break;
	case SUA_CO_RELRE: /* Release Request == SCCP RLSD */
		if (!prim)
			goto prim_needed;
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_RELEASE | prim->u.disconnect.cause);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: importance */
		break;
	case SUA_CO_RELCO: /* Release Confirm == SCCP RLC */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELCO);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		break;
	case SUA_CO_CODT: /* Connection Oriented Data Transfer == SCCP DT1 */
		if (!prim)
			goto prim_needed;
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_CODT);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		/* Sequence number only in expedited data */
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		/* optional: priority; correlation id */
		xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg),
				 msgb_l2(prim->oph.msg));
		break;
	case SUA_CO_COIT: /* Connection Oriented Interval Timer == SCCP IT */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COIT);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_PROTO_CLASS, conn->sccp_class);
		xua_msg_add_u32(xua, SUA_IEI_SRC_REF, conn->conn_id);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		/* optional: sequence number; credit (both class 3 only) */
		break;
	case SUA_CO_COREF: /* Connect Refuse == SCCP CREF */
		xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COREF);
		xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, conn->inst->route_ctx);
		xua_msg_add_u32(xua, SUA_IEI_DEST_REF, conn->remote_ref);
		//xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | prim->u.disconnect.cause);
		xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | SCCP_REFUSAL_UNEQUIPPED_USER);
		/* optional: source addr */
		if (conn->called_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_SRC_ADDR, &conn->called_addr);
		/* conditional: dest addr */
		if (conn->calling_addr.presence)
			xua_msg_add_sccp_addr(xua, SUA_IEI_DEST_ADDR, &conn->calling_addr);
		/* optional: data */
		if (encode_opt_data)
			xua_msg_add_data(xua, SUA_IEI_DATA, msgb_l2len(prim->oph.msg), msgb_l2(prim->oph.msg));
		/* optional: importance */
		break;
	/* FIXME */
	default:
		LOGPSCC(conn, LOGL_ERROR, "Don't know how to encode msg_type %u\n", msg_type);
		xua_msg_free(xua);
		return NULL;
	}
	return xua;

prim_needed:
	xua_msg_free(xua);
	LOGPSCC(conn, LOGL_ERROR, "%s must be called with valid 'prim' pointer for msg_type=%u\n",
		__func__, msg_type);
	return NULL;
}

/* generate xua_msg, encode it and send it to SCRC
 * returns 0 on success, negative on error
 */
int sccp_conn_xua_gen_encode_and_send(struct sccp_connection *conn, uint32_t event,
				      const struct osmo_scu_prim *prim, int msg_type)
{
	struct xua_msg *xua;

	xua = xua_gen_msg_co(conn, event, prim, msg_type);
	if (!xua)
		return -ENOMEM;

	sccp_scrc_rx_scoc_conn_msg(conn->inst, xua);
	xua_msg_free(xua);
	return 0;
}

/* map from SCCP return cause to SCCP Refusal cause */
static const uint8_t cause_map_cref[] = {
	[SCCP_RETURN_CAUSE_SUBSYSTEM_CONGESTION] =
				SCCP_REFUSAL_SUBSYTEM_CONGESTION,
	[SCCP_RETURN_CAUSE_SUBSYSTEM_FAILURE] =
				SCCP_REFUSAL_SUBSYSTEM_FAILURE,
	[SCCP_RETURN_CAUSE_UNEQUIPPED_USER] =
				SCCP_REFUSAL_UNEQUIPPED_USER,
	[SCCP_RETURN_CAUSE_UNQUALIFIED] =
				SCCP_REFUSAL_UNQUALIFIED,
	[SCCP_RETURN_CAUSE_SCCP_FAILURE] =
				SCCP_REFUSAL_SCCP_FAILURE,
	[SCCP_RETURN_CAUSE_HOP_COUNTER_VIOLATION] =
				SCCP_REFUSAL_HOP_COUNTER_VIOLATION,
};

static uint8_t get_cref_cause_for_ret(uint8_t ret_cause)
{
	if (ret_cause < ARRAY_SIZE(cause_map_cref))
		return cause_map_cref[ret_cause];
	else
		return SCCP_REFUSAL_UNQUALIFIED;
}

/* Generate a COREF message purely based on an incoming SUA message,
 * without the use of any local connection state */
static struct xua_msg *gen_coref_without_conn(struct osmo_sccp_instance *inst,
					      struct xua_msg *xua_in,
					      uint32_t ref_cause)
{
	struct xua_msg *xua;

	xua = xua_msg_alloc();
	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COREF);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, inst->route_ctx);

	xua_msg_copy_part(xua, SUA_IEI_DEST_REF, xua_in, SUA_IEI_SRC_REF);
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_REFUSAL | ref_cause);
	/* optional: source addr */
	xua_msg_copy_part(xua, SUA_IEI_SRC_ADDR, xua_in, SUA_IEI_DEST_ADDR);
	/* conditional: dest addr */
	xua_msg_copy_part(xua, SUA_IEI_DEST_ADDR, xua_in, SUA_IEI_SRC_ADDR);
	/* optional: importance */
	xua_msg_copy_part(xua, SUA_IEI_IMPORTANCE, xua_in, SUA_IEI_IMPORTANCE);
	/* optional: data */
	xua_msg_copy_part(xua, SUA_IEI_DATA, xua_in, SUA_IEI_DATA);

	return xua;
}

/* Find a SCCP user for given SUA message (based on SUA_IEI_DEST_ADDR */
static struct osmo_sccp_user *sccp_find_user(struct osmo_sccp_instance *inst,
					     struct xua_msg *xua)
{
	int rc;
	struct osmo_sccp_addr called_addr;

	rc = sua_addr_parse(&called_addr, xua, SUA_IEI_DEST_ADDR);
	if (rc < 0) {
		LOGPSCI(inst, LOGL_ERROR, "Cannot find SCCP User for XUA "
			"Message %s without valid DEST_ADDR\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		return NULL;
	}

	if (!(called_addr.presence & OSMO_SCCP_ADDR_T_SSN)) {
		LOGPSCI(inst, LOGL_ERROR, "Cannot resolve SCCP User for "
			"XUA Message %s without SSN in CalledAddr\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		return NULL;
	}

	return sccp_user_find(inst, called_addr.ssn, called_addr.pc);
}

/*! \brief SCOC: Receive SCRC Routing Failure
 *  \param[in] inst SCCP Instance on which we operate
 *  \param[in] xua SUA message that was failed to route
 *  \param[in] return_cause Reason (cause) for routing failure */
void sccp_scoc_rx_scrc_rout_fail(struct osmo_sccp_instance *inst,
				struct xua_msg *xua, uint32_t return_cause)
{
	uint32_t conn_id;
	struct sccp_connection *conn;

	LOGPSCI(inst, LOGL_NOTICE, "SCRC Routing Failure (%s) for message %s\n",
		osmo_sccp_return_cause_name(return_cause),
		xua_hdr_dump(xua, &xua_dialect_sua));

	/* try to dispatch to connection FSM (if any) */
	conn_id = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
	conn = sccp_find_conn_by_id(inst, conn_id);
	if (conn) {
		osmo_fsm_inst_dispatch(conn->fi,
					SCOC_E_RCOC_ROUT_FAIL_IND, xua);
	} else {
		/* generate + send CREF directly */
		struct xua_msg *cref;
		uint8_t cref_cause = get_cref_cause_for_ret(return_cause);
		cref = gen_coref_without_conn(inst, xua, cref_cause);
		sccp_scrc_rx_scoc_conn_msg(inst, cref);
		xua_msg_free(cref);
	}
}

/* Generate a COERR based in input arguments */
static struct xua_msg *gen_coerr(uint32_t route_ctx, uint32_t dest_ref,
				uint32_t err_cause)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_COERR);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, dest_ref);
	xua_msg_add_u32(xua, SUA_IEI_CAUSE, SUA_CAUSE_T_ERROR | err_cause);

	return xua;
}

/* generate COERR from incoming XUA and send it */
static void tx_coerr_from_xua(struct osmo_sccp_instance *inst,
				struct xua_msg *in, uint32_t err_cause)
{
	struct xua_msg *xua;
	uint32_t route_ctx, dest_ref;

	route_ctx = xua_msg_get_u32(in, SUA_IEI_ROUTE_CTX);
	/* get *source* reference and use as destination ref */
	dest_ref = xua_msg_get_u32(in, SUA_IEI_SRC_REF);

	xua = gen_coerr(route_ctx, dest_ref, err_cause);
	/* copy over the MTP parameters */
	xua->mtp.dpc = in->mtp.opc;
	xua->mtp.opc = in->mtp.dpc;
	xua->mtp.sio = in->mtp.sio;

	/* sent to SCRC for transmission */
	sccp_scrc_rx_scoc_conn_msg(inst, xua);
	xua_msg_free(xua);
}

/* Generate a RELCO based in input arguments */
static struct xua_msg *gen_relco(uint32_t route_ctx, uint32_t dest_ref,
				uint32_t src_ref)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELCO);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, dest_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, src_ref);

	return xua;
}

/* generate RELCO from incoming XUA and send it */
static void tx_relco_from_xua(struct osmo_sccp_instance *inst,
				struct xua_msg *in)
{
	struct xua_msg *xua;
	uint32_t route_ctx, dest_ref, src_ref;

	route_ctx = xua_msg_get_u32(in, SUA_IEI_ROUTE_CTX);
	/* get *source* reference and use as destination ref */
	dest_ref = xua_msg_get_u32(in, SUA_IEI_SRC_REF);
	/* get *dest* reference and use as source ref */
	src_ref = xua_msg_get_u32(in, SUA_IEI_DEST_REF);

	xua = gen_relco(route_ctx, dest_ref, src_ref);
	/* copy over the MTP parameters */
	xua->mtp.dpc = in->mtp.opc;
	xua->mtp.opc = in->mtp.dpc;
	xua->mtp.sio = in->mtp.sio;

	/* send to SCRC for transmission */
	sccp_scrc_rx_scoc_conn_msg(inst, xua);
	xua_msg_free(xua);
}

/* Generate a RLSD based in input arguments */
static struct xua_msg *gen_rlsd(uint32_t route_ctx, uint32_t dest_ref,
				uint32_t src_ref)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(SUA_MSGC_CO, SUA_CO_RELRE);
	xua_msg_add_u32(xua, SUA_IEI_ROUTE_CTX, route_ctx);
	xua_msg_add_u32(xua, SUA_IEI_DEST_REF, dest_ref);
	xua_msg_add_u32(xua, SUA_IEI_SRC_REF, src_ref);

	return xua;
}

/* Generate a RLSD to both the remote side and the local conn */
static void tx_rlsd_from_xua_twoway(struct sccp_connection *conn,
				    struct xua_msg *in)
{
	struct xua_msg *xua;
	uint32_t route_ctx, dest_ref, src_ref;

	route_ctx = xua_msg_get_u32(in, SUA_IEI_ROUTE_CTX);
	/* get *source* reference and use as destination ref */
	dest_ref = xua_msg_get_u32(in, SUA_IEI_SRC_REF);
	/* get *source* reference and use as destination ref */
	src_ref = xua_msg_get_u32(in, SUA_IEI_DEST_REF);

	/* Generate RLSD towards remote peer */
	xua = gen_rlsd(route_ctx, dest_ref, src_ref);
	/* copy over the MTP parameters */
	xua->mtp.dpc = in->mtp.opc;
	xua->mtp.opc = in->mtp.dpc;
	xua->mtp.sio = in->mtp.sio;
	/* send to SCRC for transmission */
	sccp_scrc_rx_scoc_conn_msg(conn->inst, xua);
	xua_msg_free(xua);

	/* Generate RLSD towards local peer */
	xua = gen_rlsd(conn->inst->route_ctx, conn->conn_id, conn->remote_ref);
	xua->mtp.dpc = in->mtp.dpc;
	xua->mtp.opc = conn->remote_pc;
	xua->mtp.sio = in->mtp.sio;
	osmo_fsm_inst_dispatch(conn->fi, SCOC_E_RCOC_RLSD_IND, xua);
	xua_msg_free(xua);
}

/* process received message for unassigned local reference */
static void sccp_scoc_rx_unass_local_ref(struct osmo_sccp_instance *inst,
					 struct xua_msg *xua)
{
	/* we have received a message with unassigned destination local
	 * reference and thus apply the action indicated in Table
	 * B.2/Q.714 */
	switch (xua->hdr.msg_type) {
	case SUA_CO_COAK: /* CC */
	case SUA_CO_COIT: /* IT */
	case SUA_CO_RESRE: /* RSR */
	case SUA_CO_RESCO: /* RSC */
		/* Send COERR */
		tx_coerr_from_xua(inst, xua, SCCP_ERROR_LRN_MISMATCH_UNASSIGNED);
		break;
	case SUA_CO_COREF: /* CREF */
	case SUA_CO_RELCO: /* RLC */
	case SUA_CO_CODT: /* DT1 */
	case SUA_CO_CODA: /* AK */
	case SUA_CO_COERR: /* ERR */
		/* DISCARD */
		break;
	case SUA_CO_RELRE: /* RLSD */
		/* Send RLC */
		tx_relco_from_xua(inst, xua);
		break;
	default:
		LOGPSCI(inst, LOGL_NOTICE, "Unhandled %s\n", xua_hdr_dump(xua, &xua_dialect_sua));
		break;
	}
}

/* process received message for invalid source local reference */
static void sccp_scoc_rx_inval_src_ref(struct sccp_connection *conn,
				       struct xua_msg *xua,
				       uint32_t inval_src_ref)
{
	LOGPSCC(conn, LOGL_NOTICE,
		"Received message for source ref %u on conn with mismatching remote ref %u\n",
		inval_src_ref, conn->remote_ref);

	/* we have received a message with invalid source local
	 * reference and thus apply the action indicated in Table
	 * B.2/Q.714 */
	switch (xua->hdr.msg_type) {
	case SUA_CO_RELRE: /* RLSD */
	case SUA_CO_RESRE: /* RSR */
	case SUA_CO_RESCO: /* RSC */
		/* Send ERR */
		tx_coerr_from_xua(conn->inst, xua, SCCP_ERROR_LRN_MISMATCH_INCONSISTENT);
		break;
	case SUA_CO_COIT: /* IT */
		/* FIXME: RLSD to both sides */
		tx_rlsd_from_xua_twoway(conn, xua);
		break;
	case SUA_CO_RELCO: /* RLC */
		/* DISCARD */
		break;
	default:
		LOGPSCC(conn, LOGL_NOTICE, "Unhandled %s\n", xua_hdr_dump(xua, &xua_dialect_sua));
		break;
	}
}

/* process received message for invalid origin point code */
static void sccp_scoc_rx_inval_opc(struct sccp_connection *conn,
				   struct xua_msg *xua)
{
	char buf_opc[MAX_PC_STR_LEN];

	LOGPSCC(conn, LOGL_NOTICE,
		"Received message %s on conn with mismatching remote pc=%u=%s\n",
		xua_hdr_dump(xua, &xua_dialect_sua),
		xua->mtp.opc,
		osmo_ss7_pointcode_print_buf(buf_opc, sizeof(buf_opc), conn->inst->ss7, xua->mtp.opc));

	/* we have received a message with invalid origin PC and thus
	 * apply the action indicated in Table B.2/Q.714 */
	switch (xua->hdr.msg_type) {
	case SUA_CO_RELRE: /* RLSD */
	case SUA_CO_RESRE: /* RSR */
	case SUA_CO_RESCO: /* RSC */
		/* Send ERR */
		tx_coerr_from_xua(conn->inst, xua, SCCP_ERROR_POINT_CODE_MISMATCH);
		break;
	case SUA_CO_RELCO: /* RLC */
	case SUA_CO_CODT: /* DT1 */
	case SUA_CO_CODA: /* AK */
	case SUA_CO_COERR: /* ERR */
		/* DISCARD */
		break;
	default:
		LOGPSCC(conn, LOGL_NOTICE, "Unhandled %s\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		break;
	}
}

/*! \brief Main entrance function for primitives from the SCRC (Routing Control)
 *  \param[in] inst SCCP Instance in which we operate
 *  \param[in] xua SUA message in xua_msg format */
void sccp_scoc_rx_from_scrc(struct osmo_sccp_instance *inst,
			    struct xua_msg *xua)
{
	struct sccp_connection *conn;
	struct osmo_sccp_user *scu;
	uint32_t src_loc_ref;
	int event;

	/* we basically try to convert the SUA message into an event,
	 * and then dispatch the event to the connection-specific FSM.
	 * If it is a CORE (Connect REquest), we create the connection
	 * (and implicitly its FSM) first */

	if (xua->hdr.msg_type == SUA_CO_CORE) {
		scu = sccp_find_user(inst, xua);
		if (!scu) {
			/* this shouldn't happen, as the caller should
			 * have already verified that a local user is
			 * equipped for this SSN */
			LOGPSCI(inst, LOGL_ERROR, "Cannot find user for CORE ?!?\n");
			return;
		}
		/* Allocate new connection */
		conn = conn_create(scu);
		conn->incoming = true;
	} else {
		uint32_t conn_id;
		/* Resolve existing connection */
		conn_id = xua_msg_get_u32(xua, SUA_IEI_DEST_REF);
		conn = sccp_find_conn_by_id(inst, conn_id);
		if (!conn) {
			LOGPSCI(inst, LOGL_NOTICE, "Received %s: Cannot find connection for "
				"local reference %u\n", xua_hdr_dump(xua, &xua_dialect_sua), conn_id);
			sccp_scoc_rx_unass_local_ref(inst, xua);
			return;
		}
	}
	OSMO_ASSERT(conn);
	OSMO_ASSERT(conn->fi);

	LOGPSCC(conn, LOGL_DEBUG, "Received %s\n", xua_hdr_dump(xua, &xua_dialect_sua));

	if (xua->hdr.msg_type != SUA_CO_CORE &&
	    xua->hdr.msg_type != SUA_CO_COAK &&
	    xua->hdr.msg_type != SUA_CO_COREF) {
		if (xua_msg_find_tag(xua, SUA_IEI_SRC_REF)) {
			/* Check if received source local reference !=
			 * the one we saved in local state */
			src_loc_ref = xua_msg_get_u32(xua, SUA_IEI_SRC_REF);
			if (src_loc_ref != conn->remote_ref) {
				sccp_scoc_rx_inval_src_ref(conn, xua, src_loc_ref);
				return;
			}
		}

		/* Check if received OPC != the remote_pc we stored locally */
		if (xua->mtp.opc != conn->remote_pc) {
			sccp_scoc_rx_inval_opc(conn, xua);
			return;
		}
	}

	/* Map from XUA message to event */
	event = xua_msg_event_map(xua, sua_scoc_event_map, ARRAY_SIZE(sua_scoc_event_map));
	if (event < 0) {
		LOGPSCC(conn, LOGL_ERROR, "Cannot map SCRC msg %s to event\n",
			xua_hdr_dump(xua, &xua_dialect_sua));
		/* Table B.1/Q714 states DISCARD for any message with
		 * unknown type */
		return;
	}

	/* Dispatch event to existing connection */
	osmo_fsm_inst_dispatch(conn->fi, event, xua);
}
