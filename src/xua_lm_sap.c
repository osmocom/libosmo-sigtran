/* M3UA/SUA <-> XUA Layer Manager SAP, RFC466 1.6.3 & RFC3868 1.6.3 */
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

#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>

#include "xua_asp_fsm.h"
#include "xua_internal.h"
#include "ss7_asp.h"


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

/* M-RK_REG request */
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_rk_reg_req(const struct osmo_ss7_routing_key *rkey,
						      enum osmo_ss7_as_traffic_mode mode)
{
	struct osmo_xlm_prim *prim;
	prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_REQUEST);
	OSMO_ASSERT(prim);
	prim->u.rk_reg.key = *rkey;
	prim->u.rk_reg.traf_mode = mode;
	return prim;
}

/* M-RK_REG confirm */
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_rk_reg_cfm(const struct osmo_ss7_routing_key *rkey, uint32_t status)
{
	struct osmo_xlm_prim *prim;
	prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_CONFIRM);
	OSMO_ASSERT(prim);
	prim->u.rk_reg.key = *rkey;
	prim->u.rk_reg.status = status;
	return prim;
}

/* M-RK_DEREG confirm */
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_rk_dereg_cfm(uint32_t route_ctx, uint32_t status)
{
	struct osmo_xlm_prim *prim;
	prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_RK_DEREG, PRIM_OP_CONFIRM);
	OSMO_ASSERT(prim);
	prim->u.rk_dereg.route_ctx = route_ctx;
	prim->u.rk_dereg.status = status;
	return prim;
}

/* M-ERROR indication */
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_error_ind(uint32_t err_code)
{
	struct osmo_xlm_prim *prim;
	prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_ERROR, PRIM_OP_INDICATION);
	OSMO_ASSERT(prim);
	prim->u.error.code = err_code;
	return prim;
}

/* M-NOTIFY indication */
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_notify_ind(const struct osmo_xlm_prim_notify *ntfy)
{
	struct osmo_xlm_prim *prim;
	prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_NOTIFY, PRIM_OP_INDICATION);
	OSMO_ASSERT(prim);
	prim->u.notify = *ntfy;
	return prim;
}

/* Send a XUA LM Primitive from M3UA/SUA to the XUA Layer Manager (LM) */
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

/* process a primitive from the xUA Layer Manager (LM) to M3UA/SUA */
int osmo_xlm_sap_down(struct osmo_ss7_asp *asp, struct osmo_prim_hdr *oph)
{
	struct osmo_xlm_prim *prim = (struct osmo_xlm_prim *) oph;

	LOGPASP(asp, DLSS7, LOGL_DEBUG, "Received XUA Layer Manager Primitive: %s)\n",
		osmo_xlm_prim_name(&prim->oph));

	switch (OSMO_PRIM_HDR(&prim->oph)) {
	case OSMO_PRIM(OSMO_XLM_PRIM_M_SCTP_RELEASE, PRIM_OP_REQUEST):
		/* Layer Manager asks us to release an SCTP association with the peer */
		ss7_asp_disconnect_stream(asp);
		break;
	case OSMO_PRIM(OSMO_XLM_PRIM_M_ASP_UP, PRIM_OP_REQUEST):
		/* Layer Manager asks us to send an ASPUP REQ */
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_M_ASP_UP_REQ, NULL);
		break;
	case OSMO_PRIM(OSMO_XLM_PRIM_M_ASP_ACTIVE, PRIM_OP_REQUEST):
		/* Layer Manager asks us to send an ASPAC REQ */
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_M_ASP_ACTIVE_REQ, NULL);
		break;
	case OSMO_PRIM(OSMO_XLM_PRIM_M_RK_REG, PRIM_OP_REQUEST):
		/* Layer Manager asks us to send a Routing Key Reg Request */
		xua_rkm_send_reg_req(asp, &prim->u.rk_reg.key, prim->u.rk_reg.traf_mode);
		break;
	case OSMO_PRIM(OSMO_XLM_PRIM_M_RK_DEREG, PRIM_OP_REQUEST):
		/* Layer Manager asks us to send a Routing Key De-Reg Request */
		xua_rkm_send_dereg_req(asp, prim->u.rk_dereg.route_ctx);
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Unknown XUA Layer Manager Primitive: %s\n",
			osmo_xlm_prim_name(&prim->oph));
		break;
	}

	msgb_free(prim->oph.msg);
	return 0;
}

/* wrapper around osmo_xlm_sap_down for primitives without data */
int xlm_sap_down_simple(struct osmo_ss7_asp *asp,
			enum osmo_xlm_prim_type prim_type,
			enum osmo_prim_operation op)
{
	struct osmo_xlm_prim *prim = xua_xlm_prim_alloc(prim_type, op);
	OSMO_ASSERT(prim);
	return osmo_xlm_sap_down(asp, &prim->oph);
}
