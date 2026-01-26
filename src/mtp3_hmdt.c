/***********************************************************************
 * MTP Level 3 - Message Distribution (HMDT), ITU Q.704 Figure 25
 ***********************************************************************/

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
 *
 */

#include <osmocom/core/logging.h>

#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/mtp_sap.h>

#include "ss7_as.h"
#include "ss7_instance.h"
#include "ss7_internal.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_user.h"
#include "xua_internal.h"
#include "xua_msg.h"

/* Generate a DUPU message to be sent back to originator. */
static struct xua_msg *gen_dupu_ret_msg(enum osmo_ss7_asp_protocol proto, uint8_t user_part, const struct xua_msg *orig_xua)
{
	struct xua_msg *xua;
	struct xua_msg_part *rctx_ie;
	unsigned int num_rctx = 0;
	uint32_t rctx = 0;
	const char *info_str = "(Local) User Part Unavailable";
	const uint16_t cause = MTP_UNAVAIL_C_UNKNOWN;

	switch (proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		if ((rctx_ie = xua_msg_find_tag(orig_xua, M3UA_IEI_ROUTE_CTX))) {
			rctx = xua_msg_part_get_u32(rctx_ie);
			num_rctx = 1;
		}
		xua = m3ua_encode_dupu(&rctx, num_rctx, orig_xua->mtp.dpc, user_part, cause, info_str);
		break;
	case OSMO_SS7_ASP_PROT_SUA:
		if ((rctx_ie = xua_msg_find_tag(orig_xua, SUA_IEI_ROUTE_CTX))) {
			rctx = xua_msg_part_get_u32(rctx_ie);
			num_rctx = 1;
		}
		xua = sua_encode_dupu(&rctx, num_rctx, orig_xua->mtp.dpc, user_part, cause, info_str);
		break;
	default:
		OSMO_ASSERT(0);
	}
	OSMO_ASSERT(xua);

	xua->mtp = orig_xua->mtp;
	xua->mtp.opc = orig_xua->mtp.dpc;
	xua->mtp.dpc = orig_xua->mtp.opc;
	return xua;
}

/* ITU Q.704 Figure 25/Q.704 (sheet 2 of 3) "User Part Unavailable HMDT -> HMRT"
 * See also ITU Q.704 2.4.2 */
static int mtp3_hmdt_rx_msg_for_local_unavailable_part(struct osmo_ss7_instance *inst, uint8_t user_part, const struct xua_msg *orig_xua)
{
	struct xua_msg *xua;
	char buf_orig_opc[MAX_PC_STR_LEN];
	char buf_orig_dpc[MAX_PC_STR_LEN];
	struct osmo_ss7_route_label rtlabel;
	struct osmo_ss7_route *rt;

	if (osmo_ss7_pc_is_local(inst, orig_xua->mtp.opc)) {
		/* This shouldn't happen, if a MTP3 User sends data down the
		 * stack it should also be there to receive it back and hence we
		 * shouldn't have entered this step... */
		LOGSS7(inst, LOGL_ERROR, "Rx xUA message from local PC and unavailable part!\n");
		return -1;
	}

	/* We should only be sending DUPU to M3UA peers, hence why we don't
	 * simply call  mtp3_hmrt_message_for_routing() here. */
	rtlabel = (struct osmo_ss7_route_label){
		.opc = orig_xua->mtp.dpc,
		.dpc = orig_xua->mtp.opc,
		.sls = orig_xua->mtp.sls,
	};
	rt = ss7_instance_lookup_route(inst, &rtlabel);
	if (!rt) {
		LOGSS7(inst, LOGL_NOTICE, "Tx DUPU %u=%s User %u=%s to concerned SP %u=%s: no route!\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       user_part, get_value_string(mtp_si_vals, user_part),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		return 0;
	}
	if (!rt->dest.as) {
		LOGSS7(inst, LOGL_ERROR, "Tx DUPU %u=%s User %u=%s to concerned SP %u=%s: unsupported for linkset!\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       user_part, get_value_string(mtp_si_vals, user_part),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		return 0;
	}

	switch (rt->dest.as->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
	case OSMO_SS7_ASP_PROT_SUA:
		LOGSS7(inst, LOGL_INFO, "Message received for unavailable SP %u=%s User %u=%s. Tx DUPU to concerned SP %u=%s\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       user_part, get_value_string(mtp_si_vals, user_part),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		xua = gen_dupu_ret_msg(rt->dest.as->cfg.proto, user_part, orig_xua);
		return m3ua_tx_xua_as(rt->dest.as, xua);
	case OSMO_SS7_ASP_PROT_IPA:
		/* FIXME: No DUPU in IPA, maybe send SUA CLDR (SCCP UDTS) instead? (see send_back_udts()) */
		LOGSS7(inst, LOGL_INFO, "Message received for unavailable SP %u=%s User %u=%s, "
		       "but concerned SP %u=%s is IPA-based and doesn't support DUPU\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       user_part, get_value_string(mtp_si_vals, user_part),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		return 0;
	default:
		LOGSS7(inst, LOGL_ERROR, "DUPU message for ASP of unknown protocol %u\n",
			rt->dest.as->cfg.proto);
		return 0;
	}

	return 0;
}

/* convert from M3UA message to MTP-TRANSFER.ind osmo_mtp_prim */
static struct osmo_mtp_prim *m3ua_to_xfer_ind(struct xua_msg *xua)
{
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	struct osmo_mtp_prim *prim;
	struct m3ua_data_hdr *data_hdr;

	if (!data_ie || data_ie->len < sizeof(*data_hdr)) {
		/* FIXME: ERROR message */
		return NULL;
	}
	data_hdr = (struct m3ua_data_hdr *) data_ie->dat;

	prim = mtp_prim_xfer_ind_alloc(NULL,
				       data_ie->dat + sizeof(*data_hdr),
				       data_ie->len - sizeof(*data_hdr));
	m3ua_dh_to_xfer_param(&prim->u.transfer, data_hdr);

	return prim;
}

/* delivery given XUA message to given SS7 user
 * Ownership of xua_msg passed is transferred to this function.
 */
static int deliver_to_mtp_user(const struct osmo_ss7_user *osu, struct xua_msg *xua)
{
	struct osmo_mtp_prim *prim;
	int rc;

	/* Create MTP-TRANSFER.ind and feed to user */
	prim = m3ua_to_xfer_ind(xua);
	if (!prim) {
		rc = -1;
		goto ret_free;
	}
	prim->u.transfer = xua->mtp;

	rc = ss7_user_mtp_sap_prim_up(osu, prim);

ret_free:
	xua_msg_free(xua);
	return rc;
}

/* HMDC -> HMDT: Message for distribution; Figure 25/Q.704 */
/* This means it is a message we received from remote/L2, and it is to
 * be routed to a local user part.
 * Ownership of xua_msg passed is transferred to this function.
 */
int mtp3_hmdt_message_for_distribution(struct osmo_ss7_instance *inst, struct xua_msg *xua)
{
	struct m3ua_data_hdr *mdh;
	const struct osmo_ss7_user *osu;
	uint32_t service_ind;
	int rc;

	switch (xua->hdr.msg_class) {
	case M3UA_MSGC_XFER:
		switch (xua->hdr.msg_type) {
		case M3UA_XFER_DATA:
			mdh = data_hdr_from_m3ua(xua);
			service_ind = mdh->si & 0xf;
			break;
		default:
			LOGSS7(inst, LOGL_ERROR, "Unknown M3UA XFER Message Type %u\n", xua->hdr.msg_type);
			xua_msg_free(xua);
			return -1;
		}
		break;
	case M3UA_MSGC_SNM:
		/* FIXME */
		/* FIXME: SI = Signalling Network Management -> SRM/SLM/STM */
		/* FIXME: SI = Signalling Network Testing and Maintenance -> SLTC */
	default:
		/* Discard Message */
		LOGSS7(inst, LOGL_ERROR, "Unknown M3UA Message Class %u\n", xua->hdr.msg_class);
		xua_msg_free(xua);
		return -1;
	}

	/* "User Part Available?" */
	osu = osmo_ss7_user_find_by_si(inst, service_ind);
	if (!osu) {
		/* "Discard Message" */
		LOGSS7(inst, LOGL_NOTICE, "No MTP-User for SI %u\n", service_ind);
		/* User Part Unavailable HMDT -> HMRT */
		rc = mtp3_hmdt_rx_msg_for_local_unavailable_part(inst, service_ind, xua);
		xua_msg_free(xua);
		return rc;
	}

	/* "MTP Transfer indication HMDT→L4" */
	return deliver_to_mtp_user(osu, xua);
}
