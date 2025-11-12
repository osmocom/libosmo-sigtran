/***********************************************************************
 * MTP Level 3 - Signalling message handling (SMH) Figure 23/Q.704
 ***********************************************************************/

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
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

#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include "xua_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_linkset.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"
#include "ss7_user.h"

/* convert from M3UA message to MTP-TRANSFER.ind osmo_mtp_prim */
static struct osmo_mtp_prim *m3ua_to_xfer_ind(struct xua_msg *xua)
{
	struct osmo_mtp_prim *prim;
	struct osmo_mtp_transfer_param *param;
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	struct m3ua_data_hdr *data_hdr;
	struct msgb *upmsg = m3ua_msgb_alloc("M3UA MTP-TRANSFER.ind");

	if (!data_ie || data_ie->len < sizeof(*data_hdr)) {
		/* FIXME: ERROR message */
		msgb_free(upmsg);
		return NULL;
	}
	data_hdr = (struct m3ua_data_hdr *) data_ie->dat;

	/* fill primitive */
	prim = (struct osmo_mtp_prim *) msgb_put(upmsg, sizeof(*prim));
	param = &prim->u.transfer;
	osmo_prim_init(&prim->oph, MTP_SAP_USER,
			OSMO_MTP_PRIM_TRANSFER,
			PRIM_OP_INDICATION, upmsg);

	m3ua_dh_to_xfer_param(param, data_hdr);
	/* copy data */
	upmsg->l2h = msgb_put(upmsg, data_ie->len - sizeof(*data_hdr));
	memcpy(upmsg->l2h, data_ie->dat+sizeof(*data_hdr), data_ie->len - sizeof(*data_hdr));

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
static int hmdt_message_for_distribution(struct osmo_ss7_instance *inst, struct xua_msg *xua)
{
	struct m3ua_data_hdr *mdh;
	const struct osmo_ss7_user *osu;
	uint32_t service_ind;

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
	osu = ss7_user_find(inst, service_ind);
	if (!osu) {
		/* "Discard Message" */
		LOGSS7(inst, LOGL_NOTICE, "No MTP-User for SI %u\n", service_ind);
		/* FIXME: User Part Unavailable HMDT -> HMRT */
		xua_msg_free(xua);
		return -1;
	}

	/* "MTP Transfer indication HMDT→L4" */
	return deliver_to_mtp_user(osu, xua);
}

/* HMDC->HMRT Msg For Routing; Figure 26/Q.704 */
/* local message was receive d from L4, SRM, SLM, STM or SLTC, or
 * remote message received from L2 and HMDC determined msg for routing
 * Ownership of xua_msg passed is transferred to this function.
 */
static int hmrt_message_for_routing(struct osmo_ss7_instance *inst,
				    struct xua_msg *xua)
{
	uint32_t dpc = xua->mtp.dpc;
	struct osmo_ss7_route_label rtlabel = {
		.opc = xua->mtp.opc,
		.dpc = xua->mtp.dpc,
		.sls = xua->mtp.sls,
	};
	struct osmo_ss7_route *rt;

	/* find route for OPC+DPC+SLS: */
	/* FIXME: unify with gen_mtp_transfer_req_xua() */
	rt = ss7_instance_lookup_route(inst, &rtlabel);
	if (rt) {
		/* FIXME: DPC SP restart? */
		/* FIXME: DPC Congested? */
		/* FIXME: Select link based on SLS */
		/* FIXME: Transmit over respective Link */
		if (rt->dest.as) {
			struct osmo_ss7_as *as = rt->dest.as;

			if (log_check_level(DLSS7, LOGL_DEBUG)) {
				/* osmo_ss7_route_name() calls osmo_ss7_pointcode_print() and
				 * osmo_ss7_pointcode_print2(), guard against its static buffer being
				 * overwritten. */
				const char *rt_name = osmo_ss7_route_name(rt, false);
				LOGSS7(inst, LOGL_DEBUG, "Found route for dpc=%u=%s: %s\n",
				       dpc, osmo_ss7_pointcode_print(inst, dpc), rt_name);
			}

			rate_ctr_inc2(as->ctrg, SS7_AS_CTR_TX_MSU_TOTAL);
			OSMO_ASSERT(xua->mtp.sls <= 0xf);
			rate_ctr_inc2(as->ctrg, SS7_AS_CTR_TX_MSU_SLS_0 + xua->mtp.sls);

			switch (as->cfg.proto) {
			case OSMO_SS7_ASP_PROT_M3UA:
				LOGSS7(inst, LOGL_DEBUG, "rt->dest.as proto is M3UA for dpc=%u=%s\n",
				       dpc, osmo_ss7_pointcode_print(inst, dpc));
				return m3ua_tx_xua_as(as, xua);
			case OSMO_SS7_ASP_PROT_IPA:
				return ipa_tx_xua_as(as, xua);
			default:
				LOGSS7(inst, LOGL_ERROR, "MTP message for ASP of unknown protocol %u\n",
				       as->cfg.proto);
				break;
			}
		} else if (rt->dest.linkset) {
			if (log_check_level(DLSS7, LOGL_ERROR)) {
				/* osmo_ss7_route_name() calls osmo_ss7_pointcode_print() and
				 * osmo_ss7_pointcode_print2(), guard against its static buffer being
				 * overwritten. */
				const char *rt_name = osmo_ss7_route_name(rt, false);
				LOGSS7(inst, LOGL_ERROR,
				       "Found route for dpc=%u=%s: %s, but MTP-TRANSFER.req unsupported for linkset.\n",
				       dpc, osmo_ss7_pointcode_print(inst, dpc), rt_name);
			}
		} else
			OSMO_ASSERT(0);
	} else {
		LOGSS7(inst, LOGL_ERROR, "MTP-TRANSFER.req for dpc=%u=%s: no route!\n",
		       dpc, osmo_ss7_pointcode_print(inst, dpc));
		/* DPC unknown HMRT -> MGMT */
		/* Message Received for inaccesible SP HMRT ->RTPC */
		/* Discard Message */
	}
	xua_msg_free(xua);
	return -1;
}

/* HMDC: Received Message L2 -> L3; Figure 24/Q.704 */
/* This means a message was received from L2 and we have to decide if it
 * is for the local stack (HMDT) or for routng (HMRT)
 * Ownership of xua_msg passed is transferred to this function. */
int m3ua_hmdc_rx_from_l2(struct osmo_ss7_instance *inst, struct xua_msg *xua)
{
	uint32_t dpc = xua->mtp.dpc;
	if (osmo_ss7_pc_is_local(inst, dpc)) {
		LOGSS7(inst, LOGL_DEBUG, "%s(): found dpc=%u=%s as local\n",
		       __func__, dpc, osmo_ss7_pointcode_print(inst, dpc));
		return hmdt_message_for_distribution(inst, xua);
	} else {
		LOGSS7(inst, LOGL_DEBUG, "%s(): dpc=%u=%s not local, message is for routing\n",
		       __func__, dpc, osmo_ss7_pointcode_print(inst, dpc));
		return hmrt_message_for_routing(inst, xua);
	}
}

/* Figure 26/Q.704 (sheet 1 of 5) "MTP Transfer request L4→L3" */
int hmrt_mtp_xfer_request_l4_to_l3(struct osmo_ss7_instance *inst, const struct osmo_mtp_transfer_param *param, uint8_t *user_data, size_t user_data_len)
{
	struct m3ua_data_hdr data_hdr;
	struct xua_msg *xua;

	/* convert from osmo_mtp_prim MTP-TRANSFER.req to xua_msg */
	mtp_xfer_param_to_m3ua_dh(&data_hdr, param);
	xua = m3ua_xfer_from_data(&data_hdr, user_data, user_data_len);
	OSMO_ASSERT(xua);
	xua->mtp = *param;

	/* normally we would call hmrt_message_for_routing() here, if we were to follow the state
	 * diagrams of the ITU-T Q.70x specifications.  However, what if a local MTP user sends a
	 * MTP-TRANSFER.req to a local SSN? This wouldn't work as per the spec, but I believe it
	 * is a very useful feature (aka "loopback device" in IPv4). So we call
	 * m3ua_hmdc_rx_from_l2() just like the MTP-TRANSFER had been received from L2. */
	return m3ua_hmdc_rx_from_l2(inst, xua);
}
