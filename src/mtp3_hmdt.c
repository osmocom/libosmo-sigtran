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

#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/mtp_sap.h>

#include "ss7_instance.h"
#include "ss7_user.h"
#include "xua_internal.h"
#include "xua_msg.h"


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
		/* FIXME: User Part Unavailable HMDT -> HMRT */
		xua_msg_free(xua);
		return -1;
	}

	/* "MTP Transfer indication HMDT→L4" */
	return deliver_to_mtp_user(osu, xua);
}
