/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <errno.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/mtp_sap.h>

#include "ss7_user.h"
#include "ss7_internal.h"
#include "xua_internal.h"

const struct value_string osmo_mtp_prim_type_names[] = {
	{ OSMO_MTP_PRIM_TRANSFER,	"MTP-TRANSFER" },
	{ OSMO_MTP_PRIM_PAUSE,		"MTP-PAUSE" },
	{ OSMO_MTP_PRIM_RESUME,		"MTP-RESUME" },
	{ OSMO_MTP_PRIM_STATUS,		"MTP-STATUS" },
	{ 0, NULL }
};

static char prim_name_buf[128];

static int mtp_prim_hdr_name_buf(char *buf, size_t buflen, const struct osmo_prim_hdr *oph)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	if (!oph) {
		OSMO_STRBUF_PRINTF(sb, "null");
		return sb.chars_needed;
	}

	OSMO_STRBUF_PRINTF(sb, "%s.%s",
			   osmo_mtp_prim_type_name(oph->primitive),
			   osmo_prim_operation_name(oph->operation));
	return sb.chars_needed;
}

char *osmo_mtp_prim_name(const struct osmo_prim_hdr *oph)
{
	mtp_prim_hdr_name_buf(prim_name_buf, sizeof(prim_name_buf), oph);
	return prim_name_buf;
}

/*! \brief Send a MTP SAP Primitive up to the MTP User
 *  \param[in] osu MTP User to whom to send the primitive
 *  \param[in] prim Primitive to send to the user
 *  \returns return value of the MTP User's prim_cb() function
 *
 * Ownership of prim->oph->msg is passed to the user of the registered callback
 */
int ss7_user_mtp_sap_prim_up(const struct osmo_ss7_user *osu, struct osmo_mtp_prim *omp)
{
	LOGPSS7U(osu, LOGL_DEBUG, "Delivering to MTP User: %s\n",
		osmo_mtp_prim_name(&omp->oph));
	return osu->prim_cb(&omp->oph, (void *) osu->priv);
}

/* MTP-User requests to send a MTP-TRANSFER.req via the stack
 *  \param[in] osu MTP User sending us the primitive
 *  \param[in] oph Osmocom primitive sent by the user
 *
 * The oph->msg ownership is transferred to this function, which will free it.
 */
int osmo_ss7_user_mtp_sap_prim_down(struct osmo_ss7_user *osu, struct osmo_mtp_prim *omp)
{
	struct msgb *msg = omp->oph.msg;
	int rc;

	OSMO_ASSERT(omp->oph.sap == MTP_SAP_USER);

	switch (OSMO_PRIM_HDR(&omp->oph)) {
	case OSMO_PRIM(OSMO_MTP_PRIM_TRANSFER, PRIM_OP_REQUEST):
		rc = hmrt_mtp_xfer_request_l4_to_l3(osu->inst, &omp->u.transfer,
						    msgb_l2(msg), msgb_l2len(msg));
		break;
	default:
		LOGPSS7U(osu, LOGL_ERROR, "Ignoring unknown primitive %u:%u\n",
			 omp->oph.primitive, omp->oph.operation);
		rc = -1;
		break;
	}

	msgb_free(msg);
	return rc;
}
