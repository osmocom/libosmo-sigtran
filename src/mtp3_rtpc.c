/***********************************************************************
 * MTP Level 3 - Transfer prohibited control (RTPC), ITU Q.704 Figure 44
 ***********************************************************************/

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

#include <stdint.h>

#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include "mtp3_hmdt.h"
#include "mtp3_rtpc.h"
#include "ss7_as.h"
#include "ss7_internal.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "xua_internal.h"
#include "xua_msg.h"

/* Generate a DUNA message to be sent back to originator. */
static struct xua_msg *gen_duna_ret_msg(struct osmo_ss7_instance *inst, const struct xua_msg *orig_xua)
{
	struct xua_msg *xua;
	struct xua_msg_part *rctx_ie;
	unsigned int num_rctx = 0;
	uint32_t rctx = 0;
	uint32_t aff_pc = htonl(orig_xua->mtp.dpc);

	if ((rctx_ie = xua_msg_find_tag(orig_xua, M3UA_IEI_ROUTE_CTX))) {
		rctx = xua_msg_part_get_u32(rctx_ie);
		num_rctx = 1;
	}
	xua = m3ua_encode_duna(&rctx, num_rctx, &aff_pc, 1,
			       "transfer prohibited (inaccessible SP)");
	OSMO_ASSERT(xua);

	xua->mtp = orig_xua->mtp;
	xua->mtp.opc = orig_xua->mtp.dpc;
	xua->mtp.dpc = orig_xua->mtp.opc;
	return xua;
}

 /* Figure 44/Q.704 (sheet 1 of 3), "Message received for inaccessible SP HMRT -> RTPC" */
int mtp3_rtpc_rx_msg_for_inaccessible_sp(struct osmo_ss7_instance *inst, const struct xua_msg *orig_xua)
{
	struct xua_msg *xua;
	char buf_orig_opc[MAX_PC_STR_LEN];
	char buf_orig_dpc[MAX_PC_STR_LEN];
	struct osmo_ss7_route_label rtlabel;
	struct osmo_ss7_route *rt;

	/* TODO: Start T8 */

	/* "transfer prohibited RTPC -> HMRT", "To concerned SP or STP".
	 * See also Q.704 13.2 Transfer-prohibited. */

	/* Note: There's no explicit mention of MTP3 TFP equivalent in RFC4666 (M3UA) specs,
	 * but section 1.4.3.2 explicitly mentions: "TFP ... MUST NOT be encapsulated as
	 * Data message Payload Data and sent either from SG to ASP or from ASP to
	 * SG. The SG MUST terminate these messages and generate M3UA messages,
	 * as appropriate."
	 * Best match for it is DUNA, so DUNA we send.
	 */

	if (osmo_ss7_pc_is_local(inst, orig_xua->mtp.opc)) {
		xua = gen_duna_ret_msg(inst, orig_xua);
		return mtp3_hmdt_message_for_distribution(inst, xua);
	}

	/* We should only be sending DUNA to M3UA peers, hence why we don't
	 * simply call  mtp3_hmrt_message_for_routing() here. */
	rtlabel = (struct osmo_ss7_route_label){
		.opc = orig_xua->mtp.dpc,
		.dpc = orig_xua->mtp.opc,
		.sls = orig_xua->mtp.sls,
	};
	rt = ss7_instance_lookup_route(inst, &rtlabel);
	if (!rt) {
		LOGSS7(inst, LOGL_NOTICE, "Tx TFP (DUNA) inaccessible SP %u=%s to concerned SP %u=%s: no route!\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		return 0;
	}
	if (!rt->dest.as) {
		LOGSS7(inst, LOGL_ERROR, "Tx TFP (DUNA) inaccessible SP %u=%s to concerned SP %u=%s: unsupported for linkset!\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		return 0;
	}

	switch (rt->dest.as->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		LOGSS7(inst, LOGL_INFO, "Message received for inaccessible SP %u=%s. Tx TFP (DUNA) to concerned SP %u=%s\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		xua = gen_duna_ret_msg(inst, orig_xua);
		return m3ua_tx_xua_as(rt->dest.as, xua);
	case OSMO_SS7_ASP_PROT_IPA:
		/* FIXME: No DUNA in IPA, maybe send SUA CLDR (SCCP UDTS) instead? */
		LOGSS7(inst, LOGL_INFO, "Message received for inaccessible SP %u=%s, "
		       "but concerned SP %u=%s is IPA-based and doesn't support TFP (DUNA)\n",
		       orig_xua->mtp.dpc, osmo_ss7_pointcode_print_buf(buf_orig_dpc, sizeof(buf_orig_dpc), inst, orig_xua->mtp.dpc),
		       orig_xua->mtp.opc, osmo_ss7_pointcode_print_buf(buf_orig_opc, sizeof(buf_orig_opc), inst, orig_xua->mtp.opc));
		return 0;
	default:
		LOGSS7(inst, LOGL_ERROR, "DUNA message for ASP of unknown protocol %u\n",
			rt->dest.as->cfg.proto);
		return 0;
	}

	return 0;
}
