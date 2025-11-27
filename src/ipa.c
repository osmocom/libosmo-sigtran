/* implementation of IPA/SCCPlite transport */

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

#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/gsm/ipa.h>
#include <osmocom/gsm/protocol/ipaccess.h>

//#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>

#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "mtp3_hmdc.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_internal.h"
#include "xua_asp_fsm.h"
#include "xua_internal.h"
#include "xua_msg.h"

/* generate a msgb containing an IPA CCM PING message */
struct msgb *ipa_gen_ping(void)
{
	/* sufficient headroom for osmo_ipa_msg_push_header() */
	struct msgb *msg = ipa_msg_alloc(16);
	if (!msg)
		return NULL;

	msgb_put_u8(msg, IPAC_MSGT_PING);
	ipa_prepend_header(msg, IPAC_PROTO_IPACCESS);

	return msg;
}

struct msgb *ipa_to_msg(struct xua_msg *xua)
{
	struct xua_msg_part *data_ie;
	struct m3ua_data_hdr *data_hdr;
	struct msgb *msg;
	unsigned int src_len;
	const uint8_t *src;
	uint8_t *dst;

	/* we're actually only interested in the data part */
	data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	if (!data_ie || data_ie->len < sizeof(struct m3ua_data_hdr))
		return NULL;
	data_hdr = (struct m3ua_data_hdr *) data_ie->dat;

	/* and even the data part still has the header prepended */
	src = data_ie->dat + sizeof(struct m3ua_data_hdr);
	src_len = data_ie->len - sizeof(struct m3ua_data_hdr);

	if (src_len == 0) {
		LOGP(DLSS7, LOGL_NOTICE, "Discarding Tx empty IPA msg/payload\n");
		return NULL;
	}

	switch (data_hdr->si) {
	case MTP_SI_SCCP:
		/* sufficient headroom for osmo_ipa_msg_push_header() */
		msg = ipa_msg_alloc(16);
		if (!msg)
			return NULL;
		dst = msgb_put(msg, src_len);
		memcpy(dst, src, src_len);
		osmo_ipa_msg_push_header(msg, IPAC_PROTO_SCCP);
		return msg;
	case MTP_SI_NI11_OSMO_IPA:
		/* Process our SI extension: full IPA with hdr + payload, used in SCCPlite
		 * between BSC and MSC to send MGCP and CTRL over IPA multiplex */
		msg = msgb_alloc(src_len, "MTP_SI_NI11_OSMO_IPA");
		if (!msg)
			return NULL;
		dst = msgb_put(msg, src_len);
		memcpy(dst, src, src_len);
		return msg;
	default:
		LOGP(DLSS7, LOGL_ERROR, "Cannot transmit non-SCCP SI (%u) to IPA peer\n",
		     data_hdr->si);
		return NULL;
	}
}

/*! \brief Send a given xUA message via a given IPA "Application Server"
 *  \param[in] as Application Server through which to send \a xua
 *  \param[in] xua xUA message to be sent
 *  \return 0 on success; negative on error
 *
 *  This function takes ownership of xua msg passed to it.
 */
int ipa_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	OSMO_ASSERT(as->cfg.proto == OSMO_SS7_ASP_PROT_IPA);

	return xua_as_transmit_msg(as, xua);
}

static int ipa_rx_msg_ccm(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	uint8_t msg_type = msg->l2h[0];
	int rc = 0;

	LOGPASP(asp, DLSS7, LOGL_DEBUG, "%s:%s\n", __func__, msgb_hexdump(msg));

	/* Convert CCM into events to the IPA_ASP_FSM */
	switch (msg_type) {
	case IPAC_MSGT_ID_ACK:
		osmo_fsm_inst_dispatch(asp->fi, IPA_ASP_E_ID_ACK, msg);
		break;
	case IPAC_MSGT_ID_RESP:
		osmo_fsm_inst_dispatch(asp->fi, IPA_ASP_E_ID_RESP, msg);
		break;
	case IPAC_MSGT_ID_GET:
		osmo_fsm_inst_dispatch(asp->fi, IPA_ASP_E_ID_GET, msg);
		break;
	case IPAC_MSGT_PING:
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_ASPSM_BEAT, msg);
		break;
	case IPAC_MSGT_PONG:
		osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_ASPSM_BEAT_ACK, msg);
		break;
	default:
		LOGPASP(asp, DLSS7, LOGL_NOTICE, "Unknown CCM Message 0x%02x: %s\n",
			msg_type, msgb_hexdump(msg));
		rc = -1;
	}

	return rc;
}

struct osmo_ss7_as *ipa_find_as_for_asp(struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_as *as;

	/* in the IPA case, we assume there is a 1:1 mapping between the
	 * ASP and the AS.  An AS without ASP means there is no
	 * connection, and an ASP without AS means that we don't (yet?)
	 * know the identity of the peer */

	llist_for_each_entry(as, &asp->inst->as_list, list) {
		if (osmo_ss7_as_has_asp(as, asp))
			return as;
	}
	return NULL;
}

/* Patch a SCCP message and add point codes to Called/Calling Party (if missing) */
static struct msgb *patch_sccp_with_pc(const struct osmo_ss7_asp *asp, const struct msgb *sccp_msg_in,
					uint32_t opc, uint32_t dpc)
{
	struct osmo_sccp_addr addr;
	struct msgb *sccp_msg_out;
	struct xua_msg *sua;
	int rc;

	/* start by converting SCCP to SUA */
	sua = osmo_sccp_to_xua(sccp_msg_in);
	if (!sua) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Couldn't convert SCCP to SUA: %s\n",
			msgb_hexdump(sccp_msg_in));
		return NULL;
	}

	rc = sua_addr_parse(&addr, sua, SUA_IEI_DEST_ADDR);
	switch (rc) {
	case 0:
		if (addr.presence & OSMO_SCCP_ADDR_T_PC)
			break;
		/* if there's no point code in dest_addr, add one */
		addr.presence |= OSMO_SCCP_ADDR_T_PC;
		addr.pc = dpc;
		xua_msg_free_tag(sua, SUA_IEI_DEST_ADDR);
		xua_msg_add_sccp_addr(sua, SUA_IEI_DEST_ADDR, &addr);
		break;
	case -ENODEV: /* no destination address in message */
		break;
	default: /* some other error */
		xua_msg_free(sua);
		return NULL;
	}

	rc = sua_addr_parse(&addr, sua, SUA_IEI_SRC_ADDR);
	switch (rc) {
	case 0:
		if (addr.presence & OSMO_SCCP_ADDR_T_PC)
			break;
		/* if there's no point code in src_addr, add one */
		addr.presence |= OSMO_SCCP_ADDR_T_PC;
		addr.pc = opc;
		xua_msg_free_tag(sua, SUA_IEI_SRC_ADDR);
		xua_msg_add_sccp_addr(sua, SUA_IEI_SRC_ADDR, &addr);
		break;
	case -ENODEV: /* no source address in message */
		break;
	default: /* some other error */
		xua_msg_free(sua);
		return NULL;
	}

	/* re-encode SUA to SCCP and return */
	sccp_msg_out = osmo_sua_to_sccp(sua);
	if (!sccp_msg_out)
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Couldn't re-encode SUA to SCCP\n");
	xua_msg_free(sua);
	return sccp_msg_out;
}

/* Received an IPA frame containing either SCCP, MGCP or CTRL over the IPA multiplex.
 * All those are either forwarded (routing) or locally distributed up the stack to an MTP User. */
static int ipa_rx_msg_up(struct osmo_ss7_asp *asp, struct msgb *msg, uint8_t sls)
{
	int rc;
	enum ipaccess_proto ipa_proto = osmo_ipa_msgb_cb_proto(msg);
	struct m3ua_data_hdr data_hdr;
	struct xua_msg *xua = NULL;
	struct osmo_ss7_as *as = ipa_find_as_for_asp(asp);
	uint32_t opc, dpc;

	if (!as) {
		LOGPASP(asp, DLSS7, LOGL_ERROR, "Rx message for IPA ASP without AS?!\n");
		return -1;
	}

	rate_ctr_inc2(as->ctrg, SS7_AS_CTR_RX_MSU_TOTAL);
	OSMO_ASSERT(sls <= 0xf);
	rate_ctr_inc2(as->ctrg, SS7_AS_CTR_RX_MSU_SLS_0 + sls);

	/* We have received an IPA-encapsulated SCCP message, without
	 * any MTP routing label.  Furthermore, the SCCP Called/Calling
	 * Party are SSN-only, with no GT or PC.  This means we have no
	 * real idea where it came from, nor where it goes to.  We could
	 * simply treat it as being for the local point code, but then
	 * this means that we would have to implement SCCP connection
	 * coupling in order to route the connections to any other point
	 * code.  The reason for this is the lack of addressing
	 * information inside the non-CR/CC connection oriented
	 * messages.
	 *
	 * The only other alternative we have is to:
	 *
	 * ASP role: we assume whatever was received at the ASP/AS was meant to
	 * reach us and hence set the DPC to the PC configured in the
	 * 'routing-key'. In this case the 'override OPC' is used so that upper
	 * layers can find out where it came from, so it can answer back if needed.
	 *
	 * SG role (STP): By default, the AS associated with the ASP assumes the
	 * OPC of the message received was transmitted to us from the PC
	 * configured in the 'routing-key'. If set, 'override OPC' can be used
	 * to also tweak the originating PC, which can be useful in setups with
	 * traffic coming from another STP where want to set eg. the OPC to the
	 * PC of the originating AS. In this case the 'override DPC'.
	 * allows to find out where those messages are to be routed to in the
	 * routing decision.
	 *
	 * This is all quite ugly, but then what can we do :/
	 */

	/* First, determine the DPC and OPC to use */
	if (asp->cfg.role == OSMO_SS7_ASP_ROLE_ASP) {
		/* Source: Based on VTY config */
		opc = as->cfg.pc_override.opc;
		/* Destination: PC of the routing key */
		dpc = as->cfg.routing_key.pc;
	} else {
		/* Source: if set, based on VTY config,
		 * otherwise by default the PC of the routing key */
		if (as->cfg.pc_override.opc_enabled)
			opc = as->cfg.pc_override.opc;
		else
			opc = as->cfg.routing_key.pc;
		/* Destination: Based on VTY config */
		dpc = as->cfg.pc_override.dpc;
	}

	/* Second, create a MTP3/M3UA label with those point codes */
	memset(&data_hdr, 0, sizeof(data_hdr));
	data_hdr.opc = osmo_htonl(opc);
	data_hdr.dpc = osmo_htonl(dpc);
	data_hdr.sls = sls;
	data_hdr.ni = as->inst->cfg.network_indicator;

	switch (ipa_proto) {
	case IPAC_PROTO_SCCP:
		/* Third, patch this into the SCCP message and create M3UA message in XUA structure  */
		data_hdr.si = MTP_SI_SCCP;
		if (as->cfg.pc_override.sccp_mode == OSMO_SS7_PATCH_BOTH) {
			struct msgb *msg_patched = patch_sccp_with_pc(asp, msg, opc, dpc);
			if (!msg_patched) {
				LOGPASP(asp, DLSS7, LOGL_ERROR, "Unable to patch PC into SCCP message; dropping\n");
				return -1;
			}
			xua = m3ua_xfer_from_data(&data_hdr, msgb_data(msg_patched), msgb_length(msg_patched));
			msgb_free(msg_patched);
		} else {
			xua = m3ua_xfer_from_data(&data_hdr, msgb_data(msg), msgb_length(msg));
		}
		break;
	default:
		/* Submit IPA headers+payload is up the stack so MTP-USER can receive it. This is useful to
		 * obtain MGCP/CTRL proto payloads from the SCCPLite IPA multiplex. */
		data_hdr.si = MTP_SI_NI11_OSMO_IPA;
		osmo_ipa_msg_push_headers(msg, ipa_proto, osmo_ipa_msgb_cb_proto_ext(msg));
		xua = m3ua_xfer_from_data(&data_hdr, msgb_data(msg), msgb_length(msg));
		break;
	}

	/* Update xua->mtp with values from data_hdr */
	m3ua_dh_to_xfer_param(&xua->mtp, &data_hdr);

	/* Pass on as if we had received it from an M3UA ASP.
	 * xua ownership is passed here: */
	rc = mtp3_hmdc_rx_from_l2(asp->inst, xua);
	return rc;
}

/*! \brief process M3UA message received from socket
 *  \param[in] asp Application Server Process receiving \a msg
 *  \param[in] msg received message buffer. It is kept owned by the caller.
 *  \param[in] sls The SLS (signaling link selector) field to use in the generated M3UA header
 *  \returns 0 on success; negative on error */
int ipa_rx_msg(struct osmo_ss7_asp *asp, struct msgb *msg, uint8_t sls)
{
	int rc;

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA);

	/* Here IPA headers have already been validated and were stored in
	 * osmo_ipa_msgb_cb_proto(_ext)(), and msgb_data() and msgb_l2() both
	 * point to IPA payload. */

	switch (osmo_ipa_msgb_cb_proto(msg)) {
	case IPAC_PROTO_IPACCESS:
		rc = ipa_rx_msg_ccm(asp, msg);
		break;
	default:
		rc = ipa_rx_msg_up(asp, msg, sls);
		break;
	}

	return rc;
}
