/* TCAP ID based ASP Load-Sharing */

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

#include <osmocom/core/bit32gen.h>
#include <osmocom/core/byteswap.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/talloc.h>

#include <osmocom/netif/ipa.h>

#include <osmocom/sccp/sccp_types.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/tcap/OCTET_STRING.h>
#include <osmocom/tcap/TCAP_TCMessage.h>
#include <osmocom/tcap/tcap.h>

#include "mtp3_hmrt.h"
#include "ss7_as.h"
#include "sccp_internal.h"
#include "ss7_asp.h"
#include "ss7_internal.h"
#include "ss7_vty.h"
#include "tcap_as_loadshare.h"
#include "tcap_trans_tracking.h"
#include "xua_internal.h"

#define OTID_SET 1 << 0
#define DTID_SET 1 << 1

struct tcap_parsed {
	TCAP_TCMessage_PR present;
	uint32_t otid;
	uint32_t dtid;
};

static inline uint32_t tcap_id_from_octet_str(const OCTET_STRING_t *src)
{
	OSMO_ASSERT(src->size == 4);

	return osmo_load32be(src->buf);
}

/* returns negative on error, mask with any/both OTID_SET|DTID_SET on success */
static int parse_tcap(struct osmo_ss7_as *as, const uint8_t *data, size_t len, struct tcap_parsed *ids)
{
	int rc;
	struct TCAP_TCMessage tcap;
	struct TCAP_TCMessage *tcapmsg = &tcap;

	OSMO_ASSERT(ids);

	rc = osmo_asn1_tcap_decode(tcapmsg, data, len);
	if (rc < 0) {
		LOGPAS(as, DLTCAP, LOGL_DEBUG, "Error decoding TCAP message rc: %d, message: %s\n",
		       rc, osmo_hexdump(data, len));
		goto free_asn;
	}

	ids->present = tcapmsg->present;
	switch (tcapmsg->present) {
	case TCAP_TCMessage_PR_begin:
	{
		TCAP_Begin_t part = tcapmsg->choice.begin;
		ids->otid = tcap_id_from_octet_str(&part.otid);
		rc = OTID_SET;
		break;
	}
	case TCAP_TCMessage_PR_continue:
	{
		TCAP_Continue_t part = tcapmsg->choice.Continue;
		ids->otid = tcap_id_from_octet_str(&part.otid);
		ids->dtid = tcap_id_from_octet_str(&part.dtid);
		rc = OTID_SET | DTID_SET;
		break;
	}
	case TCAP_TCMessage_PR_end:
	{
		TCAP_End_t part = tcapmsg->choice.end;
		ids->dtid = tcap_id_from_octet_str(&part.dtid);
		rc = DTID_SET;
		break;
	}
	case TCAP_TCMessage_PR_abort:
	{
		TCAP_Abort_t part = tcapmsg->choice.abort;
		ids->dtid = tcap_id_from_octet_str(&part.dtid);
		rc = DTID_SET;
		break;
	}

	/* No TID present */
	case TCAP_TCMessage_PR_unidirectional:
		rc = 0;
		break;
	default:
		rc = -EINVAL;
		break;
	}

free_asn:
	osmo_asn1_tcap_TCMessage_free_contents(tcapmsg);
	return rc;
}

static inline uint32_t tcap_gen_hash(uint32_t pc, uint8_t ssn)
{
	ssn ^= ((pc >> 24) & 0xff);
	return ((uint32_t)ssn << 24) | (pc & 0xffffff);
}

static inline uint64_t tcap_gen_hash_addr(const struct osmo_sccp_addr *addr)
{
	uint8_t ssn = 0;
	uint32_t pc = 0xffffffff;

	if (addr->presence & OSMO_SCCP_ADDR_T_PC)
		pc = addr->pc;

	if (addr->presence & OSMO_SCCP_ADDR_T_SSN)
		ssn = addr->ssn;

	return tcap_gen_hash(pc, ssn);
}

/* TODO: potential optimisation:
 * Use a sorted list under the hash (tid_range{hash(pc, ssn, tcrng_entry)} -> (struct tcrng_entry {hlist, tid_start, tid_end})
 */
static struct osmo_ss7_asp *tcap_hlist_get(const struct osmo_ss7_as *as, uint32_t pc, uint8_t ssn, uint32_t tid)
{
	struct tcap_range *tcrng;
	struct osmo_ss7_asp *asp = NULL;

	hash_for_each_possible(as->tcap.tid_ranges, tcrng, list, tcap_gen_hash(pc, ssn)) {
		if (tcrng->pc != pc || tcrng->ssn != ssn)
			continue;

		if (tcap_range_matches(tcrng, tid)) {
			asp = tcrng->asp;
			break;
		}
	}

	return asp;
}

struct osmo_ss7_asp *tcap_as_asp_find_by_tcap_id(
		struct osmo_ss7_as *as,
		struct osmo_sccp_addr *calling_addr,
		struct osmo_sccp_addr *called_addr,
		uint32_t otid)
{
	struct osmo_ss7_asp *asp = NULL;

	uint8_t ssn = 0;
	uint32_t pc = TCAP_PC_WILDCARD;

	if (called_addr->presence & OSMO_SCCP_ADDR_T_PC)
		pc = called_addr->pc;

	if (called_addr->presence & OSMO_SCCP_ADDR_T_SSN)
		ssn = called_addr->ssn;

	/* check full range of PC/SSN */
	if (as->tcap.contains_pc && as->tcap.contains_ssn) {
		asp = tcap_hlist_get(as, pc, ssn, otid);
		if (asp)
			return asp;
	}

	/* check with PC wildcard */
	if (as->tcap.contains_ssn) {
		asp = tcap_hlist_get(as, TCAP_PC_WILDCARD, ssn, otid);
		if (asp)
			return asp;
	}

	/* check with SSN wildcard */
	if (as->tcap.contains_pc) {
		asp = tcap_hlist_get(as, pc, TCAP_SSN_WILDCARD, otid);
		if (asp)
			return asp;
	}

	/* check with PC/SSN wildcard */
	return tcap_hlist_get(as, TCAP_PC_WILDCARD, TCAP_SSN_WILDCARD, otid);
}

static struct tcap_range *tcap_overlap_tid(struct osmo_ss7_as *as, uint32_t pc, uint8_t ssn,
			      uint32_t tid_start, uint32_t tid_end)
{
	struct tcap_range *tcrng;

	hash_for_each_possible(as->tcap.tid_ranges, tcrng, list, tcap_gen_hash(pc, ssn)) {
		if (tcrng->pc != pc || tcrng->ssn != ssn)
			continue;

		if (tcap_range_overlaps(tcrng, tid_start, tid_end))
			return tcrng;
	}

	return NULL;
}

static struct osmo_ss7_asp *find_asp_no_tcap_range(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;
	unsigned int first_idx;

	first_idx = (as->cfg.loadshare.tcap.last_asp_idx_sent + 1) % ARRAY_SIZE(as->cfg.asps);
	i = first_idx;
	do {
		asp = as->cfg.asps[i];
		if (asp && osmo_ss7_asp_active(asp) && asp->tcap.enabled)
			break;
		i = (i + 1) % ARRAY_SIZE(as->cfg.asps);
	} while (i != first_idx);
	as->cfg.loadshare.tcap.last_asp_idx_sent = i;

	return asp;
}

static bool ssn_contains_tcap(uint8_t ssn)
{
	switch (ssn) {
	case OSMO_SCCP_SSN_MAP:
	case OSMO_SCCP_SSN_HLR:
	case OSMO_SCCP_SSN_VLR:
	case OSMO_SCCP_SSN_MSC:
	case OSMO_SCCP_SSN_EIR:
	case OSMO_SCCP_SSN_AUC:
	case OSMO_SCCP_SSN_TC_TEST:
	case OSMO_SCCP_SSN_GMLC_MAP:
	case OSMO_SCCP_SSN_CAP:
	case OSMO_SCCP_SSN_gsmSCF_MAP:
	case OSMO_SCCP_SSN_SIWF_MAP:
	case OSMO_SCCP_SSN_SGSN_MAP:
	case OSMO_SCCP_SSN_GGSN_MAP:
		/* SSNs known to use TCAP */
		return true;
	default:
		return false;
	}
}

/** Traffic from the TCAP ASP -> AS -> osmo-stp, only used to update transaction tracking
 *
 * @param as
 * @param asp asp sent the \ref sccp_msg message towards osmo-stp
 * @param opc M3UA opc
 * @param dpc M3UA DPC
 * @param sccp_msg pointer to a msg.
 * @return 0 on successful handling, < 0 on error cases (missing IE, decoding errors)
 */
int tcap_as_rx_sccp_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp, uint32_t opc, uint32_t dpc, struct msgb *sccp_msg)
{
	struct tcap_parsed parsed = {};
	struct xua_msg_part *ie_data;
	struct osmo_sccp_addr calling_addr, called_addr;
	int rc;
	struct xua_msg *sua = osmo_sccp_to_xua(sccp_msg);
	if (!sua) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Unable to parse SCCP message\n");
		return -1;
	}

	/* TCAP uses only connectionless SCCP messages */
	if (sua->hdr.msg_class != SUA_MSGC_CL && sua->hdr.msg_class != SUA_CL_CLDT)
		return -2;

	rc = sua_addr_parse(&calling_addr, sua, SUA_IEI_SRC_ADDR);
	if (rc < 0) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Unable to parse SCCP Destination Address\n");
		return -3;
	}

	/* retrieve + decode destination address */
	rc = sua_addr_parse(&called_addr, sua, SUA_IEI_DEST_ADDR);
	if (rc < 0) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Unable to parse SCCP Destination Address\n");
		return -4;
	}

	if (!ssn_contains_tcap(called_addr.ssn)) {
		/* No TCAP */
		return 0;
	}

	/* TCAP transaction tracking requires point codes */
	if (!(calling_addr.presence & OSMO_SCCP_ADDR_T_PC)) {
		/* use M3UA OPC instead */
		calling_addr.pc = opc;
		calling_addr.presence |= OSMO_SCCP_ADDR_T_PC;
	}
	if (!(called_addr.presence & OSMO_SCCP_ADDR_T_PC)) {
		/* use M3UA DPC instead */
		called_addr.pc = dpc;
		called_addr.presence |= OSMO_SCCP_ADDR_T_PC;
	}

	/* retrieve the SCCP payload (actual encoded TCAP data) */
	ie_data = xua_msg_find_tag(sua, SUA_IEI_DATA);
	if (!ie_data)
		return -6;

	rc = parse_tcap(as, ie_data->dat, ie_data->len, &parsed);
	if (rc <= 0) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Failed get TCAP otid/dtid.\n");
		return -7;
	}

	LOGPAS(as, DLTCAP, LOGL_INFO, "Looking up transaction for type 0x%02x, otid=%u dtid=%u\n", parsed.present, parsed.otid, parsed.dtid);
	/* TCAP messages towards the IPAC nodes */
	switch (parsed.present) {
	case TCAP_TCMessage_PR_begin:
		if (!(rc & OTID_SET)) {
			/* FIXME: failure case */
			return -8;
		}

		tcap_trans_track_entry_create(as, asp, &calling_addr, &parsed.otid, &called_addr, NULL);
		break;
	case TCAP_TCMessage_PR_continue:
		if (!((rc & OTID_SET) && (rc & DTID_SET))) {
			/* FIXME: failure case */
			return -8;
		}

		/* only hit/update the transaction tracking */
		tcap_trans_track_continue(as, &calling_addr, &parsed.otid, &called_addr, &parsed.dtid);
		break;
	case TCAP_TCMessage_PR_abort:
	case TCAP_TCMessage_PR_end:
		if (!(rc & DTID_SET)) {
			/* FIXME: failure case */
			return -8;
		}

		/* only hit/update the transaction tracking */
		tcap_trans_track_end(as, &calling_addr, NULL, &called_addr, &parsed.dtid);
		break;
	case TCAP_TCMessage_PR_unidirectional:
	case TCAP_TCMessage_PR_NOTHING:
	default:
		/* TODO: what to do with those messages? */
		return -9;
	}

	return 0;
}

/** Send UDTS to indicate that the originating UDT could not be delivered to its destination
  * @param as
  * @param orig_mtp MTP routing information of the originating message (message that could not be delivered)
  * @param orig_sua Originating message that could not be delivered
  * @param cause_code the return cause of the UDTS
  * @return 0 on success, negative on error
*/
static int send_back_udts(struct osmo_ss7_as *as,
			  const struct osmo_mtp_transfer_param *orig_mtp,
			  const struct xua_msg *orig_sua,
			  uint8_t cause_code)
{
	struct msgb *msg;
	struct xua_msg *sua;
	int rc = -EINVAL;
	uint32_t spare_proto = 0;
	struct osmo_mtp_transfer_param new_mtp;
	uint32_t rctx;

	OSMO_ASSERT(orig_sua->hdr.msg_class == SUA_MSGC_CL && orig_sua->hdr.msg_type == SUA_CL_CLDT);

	if (!xua_msg_get_u32p(orig_sua, SUA_IEI_PROTO_CLASS, &spare_proto))
		return -EINVAL;

	/* Check if Return on Error is set */
	if ((spare_proto & 0xf0) != 0x80)
		return 0;

	struct xua_msg_part *rctx_ie = xua_msg_find_tag(orig_sua, SUA_IEI_ROUTE_CTX);
	if (rctx_ie)
		rctx = xua_msg_part_get_u32(rctx_ie);
	else
		rctx = 0; /* Routing Context should be there as per proto... */

	sua = sua_gen_cldr(orig_sua, rctx, cause_code);
	if (!sua)
		return -ENOMEM;

	LOGPAS(as, DLTCAP, LOGL_INFO, "Tx UDTS: %s\n", xua_msg_dump(sua, &xua_dialect_sua));

	msg = osmo_sua_to_sccp(sua);
	if (!msg) {
		rc = -ENOMEM;
		goto free_sua;
	}

	new_mtp = *orig_mtp;
	new_mtp.opc = orig_mtp->dpc;
	new_mtp.dpc = orig_mtp->opc;
	mtp3_hmrt_mtp_xfer_request_l4_to_l3(as->inst, &new_mtp, msgb_data(msg), msgb_length(msg));
	msgb_free(msg);
free_sua:
	xua_msg_free(sua);
	return rc;
}

/*! Traffic STP -> AS -> ASP (Tx path) Loadshare towards the TCAP routing AS
 *
 * \param[out] rasp the selected ASP if any, can be NULL
 * \param[in] as
 * \param[in] opc the OPC from MTP
 * \param[in] dpc the DPC from MTP
 * \param[in] mtp MTP routing information
 * \param[in] sccp_msg the SCCP message. Callee takes ownership.
 * \return 0: on succcess (msg handled by the callee),
 *	   -EPROTONOSUPPORT: let caller (regular loadsharing) handle those.
 */
static int asp_loadshare_tcap_sccp(struct osmo_ss7_asp **rasp, struct osmo_ss7_as *as,
				   const struct osmo_mtp_transfer_param *mtp, struct msgb *sccp_msg)
{
	struct tcap_parsed parsed = {};
	struct xua_msg *sua;
	struct xua_msg_part *ie_data;
	struct osmo_sccp_addr calling_addr, called_addr;
	struct osmo_ss7_asp *asp = NULL;
	int rc;

	OSMO_ASSERT(rasp);

	/* decode SCCP and convert to a SUA/xUA representation */
	sua = osmo_sccp_to_xua(sccp_msg);
	if (!sua) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Unable to parse SCCP message\n");
		rc = -EPROTONOSUPPORT;
		goto out_free_msgb;
	}

	/* TCAP uses only connectionless SCCP messages */
	if (sua->hdr.msg_class != SUA_MSGC_CL && sua->hdr.msg_class != SUA_CL_CLDT) {
		/* ignoring packets */
		rc = -EPROTONOSUPPORT;
		goto out_free_sua;
	}

	rc = sua_addr_parse(&calling_addr, sua, SUA_IEI_SRC_ADDR);
	if (rc < 0) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Unable to parse SCCP Source Address\n");
		goto out_free_sua;
	}

	rc = sua_addr_parse(&called_addr, sua, SUA_IEI_DEST_ADDR);
	if (rc < 0) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Unable to parse SCCP Destination Address\n");
		goto out_free_sua;
	}

	if (!(called_addr.presence & OSMO_SCCP_ADDR_T_SSN) || !ssn_contains_tcap(called_addr.ssn)) {
		/* No tcap, return NULL */
		rc = -EPROTONOSUPPORT;
		goto out_free_sua;
	}

	/* TCAP transaction tracking requires point codes */
	if (!(calling_addr.presence & OSMO_SCCP_ADDR_T_PC)) {
		/* use M3UA OPC instead */
		calling_addr.pc = mtp->opc;
		calling_addr.presence |= OSMO_SCCP_ADDR_T_PC;
	}
	if (!(called_addr.presence & OSMO_SCCP_ADDR_T_PC)) {
		/* use M3UA DPC instead */
		called_addr.pc = mtp->dpc;
		called_addr.presence |= OSMO_SCCP_ADDR_T_PC;
	}

	/* retrieve the SCCP payload (TCAP data) */
	ie_data = xua_msg_find_tag(sua, SUA_IEI_DATA);
	if (!ie_data) {
		rc = -ENODATA;
		goto out_free_sua;
	}

	rc = parse_tcap(as, ie_data->dat, ie_data->len, &parsed);
	LOGPAS(as, DLTCAP, LOGL_DEBUG, "TCAP decoded rc=%d otid=%u dtid=%u\n", rc, parsed.otid, parsed.dtid);

	if (rc <= 0) {
		rate_ctr_inc2(as->ctrg, SS7_AS_CTR_RX_TCAP_FAILED);
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Failed get TCAP otid/dtid.\n");
		rc = -EINVAL;
		goto out_free_sua;
	}
	rate_ctr_inc2(as->ctrg, SS7_AS_CTR_RX_TCAP_DECODED);

	/* TCAP messages towards the IPA nodes */
	switch (parsed.present) {
	case TCAP_TCMessage_PR_begin:
		if (!(rc & OTID_SET)) {
			rc = -EINVAL;
			goto out_free_sua;
		}

		/* lookup a new ASP */
		asp = tcap_as_asp_find_by_tcap_id(as, &calling_addr, &called_addr, parsed.otid);

		if (asp) {
			rate_ctr_inc2(as->ctrg, SS7_AS_CTR_TCAP_ASP_SELECTED);
		} else {
			/* if no ASP found for this TCAP, try to find a non-tcap-range ASP as fallback*/
			asp = find_asp_no_tcap_range(as);
			if (asp)
				rate_ctr_inc2(as->ctrg, SS7_AS_CTR_TCAP_ASP_FALLBACK);
			else {
				/* couldn't find a suitable canditate for OTID */
				rate_ctr_inc2(as->ctrg, SS7_AS_CTR_TCAP_ASP_FAILED);
				LOGPAS(as, DLTCAP, LOGL_DEBUG, "Couldn't find a suitable canditate for otid %u\n", parsed.otid);
				rc = -ENOKEY;
				goto out_free_sua;
			}
		}

		tcap_trans_track_begin(as, asp, &called_addr, NULL, &calling_addr, &parsed.otid);
		rc = 0;
		break;
	case TCAP_TCMessage_PR_continue:
		if (!((rc & OTID_SET) && (rc & DTID_SET))) {
			rc = -EINVAL;
			goto out_free_sua;
		}

		asp = tcap_trans_track_continue(as, &called_addr, &parsed.dtid, &calling_addr, &parsed.otid);
		rc = asp ? 0 : -ENOKEY;
		break;
	case TCAP_TCMessage_PR_abort:
	case TCAP_TCMessage_PR_end:
		if (!(rc & DTID_SET)) {
			/* FIXME: failure case */
			rc = -EINVAL;
			goto out_free_sua;
		}

		asp = tcap_trans_track_end(as, &called_addr, &parsed.dtid, &calling_addr, NULL);
		rc = asp ? 0 : -ENOKEY;
		break;
	case TCAP_TCMessage_PR_unidirectional:
	case TCAP_TCMessage_PR_NOTHING:
	default:
		/* Ignore, let regular loadsharing handle those */
		rc = -EPROTONOSUPPORT;
		break;
	}
out_free_sua:
	/* RFC3868 4.7.3: "If an ASP is not available, the SG may generate (X)UDTS "routing failure",
	 * if the return option is used."
	 * See also ITU Q.714 4.2 */
	if (rc < 0 && rc != -EPROTONOSUPPORT) {
		send_back_udts(as, mtp, sua, SCCP_RETURN_CAUSE_SUBSYSTEM_FAILURE);
		rc = 0;
	}
	xua_msg_free(sua);
out_free_msgb:
	msgb_free(sccp_msg);
	*rasp = asp;
	return rc;
}

/*! Entrypoint for M3UA messages towards the TCAP nodes
 *
 * @param[out] asp Result pointer of the selected asp. Set to NULL if return code is != 0
 * @param[in] as
 * @param[in] xua
 * @return 0: on succcess (msg handled by the callee),
 *	   -EPROTONOSUPPORT: let caller (regular loadsharing) handle those.
 */
/* return 0 and asp is set */
int tcap_as_select_asp_loadshare(struct osmo_ss7_asp **asp, struct osmo_ss7_as *as, const struct xua_msg *xua)
{
	uint8_t service_ind = xua->mtp.sio & 0xF;
	struct xua_msg_part *m3ua_data_ie;
	struct msgb *sccp_msg;
	uint8_t *cur;

	OSMO_ASSERT(asp);
	*asp = NULL;

	if (service_ind != MTP_SI_SCCP)
		return -EPROTONOSUPPORT;

	/* we only care about actual M3UA data transfer messages */
	if (xua->hdr.msg_class != M3UA_MSGC_XFER || xua->hdr.msg_type != M3UA_XFER_DATA)
		return -EPROTONOSUPPORT;

	/* we only care about SCCP as higher layer protocol.
	 * extract the SCCP payload and convert to a msgb */
	m3ua_data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	if (!m3ua_data_ie) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Couldn't find M3UA protocol data\n");
		return -EPROTONOSUPPORT;
	}

	sccp_msg = msgb_alloc(m3ua_data_ie->len, "loadshare_tcap");
	if (!sccp_msg) {
		LOGPAS(as, DLTCAP, LOGL_ERROR, "Unable to allocate SCCP message buffer\n");
		return -ENOMEM;
	}
	cur = msgb_put(sccp_msg, m3ua_data_ie->len);
	memcpy(cur, m3ua_data_ie->dat, m3ua_data_ie->len);
	sccp_msg->l2h = cur +  sizeof(struct m3ua_data_hdr);

	return asp_loadshare_tcap_sccp(asp, as, &xua->mtp, sccp_msg);
}

enum ipa_tcap_routing_msg_types {
	MT_TID_ADD_RANGE	= 0x01,
	MT_TID_ACK		= 0x02,
	MT_TID_NACK		= 0x03,
};

enum ipa_tcap_routing_nack_error {
	NACK_ERR_SYS_FAILURE	= 0x01, /* system failure */
	NACK_ERR_EALREADY	= 0x72, /* already in use */
};

struct ipa_tcap_routing_hdr {
	uint8_t mt;
	uint32_t seq;
	uint8_t data[0];
} __attribute__((packed));

struct ipa_tcap_routing_add_range {
	uint32_t tid_start;
	uint32_t tid_end;
	uint32_t pc;
	uint8_t ssn;
} __attribute__((packed));

struct ipa_tcap_routing_nack {
	uint8_t err;
} __attribute__((packed));

static struct msgb *ipa_tcap_routing_alloc(uint32_t seq_nr, uint8_t mt)
{
	struct ipa_tcap_routing_hdr hdr = {
		.mt = mt,
		.seq = osmo_htonl(seq_nr),
	};

	struct msgb *msg = osmo_ipa_msg_alloc(16);
	if (!msg)
		return NULL;

	void *dst = msgb_put(msg, sizeof(hdr));
	memcpy(dst, &hdr, sizeof(hdr));

	return msg;
}

static int ipa_tx_tcap_routing_ack(struct osmo_ss7_asp *asp, uint32_t seq_nr)
{
	struct msgb *msg = ipa_tcap_routing_alloc(seq_nr, MT_TID_ACK);
	if (!msg)
		return -ENOMEM;

	osmo_ipa_msg_push_headers(msg, IPAC_PROTO_OSMO, IPAC_PROTO_EXT_TCAP_ROUTING);
	return osmo_ss7_asp_send(asp, msg);
}

static int ipa_tx_tcap_routing_nack(struct osmo_ss7_asp *asp, uint32_t seq_nr, uint8_t err_code)
{
	struct msgb *msg = ipa_tcap_routing_alloc(seq_nr, MT_TID_NACK);
	if (!msg)
		return -ENOMEM;

	msgb_put_u8(msg, err_code);

	osmo_ipa_msg_push_headers(msg, IPAC_PROTO_OSMO, IPAC_PROTO_EXT_TCAP_ROUTING);
	return osmo_ss7_asp_send(asp, msg);
}

/** Entrypoint for IPA TCAP Routing messages, parses and handles those
 *
 * @param asp
 * @param msg the message buffer. It is kept owned by the caller.
 * @return 0 on success
 */
int ipa_rx_msg_osmo_ext_tcap_routing(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	int rc = 0;
	struct osmo_ss7_as *as;
	struct ipa_tcap_routing_hdr *hdr;
	enum ipa_tcap_routing_msg_types routing_msg;

	if (cs7_role != CS7_ROLE_SG) {
		LOGPASP(asp, DLTCAP, LOGL_ERROR,
			"Rx unexpected OSMO IPA EXT TCAP ROUTING msg in role != CS7_ROLE_SG!\n");
		rc = -ENOENT;
		goto out;
	}

	as = ipa_find_as_for_asp(asp);
	if (!as) {
		LOGPASP(asp, DLTCAP, LOGL_ERROR, "Rx message for IPA ASP without AS?!\n");
		rc = -ENOENT;
		goto out;
	}

	/* pull the IPA and OSMO_EXT header */
	hdr = (struct ipa_tcap_routing_hdr *) msgb_data(msg);
	if (msgb_length(msg) < sizeof(struct ipa_tcap_routing_hdr)) {
		LOGPASP(asp, DLTCAP, LOGL_ERROR, "TCAP routing message too short\n");
		rc = -EINVAL;
		goto out;
	}

	routing_msg = (enum ipa_tcap_routing_msg_types) hdr->mt;
	switch (routing_msg) {
	case MT_TID_ADD_RANGE: {
		struct tcap_range *tcrng;
		struct ipa_tcap_routing_add_range tcar = {};

		if (!as->cfg.loadshare.tcap.enabled || as->cfg.mode != OSMO_SS7_AS_TMOD_LOADSHARE)
			LOGPASP(asp, DLTCAP, LOGL_NOTICE, "Wrong traffic mode %s on AS %s will not use TCAP Ranges\n", osmo_ss7_as_traffic_mode_name(as->cfg.mode), as->cfg.name);

		if (msgb_length(msg) < sizeof(*hdr) + sizeof(struct ipa_tcap_routing_add_range)) {
			LOGPASP(asp, DLTCAP, LOGL_ERROR, "TCAP routing message is too small\n");
			rc = -EINVAL;
			goto out;
		}

		msgb_pull(msg, sizeof(*hdr));

		tcar.tid_start = msgb_pull_u32(msg);
		tcar.tid_end = msgb_pull_u32(msg);
		tcar.pc = msgb_pull_u32(msg);
		tcar.ssn = msgb_pull_u8(msg);

		LOGPASP(asp, DLTCAP, LOGL_INFO, "Rx: TCAP Add Range command: seq: %u pc: %u ssn: %u [%u-%u]\n", osmo_ntohl(hdr->seq), tcar.pc, tcar.ssn, tcar.tid_start, tcar.tid_end);

		tcrng = tcap_overlap_tid(as, tcar.pc, tcar.ssn, tcar.tid_start, tcar.tid_end);
		if (tcrng) {
			LOGPASP(asp, DLTCAP, LOGL_ERROR, "New TCAP Range overlaps with existing range to ASP %s [%u-%u]. Rejecting Add Range Command seq: %u pc: %u ssn: %u [%u-%u]\n",
				tcrng->asp->cfg.name, tcrng->tid_start, tcrng->tid_end, osmo_ntohl(hdr->seq), tcar.pc, tcar.ssn, tcar.tid_start, tcar.tid_end);
			rc = ipa_tx_tcap_routing_nack(asp, osmo_ntohl(hdr->seq), NACK_ERR_EALREADY);
			goto out;
		}

		tcrng = tcap_range_alloc(as, asp, tcar.tid_start, tcar.tid_end, tcar.pc, tcar.ssn);
		if (!tcrng) {
			LOGPASP(asp, DLTCAP, LOGL_ERROR, "TCAP Add Range: failed to allocate memory\n");
			rc = ipa_tx_tcap_routing_nack(asp, osmo_ntohl(hdr->seq), NACK_ERR_SYS_FAILURE);
			goto out;
		}

		if (tcar.pc != TCAP_PC_WILDCARD)
			as->tcap.contains_pc = true;

		if (tcar.ssn != TCAP_SSN_WILDCARD)
			as->tcap.contains_ssn = true;

		asp->tcap.enabled = true;
		rc = ipa_tx_tcap_routing_ack(asp, osmo_ntohl(hdr->seq));
		break;
	}
	case MT_TID_ACK: /* shouldn't received from other end */
	case MT_TID_NACK: /* shouldn't received from other end */
	default:
		rc = -EINVAL;
		break;
	}

out:
	return rc;
}

/* update the short cuts contains_pc & contains_ssn */
static void tcap_range_as_update_pc_ssn(struct osmo_ss7_as *as)
{
	int i;
	struct tcap_range *tcrng;
	struct hlist_node *tmp;

	bool check_pc = as->tcap.contains_pc;
	bool found_pc = false;
	bool check_ssn = as->tcap.contains_ssn;
	bool found_ssn = false;

	hash_for_each_safe(as->tcap.tid_ranges, i, tmp, tcrng, list) {
		if (!check_pc && !check_ssn)
			break;

		if (check_pc && tcrng->pc != TCAP_PC_WILDCARD) {
			check_pc = false;
			found_pc = true;
		}

		if (check_ssn && tcrng->ssn != TCAP_SSN_WILDCARD) {
			check_ssn = false;
			found_ssn = true;
		}
	}

	if (as->tcap.contains_pc)
		as->tcap.contains_pc = found_pc;

	if (as->tcap.contains_ssn)
		as->tcap.contains_ssn = found_ssn;
}

/** Create and alloc a new TCAP range entry
 *
 * @param[in] as
 * @param[in] asp
 * @param[in] tid_start
 * @param[in] tid_end
 * @param[in] pc
 * @param[in] ssn
 * @return the TCAP range entry or NULL
 */
struct tcap_range *tcap_range_alloc(struct osmo_ss7_as *as,
				    struct osmo_ss7_asp *asp,
				    uint32_t tid_start, uint32_t tid_end,
				    uint32_t pc,
				    uint8_t ssn)
{
	struct tcap_range *tcrng = talloc_zero(asp, struct tcap_range);

	if (!tcrng)
		return NULL;

	tcrng->asp = asp;
	tcrng->pc = pc;
	tcrng->ssn = ssn;
	tcrng->tid_start = tid_start;
	tcrng->tid_end = tid_end;

	hash_add(as->tcap.tid_ranges, &tcrng->list, tcap_gen_hash(pc, ssn));

	return tcrng;
}

/** Remove and free a single TCAP range entry
 *
 * @param[in] tcrng
 */
void tcap_range_free(struct tcap_range *tcrng)
{
	hash_del(&tcrng->list);
	talloc_free(tcrng);
}

/** Checks if a tid matches to a specific range
 *
 * @param tcrng
 * @param tid
 * @return true if tid is included in the range
 */
bool tcap_range_matches(const struct tcap_range *tcrng, uint32_t tid)
{
	return (tid >= tcrng->tid_start) && (tid <= tcrng->tid_end);
}

/** Checks if a tid rnage overlaps with another range
 *
 * @param a
 * @param tid_start
 * @param tid_end
 * @return
 */
bool tcap_range_overlaps(const struct tcap_range *a, uint32_t tid_start, uint32_t tid_end)
{
	struct tcap_range b = {
		.tid_start = tid_start,
		.tid_end = tid_end
	};

	return tcap_range_matches(&b, a->tid_start) || tcap_range_matches(&b, a->tid_end)
		|| tcap_range_matches(a, tid_start) || tcap_range_matches(a, tid_end);
}


static void _tcap_range_asp_down(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp)
{
	int i;
	struct tcap_range *tcrng;
	struct hlist_node *tmp;

	tcap_trans_track_entries_free_by_asp(as, asp);
	hash_for_each_safe(as->tcap.tid_ranges, i, tmp, tcrng, list) {
		if (tcrng->asp == asp)
			tcap_range_free(tcrng);
	}
}

void tcap_as_del_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp)
{
	if (!asp->tcap.enabled)
		return;

	_tcap_range_asp_down(as, asp);
	if (as->tcap.contains_pc || as->tcap.contains_ssn)
		tcap_range_as_update_pc_ssn(as);
}

void tcap_enable(struct osmo_ss7_as *as)
{
	if (as->cfg.loadshare.tcap.enabled)
		return;

	as->cfg.loadshare.tcap.enabled = true;
	tcap_trans_track_garbage_collect_start(as);
}

void tcap_disable(struct osmo_ss7_as *as)
{
	if (!as->cfg.loadshare.tcap.enabled)
		return;

	as->cfg.loadshare.tcap.enabled = false;
	as->tcap.contains_pc = false;
	as->tcap.contains_ssn = false;
	tcap_trans_track_garbage_collect_stop(as);
	tcap_trans_track_entries_free_all(as);
}
