/* M3UA/SUA [S]SNM Handling */

/* (C) 2021 by Harald Welte <laforge@gnumonks.org>
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

#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_route.h"
#include "ss7_internal.h"
#include "ss7_route_table.h"
#include "xua_internal.h"
#include "sccp_internal.h"

/* we can share this code between M3UA and SUA as the below conditions are true */
osmo_static_assert(M3UA_SNM_DUNA == SUA_SNM_DUNA, _sa_duna);
osmo_static_assert(M3UA_SNM_DAVA == SUA_SNM_DAVA, _sa_dava);
osmo_static_assert(M3UA_SNM_DAUD == SUA_SNM_DAUD, _sa_dava);
osmo_static_assert(M3UA_IEI_AFFECTED_PC == SUA_IEI_AFFECTED_PC, _sa_aff_pc);
osmo_static_assert(M3UA_IEI_ROUTE_CTX == SUA_IEI_ROUTE_CTX, _sa_rctx);
osmo_static_assert(M3UA_IEI_INFO_STRING == SUA_IEI_INFO_STRING, _sa_inf_str);

static const char *format_affected_pcs_c(void *ctx, const struct osmo_ss7_instance *s7i,
					 const struct xua_msg_part *ie_aff_pc)
{
	const uint32_t *aff_pc = (const uint32_t *) ie_aff_pc->dat;
	unsigned int num_aff_pc = ie_aff_pc->len / sizeof(uint32_t);
	char *out = talloc_strdup(ctx, "");
	int i;

	for (i = 0; i < num_aff_pc; i++) {
		uint32_t _aff_pc = ntohl(aff_pc[i]);
		uint32_t pc = _aff_pc & 0xffffff;
		uint8_t mask = _aff_pc >> 24;

		/* append point code + mask */
		out = talloc_asprintf_append(out, "%s%s/%u", i == 0 ? "" : ", ",
					     osmo_ss7_pointcode_print(s7i, pc), mask);
	}
	return out;
}

void xua_tx_snm_available(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
			  const uint32_t *aff_pc, unsigned int num_aff_pc,
			  const char *info_str, bool available)
{
	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		m3ua_tx_snm_available(asp, rctx, num_rctx, aff_pc, num_aff_pc, info_str, available);
		break;
	case OSMO_SS7_ASP_PROT_SUA:
		sua_tx_snm_available(asp, rctx, num_rctx, aff_pc, num_aff_pc, NULL, NULL, info_str, available);
		break;
	default:
		break;
	}
}

void xua_tx_snm_daud(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
		     const uint32_t *aff_pc, unsigned int num_aff_pc, const char *info_str)
{
	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		m3ua_tx_snm_daud(asp, rctx, num_rctx, aff_pc, num_aff_pc, info_str);
		break;
	case OSMO_SS7_ASP_PROT_SUA:
		sua_tx_snm_daud(asp, rctx, num_rctx, aff_pc, num_aff_pc, NULL, NULL, info_str);
		break;
	default:
		break;
	}
}

static void xua_tx_upu(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
			uint32_t dpc, uint16_t user, uint16_t cause, const char *info_str)
{
	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		m3ua_tx_dupu(asp, rctx, num_rctx, dpc, user, cause, info_str);
		break;
	case OSMO_SS7_ASP_PROT_SUA:
		sua_tx_dupu(asp, rctx, num_rctx, dpc, user, cause, info_str);
		break;
	default:
		break;
	}
}

static void xua_tx_scon(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
			const uint32_t *aff_pc, unsigned int num_aff_pc,
			const uint32_t *concerned_dpc, const uint8_t *cong_level,
			const char *info_string)
{
	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		m3ua_tx_snm_congestion(asp, rctx, num_rctx, aff_pc, num_aff_pc,
				       concerned_dpc, cong_level, info_string);
		break;
	case OSMO_SS7_ASP_PROT_SUA:
		sua_tx_snm_congestion(asp, rctx, num_rctx, aff_pc, num_aff_pc, NULL,
				      cong_level ? *cong_level : 0, info_string);
		break;
	default:
		break;
	}
}

/* generate MTP-PAUSE / MTP-RESUME towards local SCCP users */
static void xua_snm_pc_available_to_sccp(struct osmo_sccp_instance *sccp,
					 const uint32_t *aff_pc, unsigned int num_aff_pc,
					 bool available)
{
	int i;
	for (i = 0; i < num_aff_pc; i++) {
		/* 32bit "Affected Point Code" consists of a 7-bit mask followed by 14/16/24-bit SS7 PC,
		 * see RFC 4666 3.4.1 */
		uint32_t _aff_pc = ntohl(aff_pc[i]);
		uint32_t pc = _aff_pc & 0xffffff;
		uint8_t mask = _aff_pc >> 24;

		if (!mask) {
			if (available)
				sccp_scmg_rx_mtp_resume(sccp, pc);
			else
				sccp_scmg_rx_mtp_pause(sccp, pc);
		} else {
			/* we have to send one MTP primitive for each individual point
			 * code within that mask */
			uint32_t maskbits = (1 << mask) - 1;
			uint32_t fullpc;
			for (fullpc = (pc & ~maskbits); fullpc <= (pc | maskbits); fullpc++) {
				if (available)
					sccp_scmg_rx_mtp_resume(sccp, fullpc);
				else
					sccp_scmg_rx_mtp_pause(sccp, fullpc);
			}
		}
	}
}

/* Figure 43/Q.704, Figure 44/Q.704 */
/* RFC4666 1.4.2.5: "maintain a dynamic table of available SGP routes
 * for the SS7 destinations, taking into account the SS7 destination
 * availability/restricted/congestion status received from the SGP "*/
static void xua_snm_srm_pc_available_single(struct osmo_ss7_as *as, uint32_t pc, bool available)
{
	struct osmo_ss7_instance *s7i = as->inst;
	enum osmo_ss7_route_status new_status;
	struct osmo_ss7_route *rt;

	new_status = available ? OSMO_SS7_ROUTE_STATUS_AVAILABLE :
				 OSMO_SS7_ROUTE_STATUS_UNAVAILABLE;

	/* Check if we already have a dynamic fully qualified route towards that AS: */
	rt = ss7_route_table_find_route_by_dpc_mask_as(s7i->rtable_system, pc, 0xffffff, as, true);
	if (!rt) {
		/* No dynamic fully qualified route found. Add dynamic fully
		 * qualified route and mark it as (un)available: */
		rt = ss7_route_create(s7i->rtable_system, pc, 0xffffff, true, as->cfg.name);
		if (!rt) {
			LOGPAS(as, DLSS7, LOGL_ERROR, "Unable to create dynamic route for pc=%u=%s status=%s\n",
			       pc, osmo_ss7_pointcode_print(s7i, pc), ss7_route_status_name(new_status));
			return;
		}
		ss7_route_update_route_status(rt, new_status);
		/* No need to iterate over rtable below, since we know there was no route: */
		return;
	}
	ss7_route_table_update_route_status_by_as(s7i->rtable_system, new_status, as, pc);
}
static void xua_snm_srm_pc_available(struct osmo_ss7_as *as,
				     const uint32_t *aff_pc, unsigned int num_aff_pc,
				     bool available)
{
	for (unsigned int i = 0; i < num_aff_pc; i++) {
		/* 32bit "Affected Point Code" consists of a 7-bit mask followed by 14/16/24-bit SS7 PC,
		 * see RFC 4666 3.4.1 */
		uint32_t _aff_pc = ntohl(aff_pc[i]);
		uint32_t pc = _aff_pc & 0xffffff;
		uint8_t mask = _aff_pc >> 24;

		if (!mask) {
			xua_snm_srm_pc_available_single(as, pc, available);
		} else {
			/* Update only full DPC routes. */
			uint32_t maskbits = (1 << mask) - 1;
			uint32_t fullpc;
			for (fullpc = (pc & ~maskbits); fullpc <= (pc | maskbits); fullpc++)
				xua_snm_srm_pc_available_single(as, fullpc, available);
		}
	}
}

/* advertise availability of point codes (with masks) */
void xua_snm_pc_available(struct osmo_ss7_as *as, const uint32_t *aff_pc,
			  unsigned int num_aff_pc, const char *info_str, bool available)
{
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_ss7_asp *asp;
	uint32_t rctx[OSMO_SS7_MAX_RCTX_COUNT];
	unsigned int num_rctx;

	xua_snm_srm_pc_available(as, aff_pc, num_aff_pc, available);


	/* inform local users via a MTP-{PAUSE, RESUME} primitive */
	if (s7i->sccp)
		xua_snm_pc_available_to_sccp(s7i->sccp, aff_pc, num_aff_pc, available);

	/* inform remote ASPs via DUNA/DAVA */
	llist_for_each_entry(asp, &s7i->asp_list, list) {
		/* SSNM is only permitted for ASPs in ACTIVE state */
		if (!osmo_ss7_asp_active(asp))
			continue;

		/* only send DAVA/DUNA if we locally are the SG and the remote is ASP */
		if (asp->cfg.role != OSMO_SS7_ASP_ROLE_SG)
			continue;

		num_rctx = ss7_asp_get_all_rctx_be(asp, rctx, ARRAY_SIZE(rctx), as);
		/* this can happen if the given ASP is only in the AS that reports the change,
		 * which shall be excluded */
		if (num_rctx == 0 && osmo_ss7_as_has_asp(as, asp))
			continue;
		xua_tx_snm_available(asp, rctx, num_rctx, aff_pc, num_aff_pc, info_str, available);
	}
}

/* generate SS-PROHIBITED / SS-ALLOWED towards local SCCP users */
static void sua_snm_ssn_available_to_sccp(struct osmo_sccp_instance *sccp, uint32_t aff_pc,
					  uint32_t aff_ssn, uint32_t smi, bool available)
{
	if (available)
		sccp_scmg_rx_ssn_allowed(sccp, aff_pc, aff_ssn, smi);
	else
		sccp_scmg_rx_ssn_prohibited(sccp, aff_pc, aff_ssn, smi);
}

/* advertise availability of a single subsystem */
static void sua_snm_ssn_available(struct osmo_ss7_as *as, uint32_t aff_pc, uint32_t aff_ssn,
				  const uint32_t *smi, const char *info_str, bool available)
{
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_ss7_asp *asp;
	uint32_t rctx[OSMO_SS7_MAX_RCTX_COUNT];
	unsigned int num_rctx;
	uint32_t _smi = smi ? *smi : 0; /* 0 == reserved/unknown in SUA */

	if (s7i->sccp)
		sua_snm_ssn_available_to_sccp(s7i->sccp, aff_pc, aff_ssn, _smi, available);

	/* inform remote SUA ASPs via DUNA/DAVA */
	llist_for_each_entry(asp, &s7i->asp_list, list) {
		/* SSNM is only permitted for ASPs in ACTIVE state */
		if (!osmo_ss7_asp_active(asp))
			continue;

		/* only send DAVA/DUNA if we locally are the SG and the remote is ASP */
		if (asp->cfg.role != OSMO_SS7_ASP_ROLE_SG)
			continue;

		/* DUNA/DAVA for SSN only exists in SUA */
		if (asp->cfg.proto != OSMO_SS7_ASP_PROT_SUA)
			continue;

		num_rctx = ss7_asp_get_all_rctx_be(asp, rctx, ARRAY_SIZE(rctx), as);
		/* this can happen if the given ASP is only in the AS that reports the change,
		 * which shall be excluded */
		if (num_rctx == 0)
			continue;
		sua_tx_snm_available(asp, rctx, num_rctx, &aff_pc, 1, &aff_ssn, smi, info_str, available);
	}
}

static void xua_snm_upu(struct osmo_ss7_as *as, uint32_t dpc, uint16_t user, uint16_t cause,
			const char *info_str)
{
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_ss7_asp *asp;
	uint32_t rctx[OSMO_SS7_MAX_RCTX_COUNT];
	unsigned int num_rctx;

	/* Translate to MTP-STATUS.ind towards SCCP (will create N-PCSTATE.ind to SCU) */
	if (s7i->sccp && user == MTP_SI_SCCP)
		sccp_scmg_rx_mtp_status(s7i->sccp, dpc, cause);

	/* inform remote ASPs via DUPU */
	llist_for_each_entry(asp, &s7i->asp_list, list) {
		/* SSNM is only permitted for ASPs in ACTIVE state */
		if (!osmo_ss7_asp_active(asp))
			continue;

		/* only send DAVA/DUNA if we locally are the SG and the remote is ASP */
		if (asp->cfg.role != OSMO_SS7_ASP_ROLE_SG)
			continue;

		num_rctx = ss7_asp_get_all_rctx_be(asp, rctx, ARRAY_SIZE(rctx), as);
		/* this can happen if the given ASP is only in the AS that reports the change,
		 * which shall be excluded */
		if (num_rctx == 0)
			continue;

		xua_tx_upu(asp, rctx, num_rctx, dpc, user, cause, info_str);
	}
}

static void xua_snm_scon(struct osmo_ss7_as *as, const uint32_t *aff_pc, unsigned int num_aff_pc,
			 const uint32_t *concerned_dpc, const uint8_t *cong_level, const char *info_string)
{
	struct osmo_ss7_instance *s7i = as->inst;
	struct osmo_ss7_asp *asp;
	uint32_t rctx[OSMO_SS7_MAX_RCTX_COUNT];
	unsigned int num_rctx;

	/* TODO: Translate to MTP-STATUS.ind towards SCCP (will create N-PCSTATE.ind to SCU) */

	/* RFC4666 1.4.6: "When an SG receives a congestion message (SCON) from an ASP and the SG
	 * determines that an SPMC is now encountering congestion, it MAY trigger SS7 MTP3 Transfer
	 * Controlled management messages to concerned SS7 destinations according to congestion
	 * procedures of the relevant MTP3 standard."
	 * ie. inform remote ASPs via SCON: */
	llist_for_each_entry(asp, &s7i->asp_list, list) {
		/* SSNM is only permitted for ASPs in ACTIVE state */
		if (!osmo_ss7_asp_active(asp))
			continue;

		/* only send SCON if we locally are the SG and the remote is ASP */
		if (asp->cfg.role != OSMO_SS7_ASP_ROLE_SG)
			continue;

		num_rctx = ss7_asp_get_all_rctx_be(asp, rctx, ARRAY_SIZE(rctx), as);
		/* this can happen if the given ASP is only in the AS that reports the change,
		 * which shall be excluded */
		if (num_rctx == 0)
			continue;

		xua_tx_scon(asp, rctx, num_rctx, aff_pc, num_aff_pc, concerned_dpc, cong_level, info_string);
	}
}

/* receive DAUD from ASP; pc is 'affected PC' IE with mask in network byte order! */
void xua_snm_rx_daud(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *ie_aff_pc = xua_msg_find_tag(xua, M3UA_IEI_AFFECTED_PC);
	const char *info_str = xua_msg_get_str(xua, M3UA_IEI_INFO_STRING);
	struct osmo_ss7_instance *s7i = asp->inst;
	unsigned int num_aff_pc;
	unsigned int num_rctx;
	const uint32_t *aff_pc;
	uint32_t rctx[OSMO_SS7_MAX_RCTX_COUNT];
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);
	int i;

	OSMO_ASSERT(ie_aff_pc);
	aff_pc = (const uint32_t *) ie_aff_pc->dat;
	num_aff_pc = ie_aff_pc->len / sizeof(uint32_t);

	num_rctx = ss7_asp_get_all_rctx_be(asp, rctx, ARRAY_SIZE(rctx), NULL);

	LOGPASP(asp, log_ss, LOGL_INFO, "Rx DAUD(%s) for %s\n", info_str ? info_str : "",
		format_affected_pcs_c(xua, asp->inst, ie_aff_pc));

	/* iterate over list of point codes, generate DAVA/DUPU */
	for (i = 0; i < num_aff_pc; i++) {
		uint32_t _aff_pc = ntohl(aff_pc[i]);
		uint32_t pc = _aff_pc & 0xffffff;
		uint8_t mask = _aff_pc >> 24;
		bool is_available;

		if (mask == 0) {
			/* one single point code */
			/* Check if there's an "active" route available: */
			is_available = ss7_route_table_dpc_is_accessible(s7i->rtable_system, pc);

			xua_tx_snm_available(asp, rctx, num_rctx, &aff_pc[i], 1, "Response to DAUD",
					     is_available);
		} else {
			/* Multiple single point codes with mask indicating number of wildcarded bits. */
			uint32_t maskbits = (1 << mask) - 1;
			uint32_t fullpc;
			unsigned int num_aff_pc_avail = 0;
			unsigned int num_aff_pc_unavail = 0;
			uint32_t *aff_pc_avail = talloc_size(asp, sizeof(uint32_t)*(1 << mask));
			uint32_t *aff_pc_unavail = talloc_size(asp, sizeof(uint32_t)*(1 << mask));
			for (fullpc = (pc & ~maskbits); fullpc <= (pc | maskbits); fullpc++) {
				is_available = ss7_route_table_dpc_is_accessible(s7i->rtable_system, fullpc);
				if (is_available)
					aff_pc_avail[num_aff_pc_avail++] = htonl(fullpc); /* mask = 0 */
				else
					aff_pc_unavail[num_aff_pc_unavail++] = htonl(fullpc); /* mask = 0 */
			}
			/* TODO: Ideally an extra step would be needed here to pack again all
			 * concurrent PCs on each array sharing a suffix mask, in order to
			 * shrink the transmitted list of Affected PCs. */
			const unsigned int MAX_PC_PER_MSG = 32;
			for (unsigned int i = 0; i < num_aff_pc_avail; i += MAX_PC_PER_MSG) {
				unsigned int num_transmit;
				if (i + MAX_PC_PER_MSG < num_aff_pc_avail)
					num_transmit = MAX_PC_PER_MSG;
				else
					num_transmit = (num_aff_pc_avail - i);
				xua_tx_snm_available(asp, rctx, num_rctx, &aff_pc_avail[i],
					 num_transmit, "Response to DAUD", true);
			}
			for (unsigned int i = 0; i < num_aff_pc_unavail; i += MAX_PC_PER_MSG) {
				unsigned int num_transmit;
				if (i + MAX_PC_PER_MSG < num_aff_pc_unavail)
					num_transmit = MAX_PC_PER_MSG;
				else
					num_transmit = (num_aff_pc_unavail - i);
				xua_tx_snm_available(asp, rctx, num_rctx, &aff_pc_unavail[i],
					 num_transmit, "Response to DAUD", false);
			}
			talloc_free(aff_pc_avail);
			talloc_free(aff_pc_unavail);
		}
	}
}

/* an incoming xUA DUNA was received from a remote SG */
void xua_snm_rx_duna(struct osmo_ss7_asp *asp, struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct xua_msg_part *ie_aff_pc = xua_msg_find_tag(xua, M3UA_IEI_AFFECTED_PC);
	struct xua_msg_part *ie_ssn = xua_msg_find_tag(xua, SUA_IEI_SSN);
	const char *info_str = xua_msg_get_str(xua, M3UA_IEI_INFO_STRING);
	/* TODO: should our processing depend on the RCTX included? I somehow don't think so */
	//struct xua_msg_part *ie_rctx = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);

	OSMO_ASSERT(ie_aff_pc);

	if (asp->cfg.role != OSMO_SS7_ASP_ROLE_ASP)
		return;

	LOGPASP(asp, log_ss, LOGL_NOTICE, "Rx DUNA(%s) for %s\n", info_str ? info_str : "",
		format_affected_pcs_c(xua, asp->inst, ie_aff_pc));

	if (asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA && ie_ssn) {
		/* when the SSN is included, DUNA corresponds to the SCCP N-STATE primitive */
		uint32_t ssn = xua_msg_part_get_u32(ie_ssn);
		const uint32_t *aff_pc = (const uint32_t *)ie_aff_pc->dat;
		uint32_t pc, smi;
		/* The Affected Point Code can only contain one point code when SSN is present */
		if (ie_aff_pc->len/sizeof(uint32_t) != 1)
			return;
		pc = ntohl(aff_pc[0]) & 0xffffff;
		sua_snm_ssn_available(as, pc, ssn, xua_msg_get_u32p(xua, SUA_IEI_SMI, &smi), info_str, false);
	} else {
		/* when the SSN is not included, DUNA corresponds to the SCCP N-PCSTATE primitive */
		xua_snm_pc_available(as, (const uint32_t *)ie_aff_pc->dat,
				     ie_aff_pc->len / sizeof(uint32_t), info_str, false);
	}
}

/* an incoming xUA DAVA was received from a remote SG */
void xua_snm_rx_dava(struct osmo_ss7_asp *asp, struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct xua_msg_part *ie_aff_pc = xua_msg_find_tag(xua, M3UA_IEI_AFFECTED_PC);
	struct xua_msg_part *ie_ssn = xua_msg_find_tag(xua, SUA_IEI_SSN);
	const char *info_str = xua_msg_get_str(xua, M3UA_IEI_INFO_STRING);
	/* TODO: should our processing depend on the RCTX included? I somehow don't think so */
	//struct xua_msg_part *ie_rctx = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);

	OSMO_ASSERT(ie_aff_pc);

	if (asp->cfg.role != OSMO_SS7_ASP_ROLE_ASP)
		return;

	LOGPASP(asp, log_ss, LOGL_NOTICE, "Rx DAVA(%s) for %s\n", info_str ? info_str : "",
		format_affected_pcs_c(xua, asp->inst, ie_aff_pc));

	if (asp->cfg.proto == OSMO_SS7_ASP_PROT_SUA && ie_ssn) {
		/* when the SSN is included, DAVA corresponds to the SCCP N-STATE primitive */
		uint32_t ssn = xua_msg_part_get_u32(ie_ssn);
		const uint32_t *aff_pc = (const uint32_t *)ie_aff_pc->dat;
		uint32_t pc, smi;
		/* The Affected Point Code can only contain one point code when SSN is present */
		if (ie_aff_pc->len/sizeof(uint32_t) != 1)
			return;
		pc = ntohl(aff_pc[0]) & 0xffffff;
		sua_snm_ssn_available(as, pc, ssn, xua_msg_get_u32p(xua, SUA_IEI_SMI, &smi), info_str, true);
	} else {
		/* when the SSN is not included, DAVA corresponds to the SCCP N-PCSTATE primitive */
		xua_snm_pc_available(as, (const uint32_t *)ie_aff_pc->dat,
				     ie_aff_pc->len / sizeof(uint32_t), info_str, true);
	}
}

/* an incoming SUA/M3UA DUPU was received from a remote SG */
void xua_snm_rx_dupu(struct osmo_ss7_asp *asp, struct osmo_ss7_as *as, struct xua_msg *xua)
{
	uint32_t aff_pc = xua_msg_get_u32(xua, SUA_IEI_AFFECTED_PC);
	const char *info_str = xua_msg_get_str(xua, SUA_IEI_INFO_STRING);
	/* TODO: should our processing depend on the RCTX included? I somehow don't think so */
	//struct xua_msg_part *ie_rctx = xua_msg_find_tag(xua, SUA_IEI_ROUTE_CTX);
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);
	uint32_t cause_user;
	uint16_t cause, user;

	if (asp->cfg.role != OSMO_SS7_ASP_ROLE_ASP)
		return;

	switch (asp->cfg.proto) {
	case OSMO_SS7_ASP_PROT_M3UA:
		cause_user = xua_msg_get_u32(xua, M3UA_IEI_USER_CAUSE);
		break;
	case OSMO_SS7_ASP_PROT_SUA:
		cause_user = xua_msg_get_u32(xua, SUA_IEI_USER_CAUSE);
		break;
	default:
		return;
	}

	cause = cause_user >> 16;
	user = cause_user & 0xffff;
	LOGPASP(asp, log_ss, LOGL_NOTICE, "Rx DUPU(%s) for %s User %s, cause %u\n",
		info_str ? info_str : "", osmo_ss7_pointcode_print(asp->inst, aff_pc),
		get_value_string(mtp_si_vals, user), cause);

	xua_snm_upu(as, aff_pc, user, cause, info_str);
}

/* an incoming SUA/M3UA SCON was received from a remote SG */
void xua_snm_rx_scon(struct osmo_ss7_asp *asp, struct osmo_ss7_as *as, struct xua_msg *xua)
{
	struct xua_msg_part *ie_aff_pc = xua_msg_find_tag(xua, M3UA_IEI_AFFECTED_PC);
	const char *info_str = xua_msg_get_str(xua, M3UA_IEI_INFO_STRING);
	uint32_t _concerned_dpc, _cong_level;
	const uint32_t *concerned_dpc = xua_msg_get_u32p(xua, M3UA_IEI_CONC_DEST, &_concerned_dpc);
	const uint32_t *cong_level = xua_msg_get_u32p(xua, M3UA_IEI_CONG_IND, &_cong_level);
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);

	OSMO_ASSERT(ie_aff_pc);

	LOGPASP(asp, log_ss, LOGL_NOTICE, "RX SCON(%s) for %s level=%u\n", info_str ? info_str : "",
		format_affected_pcs_c(xua, asp->inst, ie_aff_pc), cong_level ? *cong_level : 0);

	xua_snm_scon(as, (const uint32_t *) ie_aff_pc->dat, ie_aff_pc->len / sizeof(uint32_t),
		     concerned_dpc, (const uint8_t *) cong_level, info_str);
}
