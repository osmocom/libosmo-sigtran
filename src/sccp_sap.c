/* SCCP User SAP related routines */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
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

#include <string.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/prim.h>

#include <osmocom/sigtran/sccp_sap.h>

#include "ss7_instance.h"
#include "sccp_connection.h"
#include "sccp_scoc_fsm.h"
#include "sccp_internal.h"
#include "sccp_user.h"

const struct value_string osmo_scu_prim_type_names[] = {
	{ OSMO_SCU_PRIM_N_CONNECT,		"N-CONNECT" },
	{ OSMO_SCU_PRIM_N_DATA,			"N-DATA" },
	{ OSMO_SCU_PRIM_N_EXPEDITED_DATA,	"N-EXPEDITED-DATA" },
	{ OSMO_SCU_PRIM_N_DISCONNECT,		"N-DISCONNECT" },
	{ OSMO_SCU_PRIM_N_RESET,		"N-RESET" },
	{ OSMO_SCU_PRIM_N_INFORM,		"N-INFORM" },
	{ OSMO_SCU_PRIM_N_UNITDATA,		"N-UNITDATA" },
	{ OSMO_SCU_PRIM_N_NOTICE,		"N-NOTICE" },
	/* management */
	{ OSMO_SCU_PRIM_N_COORD,		"N-COORD" },
	{ OSMO_SCU_PRIM_N_STATE,		"N-STATE" },
	{ OSMO_SCU_PRIM_N_PCSTATE,		"N-PCSTATE" },
	{ 0, NULL }
};

static char prim_name_buf[128];

char *osmo_scu_prim_name(const struct osmo_prim_hdr *oph)
{
	osmo_scu_prim_hdr_name_buf(prim_name_buf, sizeof(prim_name_buf), oph);
	return prim_name_buf;
}

int osmo_scu_prim_hdr_name_buf(char *buf, size_t buflen, const struct osmo_prim_hdr *oph)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	if (!oph) {
		OSMO_STRBUF_PRINTF(sb, "null");
		return sb.chars_needed;
	}

	OSMO_STRBUF_PRINTF(sb, "%s.%s",
			   osmo_scu_prim_type_name(oph->primitive),
			   osmo_prim_operation_name(oph->operation));
	return sb.chars_needed;
}

char *osmo_scu_prim_hdr_name_c(void *ctx, const struct osmo_prim_hdr *oph)
{
	OSMO_NAME_C_IMPL(ctx, 32, "ERROR", osmo_scu_prim_hdr_name_buf, oph)
}

#include <osmocom/sigtran/sigtran_sap.h>

const struct value_string osmo_xlm_prim_names[] = {
	{ OSMO_XLM_PRIM_M_SCTP_ESTABLISH,	"M-SCTP_ESTABLISH" },
	{ OSMO_XLM_PRIM_M_SCTP_RELEASE,		"M-SCTP_RELEASE" },
	{ OSMO_XLM_PRIM_M_SCTP_RESTART,		"M-SCTP_RESTART" },
	{ OSMO_XLM_PRIM_M_SCTP_STATUS,		"M-SCTP_STATUS" },
	{ OSMO_XLM_PRIM_M_ASP_STATUS,		"M-ASP_STATUS" },
	{ OSMO_XLM_PRIM_M_AS_STATUS,		"M-AS_STATUS" },
	{ OSMO_XLM_PRIM_M_NOTIFY,		"M-NOTIFY" },
	{ OSMO_XLM_PRIM_M_ERROR,		"M-ERROR" },
	{ OSMO_XLM_PRIM_M_ASP_UP,		"M-ASP_UP" },
	{ OSMO_XLM_PRIM_M_ASP_DOWN,		"M-ASP_DOWN" },
	{ OSMO_XLM_PRIM_M_ASP_ACTIVE,		"M-ASP_ACTIVE" },
	{ OSMO_XLM_PRIM_M_ASP_INACTIVE,		"M-ASP_INACTIVE" },
	{ OSMO_XLM_PRIM_M_AS_ACTIVE,		"M-AS_ACTIVE" },
	{ OSMO_XLM_PRIM_M_AS_INACTIVE,		"M-AS_INACTIVE" },
	{ OSMO_XLM_PRIM_M_AS_DOWN,		"M-AS_DOWN" },
	/* optional as per spec, not implemented yet */
	{ OSMO_XLM_PRIM_M_RK_REG,		"M-RK_REG" },
	{ OSMO_XLM_PRIM_M_RK_DEREG,		"M-RK_DEREG" },
	{ 0, NULL },
};

char *osmo_xlm_prim_name(struct osmo_prim_hdr *oph)
{
	const char *name = get_value_string(osmo_xlm_prim_names, oph->primitive);

	snprintf(prim_name_buf, sizeof(prim_name_buf), "%s.%s", name,
		 get_value_string(osmo_prim_op_names, oph->operation));

	return prim_name_buf;
}

const struct value_string osmo_sccp_routing_ind_names[] = {
	{ OSMO_SCCP_RI_NONE,	"NONE" },
	{ OSMO_SCCP_RI_GT,	"GT" },
	{ OSMO_SCCP_RI_SSN_PC,	"SSN_PC" },
	{ OSMO_SCCP_RI_SSN_IP,	"SSN_IP" },
	{ 0, NULL }
};

const struct value_string osmo_sccp_gti_names[] = {
	{ OSMO_SCCP_GTI_NO_GT,		"NO_GT" },
	{ OSMO_SCCP_GTI_NAI_ONLY,	"NAI_ONLY" },
	{ OSMO_SCCP_GTI_TT_ONLY,	"TT_ONLY" },
	{ OSMO_SCCP_GTI_TT_NPL_ENC,	"TT_NPL_ENC" },
	{ OSMO_SCCP_GTI_TT_NPL_ENC_NAI,	"TT_NPL_ENC_NAI" },
	{ 0, NULL }
};

const struct value_string osmo_sccp_sp_status_names[] = {
	{ OSMO_SCCP_SP_S_INACCESSIBLE, "INACCESSIBLE" },
	{ OSMO_SCCP_SP_S_CONGESTED, "CONGESTED" },
	{ OSMO_SCCP_SP_S_ACCESSIBLE, "ACCESSIBLE" },
	{}
};

const struct value_string osmo_sccp_rem_sccp_status_names[] = {
	{ OSMO_SCCP_REM_SCCP_S_AVAILABLE, "AVAILABLE" },
	{ OSMO_SCCP_REM_SCCP_S_UNAVAILABLE_UNKNOWN, "UNAVAILABLE_UNKNOWN" },
	{ OSMO_SCCP_REM_SCCP_S_UNEQUIPPED, "UNEQUIPPED" },
	{ OSMO_SCCP_REM_SCCP_S_INACCESSIBLE, "INACCESSIBLE" },
	{ OSMO_SCCP_REM_SCCP_S_CONGESTED, "CONGESTED" },
	{}
};

const struct value_string osmo_sccp_ssn_names[] = {
	{ OSMO_SCCP_SSN_MGMT,		"MGMT" },
	{ OSMO_SCCP_SSN_ISUP,		"ISUP" },
	{ OSMO_SCCP_SSN_OMAP,		"OMAP" },
	{ OSMO_SCCP_SSN_MAP,		"MAP" },
	{ OSMO_SCCP_SSN_HLR,		"HLR" },
	{ OSMO_SCCP_SSN_VLR,		"VLR" },
	{ OSMO_SCCP_SSN_MSC,		"MSC" },
	{ OSMO_SCCP_SSN_EIR,		"EIR" },
	{ OSMO_SCCP_SSN_AUC,		"AUC" },
	{ OSMO_SCCP_SSN_ISDN_SS,	"ISDN_SS" },
	{ OSMO_SCCP_SSN_RES_INTL,	"RES_INTL" },
	{ OSMO_SCCP_SSN_BISDN,		"BISDN" },
	{ OSMO_SCCP_SSN_TC_TEST,	"TC_TEST" },
	{ OSMO_SCCP_SSN_RANAP,		"RANAP" },
	{ OSMO_SCCP_SSN_RNSAP,		"RNSAP" },
	{ OSMO_SCCP_SSN_GMLC_MAP,	"GMLC_MAP" },
	{ OSMO_SCCP_SSN_CAP,		"CAP" },
	{ OSMO_SCCP_SSN_gsmSCF_MAP,	"gsmSCF_MAP" },
	{ OSMO_SCCP_SSN_SIWF_MAP,	"SIWF_MAP" },
	{ OSMO_SCCP_SSN_SGSN_MAP,	"SGSN_MAP" },
	{ OSMO_SCCP_SSN_GGSN_MAP,	"GGSN_MAP" },
	{ OSMO_SCCP_SSN_PCAP,		"PCAP" },
	{ OSMO_SCCP_SSN_BSC_BSSAP_LE,	"BSC_BSSAP_LE" },
	{ OSMO_SCCP_SSN_MSC_BSSAP_LE,	"MSC_BSSAP_LE" },
	{ OSMO_SCCP_SSN_SMLC_BSSAP,	"SMLC_BSSAP" },
	{ OSMO_SCCP_SSN_BSS_OAM,	"BSS_OAM" },
	{ OSMO_SCCP_SSN_BSSAP,		"BSSAP" },
	{ 0, NULL }
};

/* get the Connection ID of the given SCU primitive */
static uint32_t scu_prim_conn_id(const struct osmo_scu_prim *prim)
{
	switch (prim->oph.primitive) {
	case OSMO_SCU_PRIM_N_CONNECT:
		return prim->u.connect.conn_id;
	case OSMO_SCU_PRIM_N_DATA:
		return prim->u.data.conn_id;
	case OSMO_SCU_PRIM_N_DISCONNECT:
		return prim->u.disconnect.conn_id;
	case OSMO_SCU_PRIM_N_RESET:
		return prim->u.reset.conn_id;
	default:
		return 0;
	}
}

/* map from SCU-primitives to SCOC FSM events */
static const struct osmo_prim_event_map scu_scoc_event_map[] = {
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_CONN_REQ },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_RESPONSE,
		SCOC_E_SCU_N_CONN_RESP },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_DATA_REQ },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_DISC_REQ },
	{ SCCP_SAP_USER, OSMO_SCU_PRIM_N_EXPEDITED_DATA, PRIM_OP_REQUEST,
		SCOC_E_SCU_N_EXP_DATA_REQ },
	{ 0, 0, 0, OSMO_NO_EVENT }
};

/*! Main entrance function for primitives from SCCP User.
 * The caller is required to free oph->msg, otherwise the same as osmo_sccp_user_sap_down().
 *  \param[in] scu SCCP User sending us the primitive
 *  \param[in] oph Osmocom primitive sent by the user
 *  \returns 0 on success; negative on error */
int osmo_sccp_user_sap_down_nofree(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct osmo_sccp_instance *inst = scu->inst;
	struct sccp_connection *conn;
	int rc = 0;
	int event;

	LOGPSCU(scu, LOGL_DEBUG, "Received SCCP User Primitive (%s)\n",
		osmo_scu_prim_name(&prim->oph));

	switch (OSMO_PRIM_HDR(&prim->oph)) {
	case OSMO_PRIM(OSMO_SCU_PRIM_N_UNITDATA, PRIM_OP_REQUEST):
	/* other CL primitives? */
		/* Connectionless by-passes this altogether */
		return sccp_sclc_user_sap_down_nofree(scu, oph);
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_REQUEST):
		/* Allocate new connection structure */
		conn = sccp_conn_alloc(scu, prim->u.connect.conn_id);
		if (!conn) {
			/* FIXME: inform SCCP user with proper reply */
			LOGPSCU(scu, LOGL_ERROR, "Cannot create conn-id for primitive %s\n",
				osmo_scu_prim_name(&prim->oph));
			return rc;
		}
		break;
	case OSMO_PRIM(OSMO_SCU_PRIM_N_CONNECT, PRIM_OP_RESPONSE):
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DATA, PRIM_OP_REQUEST):
	case OSMO_PRIM(OSMO_SCU_PRIM_N_DISCONNECT, PRIM_OP_REQUEST):
	case OSMO_PRIM(OSMO_SCU_PRIM_N_RESET, PRIM_OP_REQUEST):
		/* Resolve existing connection structure */
		conn = sccp_find_conn_by_id(inst, scu_prim_conn_id(prim));
		if (!conn) {
			/* FIXME: inform SCCP user with proper reply */
			LOGPSCU(scu, LOGL_ERROR, "Received unknown conn-id %u for primitive %s\n",
				scu_prim_conn_id(prim), osmo_scu_prim_name(&prim->oph));
			return rc;
		}
		break;
	default:
		LOGPSCU(scu, LOGL_ERROR, "Received unknown primitive %s\n",
			osmo_scu_prim_name(&prim->oph));
		return -1;
	}

	/* Map from primitive to event */
	event = osmo_event_for_prim(oph, scu_scoc_event_map);

	/* Dispatch event into connection */
	return osmo_fsm_inst_dispatch(conn->fi, event, prim);
}

/*! Main entrance function for primitives from SCCP User.
 * Implies a msgb_free(oph->msg), otherwise the same as osmo_sccp_user_sap().
 *  \param[in] scu SCCP User sending us the primitive
 *  \param[in] oph Osmocom primitive sent by the user
 *  \returns 0 on success; negative on error */
int osmo_sccp_user_sap_down(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph)
{
	struct osmo_scu_prim *prim = (struct osmo_scu_prim *) oph;
	struct msgb *msg = prim->oph.msg;
	int rc = osmo_sccp_user_sap_down_nofree(scu, oph);
	msgb_free(msg);
	return rc;
}
