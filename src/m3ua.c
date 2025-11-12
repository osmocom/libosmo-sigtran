/* Minimal implementation of RFC 4666 - MTP3 User Adaptation Layer */

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

#include <osmocom/netif/stream.h>
#include "xua_msg.h"

#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>

#include "xua_as_fsm.h"
#include "xua_asp_fsm.h"
#include "xua_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_internal.h"

#define M3UA_MSGB_SIZE 1500

/***********************************************************************
 * Protocol Definition (string tables, mandatory IE checking)
 ***********************************************************************/

/* Section 3.8.1 */
const struct value_string m3ua_err_names[] = {
	{ M3UA_ERR_INVALID_VERSION,	"Invalid Version" },
	{ M3UA_ERR_UNSUPP_MSG_CLASS,	"Unsupported Message Class" },
	{ M3UA_ERR_UNSUPP_MSG_TYPE,	"Unsupported Message Type" },
	{ M3UA_ERR_UNSUPP_TRAF_MOD_TYP,	"Unsupported Traffic Mode Type" },
	{ M3UA_ERR_UNEXPECTED_MSG,	"Unexpected Message" },
	{ M3UA_ERR_PROTOCOL_ERR,	"Protocol Error" },
	{ M3UA_ERR_INVAL_STREAM_ID,	"Invalid Stream Identifier" },
	{ M3UA_ERR_REFUSED_MGMT_BLOCKING, "Refused - Management Blocking" },
	{ M3UA_ERR_ASP_ID_REQD,		"ASP Identifier Required" },
	{ M3UA_ERR_INVAL_ASP_ID,	"Invalid ASP Identifier" },
	{ M3UA_ERR_INVAL_PARAM_VAL,	"Invalid Parameter Value" },
	{ M3UA_ERR_PARAM_FIELD_ERR,	"Parameter Field Error" },
	{ M3UA_ERR_UNEXP_PARAM,		"Unexpected Parameter" },
	{ M3UA_ERR_DEST_STATUS_UNKN,	"Destination Status Unknown" },
	{ M3UA_ERR_INVAL_NET_APPEAR,	"Invalid Network Appearance" },
	{ M3UA_ERR_MISSING_PARAM,	"Missing Parameter" },
	{ M3UA_ERR_INVAL_ROUT_CTX,	"Invalid Routing Context" },
	{ M3UA_ERR_NO_CONFGD_AS_FOR_ASP,"No Configured AS for ASP" },
	{ SUA_ERR_SUBSYS_STATUS_UNKN,	"Subsystem Status Unknown" },
	{ SUA_ERR_INVAL_LOADSH_LEVEL,	"Invalid loadsharing level" },
	{ 0, NULL }
};

const struct value_string m3ua_ntfy_type_names[] = {
	{ M3UA_NOTIFY_T_STATCHG,	"State Change" },
	{ M3UA_NOTIFY_T_OTHER,		"Other" },
	{ 0, NULL }
};

const struct value_string m3ua_ntfy_stchg_names[] = {
	{ M3UA_NOTIFY_I_RESERVED,	"Reserved" },
	{ M3UA_NOTIFY_I_AS_INACT,	"AS Inactive" },
	{ M3UA_NOTIFY_I_AS_ACT,		"AS Active" },
	{ M3UA_NOTIFY_I_AS_PEND,	"AS Pending" },
	{ 0, NULL }
};

const struct value_string m3ua_ntfy_other_names[] = {
	{ M3UA_NOTIFY_I_OT_INS_RES,	"Insufficient ASP Resources active in AS" },
	{ M3UA_NOTIFY_I_OT_ALT_ASP_ACT,	"Alternative ASP Active" },
	{ M3UA_NOTIFY_I_OT_ASP_FAILURE,	"ASP Failure" },
	{ 0, NULL }
};

const char *m3ua_ntfy_info_name(uint16_t ntfy_status_type, uint16_t ntfy_status_info)
{
	switch (ntfy_status_type) {
	case M3UA_NOTIFY_T_STATCHG:
		return get_value_string(m3ua_ntfy_stchg_names, ntfy_status_info);
	case M3UA_NOTIFY_T_OTHER:
		return get_value_string(m3ua_ntfy_other_names, ntfy_status_info);
	default:
		break;
	}
	return "NULL";
}

static const struct value_string m3ua_iei_names[] = {
	{ M3UA_IEI_INFO_STRING,		"INFO String" },
	{ M3UA_IEI_ROUTE_CTX,		"Routing Context" },
	{ M3UA_IEI_DIAG_INFO,		"Diagnostic Info" },
	{ M3UA_IEI_HEARDBT_DATA,	"Heartbeat Data" },
	{ M3UA_IEI_TRAF_MODE_TYP,	"Traffic Mode Type" },
	{ M3UA_IEI_ERR_CODE,		"Error Code" },
	{ M3UA_IEI_STATUS,		"Status" },
	{ M3UA_IEI_ASP_ID,		"ASP Identifier" },
	{ M3UA_IEI_AFFECTED_PC,		"Affected Point Code" },
	{ M3UA_IEI_CORR_ID,		"Correlation Id" },

	{ M3UA_IEI_NET_APPEAR,		"Network Appearance" },
	{ M3UA_IEI_USER_CAUSE,		"User/Cause" },
	{ M3UA_IEI_CONG_IND,		"Congestion Indication" },
	{ M3UA_IEI_CONC_DEST,		"Concerned Destination" },
	{ M3UA_IEI_ROUT_KEY,		"Routing Key" },
	{ M3UA_IEI_REG_RESULT,		"Registration Result" },
	{ M3UA_IEI_DEREG_RESULT,	"De-Registration Result" },
	{ M3UA_IEI_LOC_RKEY_ID,		"Local Routing-Key Identifier" },
	{ M3UA_IEI_DEST_PC,		"Destination Point Code" },
	{ M3UA_IEI_SVC_IND,		"Service Indicators" },
	{ M3UA_IEI_ORIG_PC,		"Originating Point Code List" },
	{ M3UA_IEI_PROT_DATA,		"Protocol Data" },
	{ M3UA_IEI_REG_STATUS,		"Registration Status" },
	{ M3UA_IEI_DEREG_STATUS,	"De-Registration Status" },
	{ 0, NULL }
};

#define MAND_IES(msgt, ies)	[msgt] = (ies)

/* XFER */
static const uint16_t data_mand_ies[] = {
	M3UA_IEI_PROT_DATA, 0
};
static const struct value_string m3ua_xfer_msgt_names[] = {
	{ M3UA_XFER_DATA,	"DATA" },
	{ 0, NULL }
};
static const struct xua_msg_class msg_class_xfer = {
	.name = "XFER",
	.msgt_names = m3ua_xfer_msgt_names,
	.mand_ies = {
		MAND_IES(M3UA_XFER_DATA, data_mand_ies),
	},
};

/* SNM */
static const uint16_t duna_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t dava_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t daud_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t scon_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const uint16_t dupu_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, M3UA_IEI_USER_CAUSE, 0
};
static const uint16_t drst_mand_ies[] = {
	M3UA_IEI_AFFECTED_PC, 0
};
static const struct value_string m3ua_snm_msgt_names[] = {
	{ M3UA_SNM_DUNA,	"DUNA" },
	{ M3UA_SNM_DAVA,	"DAVA" },
	{ M3UA_SNM_DAUD,	"DAUD" },
	{ M3UA_SNM_SCON,	"SCON" },
	{ M3UA_SNM_DUPU,	"DUPU" },
	{ M3UA_SNM_DRST,	"DRST" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_snm = {
	.name = "SNM",
	.msgt_names = m3ua_snm_msgt_names,
	.mand_ies = {
		MAND_IES(M3UA_SNM_DUNA, duna_mand_ies),
		MAND_IES(M3UA_SNM_DAVA, dava_mand_ies),
		MAND_IES(M3UA_SNM_DAUD, daud_mand_ies),
		MAND_IES(M3UA_SNM_SCON, scon_mand_ies),
		MAND_IES(M3UA_SNM_DUPU, dupu_mand_ies),
		MAND_IES(M3UA_SNM_DRST, drst_mand_ies),
	},
};

/* ASPSM */
static const struct value_string m3ua_aspsm_msgt_names[] = {
	{ M3UA_ASPSM_UP,	"UP" },
	{ M3UA_ASPSM_DOWN,	"DOWN" },
	{ M3UA_ASPSM_BEAT,	"BEAT" },
	{ M3UA_ASPSM_UP_ACK,	"UP-ACK" },
	{ M3UA_ASPSM_DOWN_ACK,	"DOWN-ACK" },
	{ M3UA_ASPSM_BEAT_ACK,	"BEAT-ACK" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_aspsm = {
	.name = "ASPSM",
	.msgt_names = m3ua_aspsm_msgt_names,
};

/* ASPTM */
const struct value_string m3ua_asptm_msgt_names[] = {
	{ M3UA_ASPTM_ACTIVE,	"ACTIVE" },
	{ M3UA_ASPTM_INACTIVE,	"INACTIVE" },
	{ M3UA_ASPTM_ACTIVE_ACK,"ACTIVE-ACK" },
	{ M3UA_ASPTM_INACTIVE_ACK, "INACTIVE-ACK" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_asptm = {
	.name = "ASPTM",
	.msgt_names = m3ua_asptm_msgt_names,
	.iei_names = m3ua_iei_names,
};

/* MGMT */
static const uint16_t err_req_ies[] = {
	M3UA_IEI_ERR_CODE, 0
};
static const uint16_t ntfy_req_ies[] = {
	M3UA_IEI_STATUS, 0
};
static const struct value_string m3ua_mgmt_msgt_names[] = {
	{ M3UA_MGMT_ERR,	"ERROR" },
	{ M3UA_MGMT_NTFY,	"NOTIFY" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_mgmt = {
	.name = "MGMT",
	.msgt_names = m3ua_mgmt_msgt_names,
	.iei_names = m3ua_iei_names,
	.mand_ies = {
		MAND_IES(M3UA_MGMT_ERR, err_req_ies),
		MAND_IES(M3UA_MGMT_NTFY, ntfy_req_ies),
	},
};

/* RKM */
static const uint16_t reg_req_ies[] = {
	M3UA_IEI_ROUT_KEY, 0
};
static const uint16_t reg_rsp_ies[] = {
	M3UA_IEI_REG_RESULT, 0
};
static const uint16_t dereg_req_ies[] = {
	M3UA_IEI_ROUTE_CTX, 0
};
static const uint16_t dereg_rsp_ies[] = {
	M3UA_IEI_DEREG_RESULT, 0
};
static const struct value_string m3ua_rkm_msgt_names[] = {
	{ M3UA_RKM_REG_REQ,	"REG-REQ" },
	{ M3UA_RKM_REG_RSP,	"REG-RESP" },
	{ M3UA_RKM_DEREG_REQ,	"DEREG-REQ" },
	{ M3UA_RKM_DEREG_RSP,	"DEREG-RESP" },
	{ 0, NULL }
};
const struct xua_msg_class m3ua_msg_class_rkm = {
	.name = "RKM",
	.msgt_names = m3ua_rkm_msgt_names,
	.iei_names = m3ua_iei_names,
	.mand_ies = {
		MAND_IES(M3UA_RKM_REG_REQ, reg_req_ies),
		MAND_IES(M3UA_RKM_REG_RSP, reg_rsp_ies),
		MAND_IES(M3UA_RKM_DEREG_REQ, dereg_req_ies),
		MAND_IES(M3UA_RKM_DEREG_RSP, dereg_rsp_ies),
	},
};

/* M3UA dialect of XUA, MGMT,XFER,SNM,ASPSM,ASPTM,RKM */
const struct xua_dialect xua_dialect_m3ua = {
	.name = "M3UA",
	.ppid = M3UA_PPID,
	.port = M3UA_PORT,
	.log_subsys = DLM3UA,
	.class = {
		[M3UA_MSGC_MGMT] = &m3ua_msg_class_mgmt,
		[M3UA_MSGC_XFER] = &msg_class_xfer,
		[M3UA_MSGC_SNM] = &m3ua_msg_class_snm,
		[M3UA_MSGC_ASPSM] = &m3ua_msg_class_aspsm,
		[M3UA_MSGC_ASPTM] = &m3ua_msg_class_asptm,
		[M3UA_MSGC_RKM] = &m3ua_msg_class_rkm,
	},
};

/* convert osmo_mtp_transfer_param to m3ua_data_hdr */
void mtp_xfer_param_to_m3ua_dh(struct m3ua_data_hdr *mdh,
				const struct osmo_mtp_transfer_param *param)
{
	mdh->opc = htonl(param->opc);
	mdh->dpc = htonl(param->dpc);
	mdh->si = param->sio & 0xF;
	mdh->ni = (param->sio >> 6) & 0x3;
	mdh->mp = (param->sio >> 4) & 0x3;
	mdh->sls = param->sls;
}

/* convert m3ua_data_hdr to osmo_mtp_transfer_param */
void m3ua_dh_to_xfer_param(struct osmo_mtp_transfer_param *param,
			   const struct m3ua_data_hdr *mdh)
{
	param->opc = ntohl(mdh->opc);
	param->dpc = ntohl(mdh->dpc);
	param->sls = mdh->sls;
	/* re-construct SIO */
	param->sio = (mdh->si & 0xF) |
		     (mdh->mp & 0x3 << 4) |
		     (mdh->ni & 0x3 << 6);
}

struct msgb *m3ua_msgb_alloc(const char *name)
{
	if (!name)
		name = "M3UA";
	return msgb_alloc_headroom(M3UA_MSG_SIZE+M3UA_MSG_HEADROOM,
				   M3UA_MSG_HEADROOM, name);
}

struct xua_msg *m3ua_xfer_from_data(const struct m3ua_data_hdr *data_hdr,
				    const uint8_t *data, unsigned int data_len)
{
	struct xua_msg *xua = xua_msg_alloc();
	struct xua_msg_part *data_part;

	xua->hdr = XUA_HDR(M3UA_MSGC_XFER, M3UA_XFER_DATA);
	/* Network Appearance: Optional */
	/* Routing Context: Conditional */
	/* Protocol Data: Mandatory */
	data_part = talloc_zero(xua, struct xua_msg_part);
	OSMO_ASSERT(data_part);
	data_part->tag = M3UA_IEI_PROT_DATA;
	data_part->len = sizeof(*data_hdr) + data_len;
	data_part->dat = talloc_size(data_part, data_part->len);
	OSMO_ASSERT(data_part->dat);
	memcpy(data_part->dat, data_hdr, sizeof(*data_hdr));
	memcpy(data_part->dat+sizeof(*data_hdr), data, data_len);
	llist_add_tail(&data_part->entry, &xua->headers);
	/* Correlation Id: Optional */

	return xua;
}

/***********************************************************************
 * ERROR generation
 ***********************************************************************/

static struct xua_msg *m3ua_gen_error(uint32_t err_code)
{
	struct xua_msg *xua = xua_msg_alloc();

	if (!xua) {
		LOGP(DLM3UA, LOGL_NOTICE, "Failed to allocate M3UA MGMT error message.\n");
		return NULL;
	}

	xua->hdr = XUA_HDR(M3UA_MSGC_MGMT, M3UA_MGMT_ERR);
	xua->hdr.version = M3UA_VERSION;
	xua_msg_add_u32(xua, M3UA_IEI_ERR_CODE, err_code);

	return xua;
}

static struct xua_msg *m3ua_gen_error_msg(uint32_t err_code, struct msgb *msg)
{
	struct xua_msg *err = m3ua_gen_error(err_code);
	struct xua_msg *xua;
	struct xua_msg_part *na_ie;
	unsigned int len_max_40;

	if (!err)
		return NULL;

	switch (err_code) {
	case M3UA_ERR_INVAL_NET_APPEAR:
		/* Include NA IE in Error message. */
		xua = xua_from_msg(M3UA_VERSION, msgb_length(msg), msgb_data(msg));
		na_ie = xua_msg_find_tag(xua, M3UA_IEI_NET_APPEAR);
		xua_msg_add_data(err, M3UA_IEI_NET_APPEAR, na_ie->len, na_ie->dat);
		xua_msg_free(xua);
		break;
	default:
		len_max_40 = msgb_length(msg);
		if (len_max_40 > 40)
			len_max_40 = 40;

		xua_msg_add_data(err, M3UA_IEI_DIAG_INFO, len_max_40, msgb_data(msg));
	}

	return err;
}

/***********************************************************************
 * NOTIFY generation
 ***********************************************************************/

/* RFC4666 Ch. 3.8.2. Notify */
struct xua_msg *m3ua_encode_notify(const struct osmo_xlm_prim_notify *npar)
{
	struct xua_msg *xua = xua_msg_alloc();
	uint32_t status;

	xua->hdr = XUA_HDR(M3UA_MSGC_MGMT, M3UA_MGMT_NTFY);

	status = M3UA_NOTIFY(htons(npar->status_type), htons(npar->status_info));
	/* cannot use xua_msg_add_u32() as it does endian conversion */
	xua_msg_add_data(xua, M3UA_IEI_STATUS, sizeof(status), (uint8_t *) &status);

	/* Conditional: ASP Identifier */
	if (npar->presence & NOTIFY_PAR_P_ASP_ID)
		xua_msg_add_u32(xua, M3UA_IEI_ASP_ID, npar->asp_id);

	/* Optional Routing Context */
	if (npar->presence & NOTIFY_PAR_P_ROUTE_CTX) {
		xua_msg_add_u32_data(xua, M3UA_IEI_ROUTE_CTX,
				     npar->route_ctx_count * sizeof(npar->route_ctx[0]),
				     (uint8_t *)&npar->route_ctx[0]);
	}

	/* Optional: Info String */
	if (npar->info_string)
		xua_msg_add_data(xua, M3UA_IEI_INFO_STRING,
				 strlen(npar->info_string)+1,
				 (uint8_t *) npar->info_string);

	return xua;
}

/* RFC4666 Ch. 3.8.2. Notify */
int m3ua_decode_notify(struct osmo_xlm_prim_notify *npar, void *ctx,
			const struct xua_msg *xua)
{
	struct xua_msg_part *info_ie, *aspid_ie, *status_ie, *rctx_ie;
	uint32_t status;

	/* cannot use xua_msg_get_u32() as it does endian conversion */
	status_ie = xua_msg_find_tag(xua, M3UA_IEI_STATUS);
	if (!status_ie) {
		LOGP(DLM3UA, LOGL_ERROR, "M3UA NOTIFY without Status IE\n");
		return -1;
	}
	status = *(uint32_t *) status_ie->dat;

	aspid_ie = xua_msg_find_tag(xua, M3UA_IEI_ASP_ID);
	rctx_ie = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	info_ie = xua_msg_find_tag(xua, M3UA_IEI_INFO_STRING);

	npar->presence = 0;
	npar->status_type = ntohs(status & 0xffff);
	npar->status_info = ntohs(status >> 16);

	if (aspid_ie) {
		npar->asp_id = xua_msg_part_get_u32(aspid_ie);
		npar->presence |= NOTIFY_PAR_P_ASP_ID;
	}

	if (rctx_ie) {
		if (rctx_ie->len & 0x03) {
			LOGP(DLM3UA, LOGL_ERROR,
			     "M3UA NOTIFY with Routing Context IE length non-multiple of 4!\n");
			return -1;
		}
		if (rctx_ie->len > sizeof(npar->route_ctx)) {
			LOGP(DLM3UA, LOGL_ERROR,
			     "M3UA NOTIFY with Routing Context IE containing > %zu items not supported!\n",
			     ARRAY_SIZE(npar->route_ctx));
			return -1;
		}
		npar->route_ctx_count = rctx_ie->len >> 2;
		for (unsigned int i = 0; i < npar->route_ctx_count; i++)
			npar->route_ctx[i] = ntohl(*(uint32_t *)&rctx_ie->dat[i << 2]);
		npar->presence |= NOTIFY_PAR_P_ROUTE_CTX;
	}

	if (info_ie) {
		npar->info_string = talloc_size(ctx, info_ie->len);
		memcpy(npar->info_string, info_ie->dat, info_ie->len);
	} else
		npar->info_string = NULL;

	return 0;
}

/***********************************************************************
 * Transmitting M3UA messages to SCTP
 ***********************************************************************/

/* Convert M3UA from xua_msg to msgb and set PPID/stream */
struct msgb *m3ua_to_msg(struct xua_msg *xua)
{
	struct msgb *msg = xua_to_msg(M3UA_VERSION, xua);

	if (!msg) {
		LOGP(DLM3UA, LOGL_ERROR, "Error encoding M3UA Msg\n");
		return NULL;
	}

	if (xua->hdr.msg_class == M3UA_MSGC_XFER) {
		/* TODO: M3UA RFC says that multiple different streams within the SCTP association
		 * *may* be used, for example, by using the SLS value. Not required but makes sense. */
		msgb_sctp_stream(msg) = 1;
	} else
		msgb_sctp_stream(msg) = 0;
	msgb_sctp_ppid(msg) = M3UA_PPID;

	return msg;
}

/* transmit given xua_msg via given ASP
 * This function takes ownership of xua msg passed to it.
 */
static int m3ua_tx_xua_asp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct msgb *msg;

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA);

	msg = m3ua_to_msg(xua);
	xua_msg_free(xua);
	if (!msg)
		return -1;

	/* msg becomes owned by osmo_ss7_asp_send here: */
	return osmo_ss7_asp_send(asp, msg);
}

/*! \brief Send a given xUA message via a given M3UA Application Server
 *  \param[in] as Application Server through which to send \ref xua
 *  \param[in] xua xUA message to be sent
 *  \return 0 on success; negative on error
 *
 *  This function takes ownership of xua msg passed to it.
 */
int m3ua_tx_xua_as(struct osmo_ss7_as *as, struct xua_msg *xua)
{
	int rc;

	OSMO_ASSERT(as->cfg.proto == OSMO_SS7_ASP_PROT_M3UA);

	/* Add RC for this AS */
	if (as->cfg.routing_key.context)
		xua_msg_add_u32(xua, M3UA_IEI_ROUTE_CTX, as->cfg.routing_key.context);

	/* send the msg to the AS for transmission.  The AS FSM might
	 * (depending on its state) enqueue it before transmission */
	rc = osmo_fsm_inst_dispatch(as->fi, XUA_AS_E_TRANSFER_REQ, xua);
	if (rc < 0)
		xua_msg_free(xua);
	return rc;
}

/***********************************************************************
 * Receiving M3UA messages from SCTP
 ***********************************************************************/

/* obtain the destination point code from a M3UA message in XUA fmt * */
struct m3ua_data_hdr *data_hdr_from_m3ua(struct xua_msg *xua)
{
	struct xua_msg_part *data_ie;
	struct m3ua_data_hdr *data_hdr;

	if (xua->hdr.msg_class != M3UA_MSGC_XFER ||
	    xua->hdr.msg_type != M3UA_XFER_DATA)
		return NULL;

	data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	if (!data_ie)
		return NULL;
	data_hdr = (struct m3ua_data_hdr *) data_ie->dat;

	return data_hdr;
}

/* This function takes ownership of xua msg passed to it. */
static int m3ua_rx_xfer(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *data_ie = xua_msg_find_tag(xua, M3UA_IEI_PROT_DATA);
	struct xua_msg_part *na_ie = xua_msg_find_tag(xua, M3UA_IEI_NET_APPEAR);
	struct xua_msg_part *rctx_ie = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	struct m3ua_data_hdr *dh;
	struct osmo_ss7_as *as;
	int rc;

	LOGPASP(asp, DLM3UA, LOGL_DEBUG, "m3ua_rx_xfer\n");

	if (xua->hdr.msg_type != M3UA_XFER_DATA) {
		LOGPASP(asp, DLM3UA, LOGL_ERROR,
			"%s(): unsupported message type: %s\n",
			__func__,
			get_value_string(m3ua_xfer_msgt_names, xua->hdr.msg_type));
		rc = M3UA_ERR_UNSUPP_MSG_TYPE;
		goto ret_free;
	}

	/* Reject unsupported Network Appearance IE. */
	if (na_ie) {
		uint32_t na = xua_msg_part_get_u32(na_ie);

		LOGPASP(asp, DLM3UA, LOGL_NOTICE,
			"Unsupported 'Network Appearance' IE '0x%08x' in message type '%s', sending 'Error'.\n",
			na, get_value_string(m3ua_xfer_msgt_names, xua->hdr.msg_type));
		if (na_ie->len != 4)
			rc = M3UA_ERR_PARAM_FIELD_ERR;
		else
			rc = M3UA_ERR_INVAL_NET_APPEAR;
		goto ret_free;
	}

	/* store the MTP-level information in the xua_msg for use by
	 * higher layer protocols */
	OSMO_ASSERT(data_ie);
	dh = (struct m3ua_data_hdr *) data_ie->dat;
	OSMO_ASSERT(dh);
	m3ua_dh_to_xfer_param(&xua->mtp, dh);
	LOGPASP(asp, DLM3UA, LOGL_DEBUG,
		"%s(): M3UA data header: opc=%u=%s dpc=%u=%s sls=%u\n",
		__func__, xua->mtp.opc, osmo_ss7_pointcode_print(asp->inst, xua->mtp.opc),
		xua->mtp.dpc, osmo_ss7_pointcode_print2(asp->inst, xua->mtp.dpc),
		xua->mtp.sls);

	/* Drop packets not matching our configured Network Indicator: */
	if (dh->ni != asp->inst->cfg.network_indicator) {
		LOGPASP(asp, DLM3UA, LOGL_NOTICE,
			"Discarding received XUA Message %s: NI=%u not matching ss7 instance configured NI=%u\n",
			xua_hdr_dump(xua, &xua_dialect_sua), dh->ni, asp->inst->cfg.network_indicator);
		rate_ctr_inc2(asp->inst->ctrg, SS7_INST_CTR_PKT_RX_NI_MISMATCH);
		rate_ctr_inc2(asp->ctrg, SS7_ASP_CTR_PKT_RX_NI_MISMATCH);
		rc = M3UA_ERR_UNEXPECTED_MSG;
		goto ret_free;
	}

	rc = xua_find_as_for_asp(&as, asp, rctx_ie);
	if (rc)
		goto ret_free;

	if (!osmo_ss7_as_active(as)) {
		rate_ctr_inc2(as->ctrg, SS7_AS_CTR_RX_MSU_DISCARD);
		LOGPAS(as, DLM3UA, LOGL_INFO, "Discarding received XUA Message %s, AS state %s\n",
		       xua_hdr_dump(xua, &xua_dialect_sua), osmo_fsm_inst_state_name(as->fi));
		goto ret_free;
	}

	rate_ctr_inc2(as->ctrg, SS7_AS_CTR_RX_MSU_TOTAL);
	OSMO_ASSERT(xua->mtp.sls <= 0xf);
	rate_ctr_inc2(as->ctrg, SS7_AS_CTR_RX_MSU_SLS_0 + xua->mtp.sls);

	if (rctx_ie) {
		/* remove ROUTE_CTX as in the routing case we want to add a new
		 * routing context on the outbound side */
		xua_msg_free_tag(xua, M3UA_IEI_ROUTE_CTX);
	}

	/* xua ownership is passed here: */
	return m3ua_hmdc_rx_from_l2(asp->inst, xua);

ret_free:
	xua_msg_free(xua);
	return rc;
}

static int m3ua_rx_mgmt_err(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	uint32_t err_code = xua_msg_get_u32(xua, M3UA_IEI_ERR_CODE);
	struct osmo_xlm_prim *prim;

	LOGPASP(asp, DLM3UA, LOGL_ERROR, "Received MGMT_ERR '%s': %s\n",
		get_value_string(m3ua_err_names, err_code),
		xua_msg_dump(xua, &xua_dialect_m3ua));

	/* report this to layer manager */
	prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_ERROR, PRIM_OP_INDICATION);
	prim->u.error.code = err_code;
	xua_asp_send_xlm_prim(asp, prim);

	/* NEVER return != 0 here, as we cannot respont to an ERR
	 * message with another ERR! */
	return 0;
}

static int m3ua_rx_mgmt_ntfy(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct osmo_xlm_prim_notify ntfy;
	const char *type_name, *info_name;
	struct osmo_xlm_prim *prim;

	m3ua_decode_notify(&ntfy, asp, xua);

	type_name = get_value_string(m3ua_ntfy_type_names, ntfy.status_type);
	info_name = m3ua_ntfy_info_name(ntfy.status_type, ntfy.status_info);
	LOGPASP(asp, DLM3UA, LOGL_NOTICE, "Received NOTIFY Type %s:%s (%s)\n",
		type_name, info_name,
		ntfy.info_string ? ntfy.info_string : "");

	/* report this to layer manager */
	prim = xua_xlm_prim_alloc(OSMO_XLM_PRIM_M_NOTIFY, PRIM_OP_INDICATION);
	prim->u.notify = ntfy;
	xua_asp_send_xlm_prim(asp,prim);

	if (ntfy.info_string)
		talloc_free(ntfy.info_string);

	return 0;
}

/* This function takes ownership of xua msg passed to it. */
static int m3ua_rx_mgmt(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	int rc;

	switch (xua->hdr.msg_type) {
	case M3UA_MGMT_ERR:
		rc = m3ua_rx_mgmt_err(asp, xua);
		break;
	case M3UA_MGMT_NTFY:
		rc = m3ua_rx_mgmt_ntfy(asp, xua);
		break;
	default:
		rc = M3UA_ERR_UNSUPP_MSG_TYPE;
	}

	xua_msg_free(xua);
	return rc;
}

/* map from M3UA ASPSM/ASPTM to xua_asp_fsm event */
static const struct xua_msg_event_map m3ua_aspxm_map[] = {
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_UP, XUA_ASP_E_ASPSM_ASPUP },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_DOWN, XUA_ASP_E_ASPSM_ASPDN },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_BEAT, XUA_ASP_E_ASPSM_BEAT },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_UP_ACK, XUA_ASP_E_ASPSM_ASPUP_ACK },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_DOWN_ACK, XUA_ASP_E_ASPSM_ASPDN_ACK },
	{ M3UA_MSGC_ASPSM, M3UA_ASPSM_BEAT_ACK, XUA_ASP_E_ASPSM_BEAT_ACK },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_ACTIVE, XUA_ASP_E_ASPTM_ASPAC },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_INACTIVE, XUA_ASP_E_ASPTM_ASPIA },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_ACTIVE_ACK, XUA_ASP_E_ASPTM_ASPAC_ACK },
	{ M3UA_MSGC_ASPTM, M3UA_ASPTM_INACTIVE_ACK, XUA_ASP_E_ASPTM_ASPIA_ACK },
};

/* This function takes ownership of xua msg passed to it. */
static int m3ua_rx_asp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	int event;
	int rc = 0;

	/* map from the M3UA message class and message type to the XUA
	 * ASP FSM event number */
	event = xua_msg_event_map(xua, m3ua_aspxm_map,
				  ARRAY_SIZE(m3ua_aspxm_map));
	if (event < 0) {
		rc = M3UA_ERR_UNSUPP_MSG_TYPE;
		goto ret_free;
	}

	/* deliver that event to the ASP FSM */
	rc = osmo_fsm_inst_dispatch(asp->fi, event, xua);
	if (rc < 0)
		rc = M3UA_ERR_UNEXPECTED_MSG;
ret_free:
	xua_msg_free(xua);
	return rc;
}

static int m3ua_rx_snm(struct osmo_ss7_asp *asp, struct xua_msg *xua);

/*! \brief process M3UA message received from socket
 *  \param[in] asp Application Server Process receiving \ref msg
 *  \param[in] msg received message buffer
 *  \returns 0 on success; negative on error */
int m3ua_rx_msg(struct osmo_ss7_asp *asp, struct msgb *msg)
{
	struct xua_msg *xua = NULL, *err = NULL;
	int rc = 0;

	OSMO_ASSERT(asp->cfg.proto == OSMO_SS7_ASP_PROT_M3UA);

	/* caller owns msg memory, we shall neither free it here nor
	 * keep references beyond the execution of this function and its
	 * callees */

	xua = xua_from_msg(M3UA_VERSION, msgb_length(msg), msgb_data(msg));
	if (!xua) {
		struct xua_common_hdr *hdr = (struct xua_common_hdr *) msg->data;

		LOGPASP(asp, DLM3UA, LOGL_ERROR, "Unable to parse incoming "
			"M3UA message\n");

		if (hdr->version != M3UA_VERSION)
			rc = M3UA_ERR_INVALID_VERSION;
		else
			rc = M3UA_ERR_PARAM_FIELD_ERR;
		goto out;
	}

	LOGPASP(asp, DLM3UA, LOGL_DEBUG, "Received M3UA Message (%s)\n",
		xua_hdr_dump(xua, &xua_dialect_m3ua));

	if (!xua_dialect_check_all_mand_ies(&xua_dialect_m3ua, xua)) {
		rc = M3UA_ERR_MISSING_PARAM;
		xua_msg_free(xua);
		goto out;
	}

	/* TODO: check if any AS configured in ASP */
	/* TODO: check for valid routing context */

	switch (xua->hdr.msg_class) {
	case M3UA_MSGC_XFER:
		/* The DATA message MUST NOT be sent on stream 0. */
		if (msgb_sctp_stream(msg) == 0) {
			rc = M3UA_ERR_INVAL_STREAM_ID;
			xua_msg_free(xua);
			goto out;
		}
		rc = m3ua_rx_xfer(asp, xua);
		break;
	case M3UA_MSGC_ASPSM:
	case M3UA_MSGC_ASPTM:
		rc = m3ua_rx_asp(asp, xua);
		break;
	case M3UA_MSGC_MGMT:
		rc = m3ua_rx_mgmt(asp, xua);
		break;
	case M3UA_MSGC_RKM:
		rc = m3ua_rx_rkm(asp, xua);
		break;
	case M3UA_MSGC_SNM:
		rc = m3ua_rx_snm(asp, xua);
		break;
	default:
		LOGPASP(asp, DLM3UA, LOGL_NOTICE, "Received unknown M3UA "
			"Message Class %u\n", xua->hdr.msg_class);
		rc = M3UA_ERR_UNSUPP_MSG_CLASS;
		xua_msg_free(xua);
		goto out;
	}

out:
	if (rc > 0)
		err = m3ua_gen_error_msg(rc, msg);
	if (err)
		m3ua_tx_xua_asp(asp, err);
	return rc;
}

/***********************************************************************
 * SSNM msg generation
 ***********************************************************************/

/* 3.4.1 Destination Unavailable (DUNA) */
static struct xua_msg *m3ua_encode_duna(const uint32_t *rctx, unsigned int num_rctx,
					const uint32_t *aff_pc, unsigned int num_aff_pc,
					const char *info_string)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(M3UA_MSGC_SNM, M3UA_SNM_DUNA);
	xua->hdr.version = M3UA_VERSION;
	if (rctx && num_rctx)
		xua_msg_add_data(xua, M3UA_IEI_ROUTE_CTX, num_rctx * sizeof(*rctx), (const uint8_t *)rctx);

	xua_msg_add_data(xua, M3UA_IEI_AFFECTED_PC, num_aff_pc * sizeof(*aff_pc), (const uint8_t *) aff_pc);

	if (info_string) {
		xua_msg_add_data(xua, M3UA_IEI_INFO_STRING,
				 strlen(info_string)+1,
				 (const uint8_t *) info_string);
	}
	return xua;
}

/* 3.4.2 Destination Available (DAVA) */
static struct xua_msg *m3ua_encode_dava(const uint32_t *rctx, unsigned int num_rctx,
					const uint32_t *aff_pc, unsigned int num_aff_pc,
					const char *info_string)
{
	/* encoding is exactly identical to DUNA */
	struct xua_msg *xua = m3ua_encode_duna(rctx, num_rctx, aff_pc, num_aff_pc, info_string);
	if (xua)
		xua->hdr.msg_type = M3UA_SNM_DAVA;
	return xua;
}

/* 3.4.3 Destination Available (DAUD) */
static struct xua_msg *m3ua_encode_daud(const uint32_t *rctx, unsigned int num_rctx,
					const uint32_t *aff_pc, unsigned int num_aff_pc,
					const char *info_string)
{
	/* encoding is exactly identical to DUNA */
	struct xua_msg *xua = m3ua_encode_duna(rctx, num_rctx, aff_pc, num_aff_pc, info_string);
	if (xua)
		xua->hdr.msg_type = M3UA_SNM_DAUD;
	return xua;
}

/* 3.4.5 Destination User Part Unavailable (DUPU) */
static struct xua_msg *m3ua_encode_dupu(const uint32_t *rctx, unsigned int num_rctx,
					uint32_t dpc, uint16_t user, uint16_t cause,
					const char *info_string)
{
	struct xua_msg *xua = xua_msg_alloc();
	uint32_t user_cause = (cause << 16) | user;

	xua->hdr = XUA_HDR(M3UA_MSGC_SNM, M3UA_SNM_DUPU);
	xua->hdr.version = M3UA_VERSION;
	if (rctx && num_rctx)
		xua_msg_add_data(xua, M3UA_IEI_ROUTE_CTX, num_rctx * sizeof(*rctx), (const uint8_t *)rctx);

	xua_msg_add_u32(xua, M3UA_IEI_AFFECTED_PC, dpc);
	xua_msg_add_u32(xua, M3UA_IEI_USER_CAUSE, user_cause);

	if (info_string) {
		xua_msg_add_data(xua, M3UA_IEI_INFO_STRING,
				 strlen(info_string)+1,
				 (const uint8_t *) info_string);
	}
	return xua;
}

/*! Transmit SSNM DUNA/DAVA message indicating [un]availability of certain point code[s]
 *  \param[in] asp ASP through which to transmit message. Must be ACTIVE.
 *  \param[in] rctx array of Routing Contexts in network byte order.
 *  \param[in] num_rctx number of rctx
 *  \param[in] aff_pc array of 'Affected Point Code' in network byte order.
 *  \param[in] num_aff_pc number of aff_pc
 *  \param[in] info_string optional information string (can be NULL).
 *  \param[in] available are aff_pc now available (true) or unavailable (false) */
void m3ua_tx_snm_available(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
			   const uint32_t *aff_pc, unsigned int num_aff_pc,
			   const char *info_string, bool available)
{
	struct xua_msg *xua;

	if (available)
		xua = m3ua_encode_dava(rctx, num_rctx, aff_pc, num_aff_pc, info_string);
	else
		xua = m3ua_encode_duna(rctx, num_rctx, aff_pc, num_aff_pc, info_string);

	m3ua_tx_xua_asp(asp, xua);
}

/*! Transmit SSNM SCON message indicating congestion
 *  \param[in] asp ASP through which to transmit message. Must be ACTIVE.
 *  \param[in] rctx array of Routing Contexts in network byte order.
 *  \param[in] num_rctx number of rctx
 *  \param[in] aff_pc array of 'Affected Point Code' in network byte order.
 *  \param[in] num_aff_pc number of aff_pc
 *  \param[in] concerned_dpc optional concerned DPC (can be NULL)
 *  \param[in] cong_level optional congestion level (can be NULL)
 *  \param[in] info_string optional information string (can be NULL). */
void m3ua_tx_snm_congestion(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
			    const uint32_t *aff_pc, unsigned int num_aff_pc,
			    const uint32_t *concerned_dpc, const uint8_t *cong_level,
			    const char *info_string)
{
	struct xua_msg *xua = xua_msg_alloc();

	xua->hdr = XUA_HDR(M3UA_MSGC_SNM, M3UA_SNM_SCON);
	xua->hdr.version = M3UA_VERSION;
	if (rctx && num_rctx)
		xua_msg_add_data(xua, M3UA_IEI_ROUTE_CTX, num_rctx * sizeof(*rctx), (const uint8_t *)rctx);

	xua_msg_add_data(xua, M3UA_IEI_AFFECTED_PC, num_aff_pc * sizeof(*aff_pc), (const uint8_t *) aff_pc);

	if (concerned_dpc)
		xua_msg_add_u32(xua, M3UA_IEI_CONC_DEST, *concerned_dpc & 0xffffff);
	if (cong_level)
		xua_msg_add_u32(xua, M3UA_IEI_CONG_IND, *cong_level & 0xff);
	if (info_string)
		xua_msg_add_data(xua, M3UA_IEI_INFO_STRING, strlen(info_string)+1, (const uint8_t *) info_string);

	m3ua_tx_xua_asp(asp, xua);
}

/*! Transmit SSNM DAUD message requesting [un]availability status of certain point code[s]
 *  \param[in] asp ASP through which to transmit message. Must be ACTIVE.
 *  \param[in] rctx array of Routing Contexts in network byte order.
 *  \param[in] num_rctx number of rctx
 *  \param[in] aff_pc array of 'Affected Point Code' in network byte order.
 *  \param[in] num_aff_pc number of aff_pc
 *  \param[in] info_string optional information string (can be NULL).
 */
void m3ua_tx_snm_daud(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
		      const uint32_t *aff_pc, unsigned int num_aff_pc, const char *info_string)
{
	struct xua_msg *xua = m3ua_encode_daud(rctx, num_rctx, aff_pc, num_aff_pc, info_string);
	m3ua_tx_xua_asp(asp, xua);
}

/*! Transmit SSNM DUPU message indicating user unavailability.
 *  \param[in] asp ASP through which to transmit message. Must be ACTIVE.
 *  \param[in] rctx array of Routing Contexts in network byte order.
 *  \param[in] num_rctx number of rctx
 *  \param[in] dpc affected point code
 *  \param[in] user the user (SI) that is unavailable
 *  \param[in] cause the cause of the user unavailability
 *  \param[in] info_string optional information string (can be NULL). */
void m3ua_tx_dupu(struct osmo_ss7_asp *asp, const uint32_t *rctx, unsigned int num_rctx,
		  uint32_t dpc, uint16_t user, uint16_t cause, const char *info_str)
{
	struct xua_msg *xua = m3ua_encode_dupu(rctx, num_rctx, dpc, user, cause, info_str);
	m3ua_tx_xua_asp(asp, xua);
}

/* received SNM message on ASP side
 * xua is owned by parent call m3ua_rx_snm() */
static int m3ua_rx_snm_asp(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct osmo_ss7_as *as = NULL;
	struct xua_msg_part *rctx_ie = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
	int rc;

	rc = xua_find_as_for_asp(&as, asp, rctx_ie);
	if (rc)
		return rc;

	/* report those up the stack so both other ASPs and local SCCP users can be notified */
	switch (xua->hdr.msg_type) {
	case M3UA_SNM_DUNA:
		xua_snm_rx_duna(asp, as, xua);
		break;
	case M3UA_SNM_DAVA:
		xua_snm_rx_dava(asp, as, xua);
		break;
	case M3UA_SNM_DUPU:
		xua_snm_rx_dupu(asp, as, xua);
		break;
	case M3UA_SNM_SCON:
		xua_snm_rx_scon(asp, as, xua);
		break;
	case M3UA_SNM_DRST:
		LOGPASP(asp, DLM3UA, LOGL_NOTICE, "Received unsupported M3UA SNM message type %u\n",
			xua->hdr.msg_type);
		/* silently ignore those to not confuse the sender */
		break;
	case M3UA_SNM_DAUD:
		/* RFC states only permitted in ASP->SG direction, not reverse. But some
		 * equipment still sends it to us as ASP ?!? */
		if (asp->cfg.quirks & OSMO_SS7_ASP_QUIRK_DAUD_IN_ASP) {
			LOGPASP(asp, DLM3UA, LOGL_NOTICE, "quirk daud_in_asp active: Accepting DAUD "
				"despite being in ASP role\n");
			xua_snm_rx_daud(asp, xua);
		} else {
			LOGPASP(asp, DLM3UA, LOGL_ERROR, "DAUD not permitted in ASP role\n");
			rc = M3UA_ERR_UNSUPP_MSG_TYPE;
		}
		break;
	default:
		rc = M3UA_ERR_UNSUPP_MSG_TYPE;
	}

	return rc;
}

/* received SNM message on SG side
 * xua is owned by parent call m3ua_rx_snm() */
static int m3ua_rx_snm_sg(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct osmo_ss7_as *as = NULL;
	struct xua_msg_part *rctx_ie;
	int rc = 0;

	switch (xua->hdr.msg_type) {
	case M3UA_SNM_SCON:
		/* RFC4666 1.4.6: "The M3UA layer at an ASP or IPSP MAY indicate local congestion
		 * to an M3UA peer with an SCON message."
		 * RFC4666 3.4.4: The SCON message MAY also be sent from the M3UA layer of an ASP
		 * to an M3UA peer, indicating that the congestion level of the M3UA layer or the
		 * ASP has changed.*/
		rctx_ie = xua_msg_find_tag(xua, M3UA_IEI_ROUTE_CTX);
		rc = xua_find_as_for_asp(&as, asp, rctx_ie);
		if (rc)
			return rc;
		xua_snm_rx_scon(asp, as, xua);
		break;
	case M3UA_SNM_DAUD:
		/* Audit: ASP inquires about availability of Point Codes */
		xua_snm_rx_daud(asp, xua);
		break;
	default:
		return M3UA_ERR_UNSUPP_MSG_TYPE;
	}

	return rc;
}

/* received SNM message
 * This function takes ownership of xua msg passed to it. */
static int m3ua_rx_snm(struct osmo_ss7_asp *asp, struct xua_msg *xua)
{
	struct xua_msg_part *na_ie = xua_msg_find_tag(xua, M3UA_IEI_NET_APPEAR);
	int rc;

	/* SNM only permitted in ACTIVE state */
	if (asp->fi->state != XUA_ASP_S_ACTIVE) {
		if (asp->fi->state == XUA_ASP_S_INACTIVE &&
		    asp->cfg.quirks & OSMO_SS7_ASP_QUIRK_SNM_INACTIVE) {
			LOGPASP(asp, DLM3UA, LOGL_NOTICE, "quirk snm_inactive active: "
				"Accepting SNM in state %s\n", osmo_fsm_inst_state_name(asp->fi));
		} else {
			LOGPASP(asp, DLM3UA, LOGL_ERROR, "Rx M3UA SNM not permitted "
				"while ASP in state %s\n", osmo_fsm_inst_state_name(asp->fi));
			rc = M3UA_ERR_UNEXPECTED_MSG;
			goto ret_free;
		}
	}

	/* Reject unsupported Network Appearance IE. */
	if (na_ie) {
		uint32_t na = xua_msg_part_get_u32(na_ie);

		LOGPASP(asp, DLM3UA, LOGL_NOTICE,
			"Unsupported 'Network Appearance' IE '0x%08x' in message type '%s', sending 'Error'.\n",
			na, get_value_string(m3ua_xfer_msgt_names, xua->hdr.msg_type));
		if (na_ie->len != 4)
			rc = M3UA_ERR_PARAM_FIELD_ERR;
		else
			rc = M3UA_ERR_INVAL_NET_APPEAR;
		goto ret_free;
	}

	switch (asp->cfg.role) {
	case OSMO_SS7_ASP_ROLE_SG:
		rc = m3ua_rx_snm_sg(asp, xua);
		break;
	case OSMO_SS7_ASP_ROLE_ASP:
		rc = m3ua_rx_snm_asp(asp, xua);
		break;
	default:
		rc = M3UA_ERR_UNSUPP_MSG_CLASS;
		break;
	}

ret_free:
	xua_msg_free(xua);
	return rc;
}
