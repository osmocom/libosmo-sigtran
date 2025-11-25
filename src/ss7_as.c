/* Core SS7 AS Handling */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/mtp_sap.h>

#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"
#include "xua_as_fsm.h"
#include "xua_asp_fsm.h"
#include "xua_msg.h"

/***********************************************************************
 * SS7 Application Server
 ***********************************************************************/

struct value_string osmo_ss7_as_traffic_mode_vals[] = {
	{ OSMO_SS7_AS_TMOD_BCAST,	"broadcast" },
	{ OSMO_SS7_AS_TMOD_LOADSHARE,	"loadshare" },
	{ OSMO_SS7_AS_TMOD_ROUNDROBIN,	"roundrobin" },
	{ OSMO_SS7_AS_TMOD_OVERRIDE,	"override" },
	{ 0, NULL }
};

#define SS7_AS_CTR_RX_MSU_SLS_STR "Number of MSU received on SLS "
#define SS7_AS_CTR_TX_MSU_SLS_STR "Number of MSU transmitted on SLS "
static const struct rate_ctr_desc ss7_as_rcd[] = {
	[SS7_AS_CTR_RX_MSU_DISCARD] = {	"rx:msu:discard",	"Total number of incoming MSU discarded" },
	[SS7_AS_CTR_RX_MSU_TOTAL] = {	"rx:msu:total",		"Total number of MSU received" },
	[SS7_AS_CTR_RX_MSU_SLS_0] = {	"rx:msu:sls:0",		SS7_AS_CTR_RX_MSU_SLS_STR "0" },
	[SS7_AS_CTR_RX_MSU_SLS_1] = {	"rx:msu:sls:1",		SS7_AS_CTR_RX_MSU_SLS_STR "1" },
	[SS7_AS_CTR_RX_MSU_SLS_2] = {	"rx:msu:sls:2",		SS7_AS_CTR_RX_MSU_SLS_STR "2" },
	[SS7_AS_CTR_RX_MSU_SLS_3] = {	"rx:msu:sls:3",		SS7_AS_CTR_RX_MSU_SLS_STR "3" },
	[SS7_AS_CTR_RX_MSU_SLS_4] = {	"rx:msu:sls:4",		SS7_AS_CTR_RX_MSU_SLS_STR "4" },
	[SS7_AS_CTR_RX_MSU_SLS_5] = {	"rx:msu:sls:5",		SS7_AS_CTR_RX_MSU_SLS_STR "5" },
	[SS7_AS_CTR_RX_MSU_SLS_6] = {	"rx:msu:sls:6",		SS7_AS_CTR_RX_MSU_SLS_STR "6" },
	[SS7_AS_CTR_RX_MSU_SLS_7] = {	"rx:msu:sls:7",		SS7_AS_CTR_RX_MSU_SLS_STR "7" },
	[SS7_AS_CTR_RX_MSU_SLS_8] = {	"rx:msu:sls:8",		SS7_AS_CTR_RX_MSU_SLS_STR "8" },
	[SS7_AS_CTR_RX_MSU_SLS_9] = {	"rx:msu:sls:9",		SS7_AS_CTR_RX_MSU_SLS_STR "9" },
	[SS7_AS_CTR_RX_MSU_SLS_10] = {	"rx:msu:sls:10",	SS7_AS_CTR_RX_MSU_SLS_STR "10" },
	[SS7_AS_CTR_RX_MSU_SLS_11] = {	"rx:msu:sls:11",	SS7_AS_CTR_RX_MSU_SLS_STR "11" },
	[SS7_AS_CTR_RX_MSU_SLS_12] = {	"rx:msu:sls:12",	SS7_AS_CTR_RX_MSU_SLS_STR "12" },
	[SS7_AS_CTR_RX_MSU_SLS_13] = {	"rx:msu:sls:13",	SS7_AS_CTR_RX_MSU_SLS_STR "13" },
	[SS7_AS_CTR_RX_MSU_SLS_14] = {	"rx:msu:sls:14",	SS7_AS_CTR_RX_MSU_SLS_STR "14" },
	[SS7_AS_CTR_RX_MSU_SLS_15] = {	"rx:msu:sls:15",	SS7_AS_CTR_RX_MSU_SLS_STR "15" },
	[SS7_AS_CTR_TX_MSU_TOTAL] = {	"tx:msu:total",		"Total number of MSU transmitted" },
	[SS7_AS_CTR_TX_MSU_SLS_0] = {	"tx:msu:sls:0",		SS7_AS_CTR_TX_MSU_SLS_STR "0" },
	[SS7_AS_CTR_TX_MSU_SLS_1] = {	"tx:msu:sls:1",		SS7_AS_CTR_TX_MSU_SLS_STR "1" },
	[SS7_AS_CTR_TX_MSU_SLS_2] = {	"tx:msu:sls:2",		SS7_AS_CTR_TX_MSU_SLS_STR "2" },
	[SS7_AS_CTR_TX_MSU_SLS_3] = {	"tx:msu:sls:3",		SS7_AS_CTR_TX_MSU_SLS_STR "3" },
	[SS7_AS_CTR_TX_MSU_SLS_4] = {	"tx:msu:sls:4",		SS7_AS_CTR_TX_MSU_SLS_STR "4" },
	[SS7_AS_CTR_TX_MSU_SLS_5] = {	"tx:msu:sls:5",		SS7_AS_CTR_TX_MSU_SLS_STR "5" },
	[SS7_AS_CTR_TX_MSU_SLS_6] = {	"tx:msu:sls:6",		SS7_AS_CTR_TX_MSU_SLS_STR "6" },
	[SS7_AS_CTR_TX_MSU_SLS_7] = {	"tx:msu:sls:7",		SS7_AS_CTR_TX_MSU_SLS_STR "7" },
	[SS7_AS_CTR_TX_MSU_SLS_8] = {	"tx:msu:sls:8",		SS7_AS_CTR_TX_MSU_SLS_STR "8" },
	[SS7_AS_CTR_TX_MSU_SLS_9] = {	"tx:msu:sls:9",		SS7_AS_CTR_TX_MSU_SLS_STR "9" },
	[SS7_AS_CTR_TX_MSU_SLS_10] = {	"tx:msu:sls:10",	SS7_AS_CTR_TX_MSU_SLS_STR "10" },
	[SS7_AS_CTR_TX_MSU_SLS_11] = {	"tx:msu:sls:11",	SS7_AS_CTR_TX_MSU_SLS_STR "11" },
	[SS7_AS_CTR_TX_MSU_SLS_12] = {	"tx:msu:sls:12",	SS7_AS_CTR_TX_MSU_SLS_STR "12" },
	[SS7_AS_CTR_TX_MSU_SLS_13] = {	"tx:msu:sls:13",	SS7_AS_CTR_TX_MSU_SLS_STR "13" },
	[SS7_AS_CTR_TX_MSU_SLS_14] = {	"tx:msu:sls:14",	SS7_AS_CTR_TX_MSU_SLS_STR "14" },
	[SS7_AS_CTR_TX_MSU_SLS_15] = {	"tx:msu:sls:15",	SS7_AS_CTR_TX_MSU_SLS_STR "15" },
};

static const struct rate_ctr_group_desc ss7_as_rcgd = {
	.group_name_prefix = "sigtran_as",
	.group_description = "SIGTRAN Application Server",
	.num_ctr = ARRAY_SIZE(ss7_as_rcd),
	.ctr_desc = ss7_as_rcd,
};
static unsigned int g_ss7_as_rcg_idx;

/*! \brief Allocate an Application Server
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of Application Server
 *  \param[in] proto Protocol of Application Server
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *ss7_as_alloc(struct osmo_ss7_instance *inst, const char *name,
				 enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_as *as;

	as = talloc_zero(inst, struct osmo_ss7_as);
	if (!as)
		return NULL;
	as->ctrg = rate_ctr_group_alloc(as, &ss7_as_rcgd, g_ss7_as_rcg_idx++);
	if (!as->ctrg) {
		talloc_free(as);
		return NULL;
	}
	rate_ctr_group_set_name(as->ctrg, name);
	as->inst = inst;
	as->cfg.name = talloc_strdup(as, name);
	as->cfg.proto = proto;
	as->cfg.mode = OSMO_SS7_AS_TMOD_OVERRIDE;
	as->cfg.recovery_timeout_msec = 2000;
	as->cfg.routing_key.l_rk_id = ss7_find_free_l_rk_id(inst);

	/* Pick 1st ASP upon 1st roundrobin assignment: */
	as->cfg.last_asp_idx_assigned = ARRAY_SIZE(as->cfg.asps) - 1;

	as->fi = xua_as_fsm_start(as, LOGL_DEBUG);
	llist_add_tail(&as->list, &inst->as_list);

	return as;
}

/*! \brief Get asp_protocol configuration of a given AS
 *  \param[in] as Application Server in which to look for \ref asp_protocol
 *  \returns The asp_protocol this AS is configured with */
enum osmo_ss7_asp_protocol osmo_ss7_as_get_asp_protocol(const struct osmo_ss7_as *as)
{
	return as->cfg.proto;
}

/*! \brief Add given ASP to given AS
 *  \param[in] as Application Server to which \ref asp is added
 *  \param[in] asp Application Server Process to be added to \ref as
 *  \returns 0 on success; negative in case of error */
int ss7_as_add_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp)
{
	unsigned int i;
	OSMO_ASSERT(asp);

	if (osmo_ss7_as_has_asp(as, asp))
		return 0;

	LOGPAS(as, DLSS7, LOGL_INFO, "Adding ASP %s to AS\n", asp->cfg.name);

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (!as->cfg.asps[i]) {
			as->cfg.asps[i] = asp;
			if (asp->fi)
				osmo_fsm_inst_dispatch(asp->fi, XUA_ASP_E_AS_ASSIGNED, as);
			return 0;
		}
	}

	LOGPAS(as, DLSS7, LOGL_ERROR, "Failed adding ASP %s to AS, ASP table is full!\n", asp->cfg.name);
	return -ENOSPC;
}

/*! \brief Add given ASP to given AS
 *  \param[in] as Application Server to which \ref asp is added
 *  \param[in] asp_name Name of Application Server Process to be added to \ref as
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_as_add_asp(struct osmo_ss7_as *as, const char *asp_name)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(as->inst, asp_name);
	if (!asp)
		return -ENODEV;

	return ss7_as_add_asp(as, asp);
}

/*! \brief Delete given ASP from given AS
 *  \param[in] as Application Server from which \ref asp is deleted
 *  \param[in] asp Application Server Process to delete from \ref as
 *  \returns 0 on success; negative in case of error
 *
 * \ref as may be freed during the function call. */
int ss7_as_del_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp)
{
	unsigned int i;
	bool found = false;

	LOGPAS(as, DLSS7, LOGL_INFO, "Removing ASP %s from AS\n", asp->cfg.name);

	/* Remove route from AS-eSLS table: */
	for (unsigned int i = 0; i < ARRAY_SIZE(as->aesls_table); i++) {
		if (as->aesls_table[i].normal_asp == asp)
			as->aesls_table[i].normal_asp = NULL;
		if (as->aesls_table[i].alt_asp == asp)
			as->aesls_table[i].alt_asp = NULL;
	}

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] == asp) {
			as->cfg.asps[i] = NULL;
			found = true;
			break;
		}
	}

	/* RKM-dynamically allocated AS: If there are no other ASPs, destroy the AS.
	 * RFC 4666 4.4.2: "If a Deregistration results in no more ASPs in an
	 * Application Server, an SG MAY delete the Routing Key data."
	 */
	if (as->rkm_dyn_allocated && osmo_ss7_as_count_asp(as) == 0)
		osmo_ss7_as_destroy(as);


	return found ? 0 : -EINVAL;
}

/*! \brief Delete given ASP from given AS
 *  \param[in] as Application Server from which \ref asp is deleted
 *  \param[in] asp_name Name of the Application Server Process to delete from \ref as
 *  \returns 0 on success; negative in case of error */
int osmo_ss7_as_del_asp(struct osmo_ss7_as *as, const char *asp_name)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(as->inst, asp_name);
	if (!asp)
		return -ENODEV;

	return ss7_as_del_asp(as, asp);
}

/*! \brief Destroy given Application Server
 *  \param[in] as Application Server to destroy */
void osmo_ss7_as_destroy(struct osmo_ss7_as *as)
{
	OSMO_ASSERT(ss7_initialized);
	LOGPAS(as, DLSS7, LOGL_INFO, "Destroying AS\n");

	if (as->fi)
		osmo_fsm_inst_term(as->fi, OSMO_FSM_TERM_REQUEST, NULL);

	/* find any routes pointing to this AS and remove them */
	ss7_route_table_del_routes_by_as(as->inst->rtable_system, as);

	as->inst = NULL;
	llist_del(&as->list);
	rate_ctr_group_free(as->ctrg);
	talloc_free(as);
}

/*! \brief Determine if given AS contains ASP
 *  \param[in] as Application Server in which to look for \ref asp
 *  \param[in] asp Application Server Process to look for in \ref as
 *  \returns true in case \ref asp is part of \ref as; false otherwise */
bool osmo_ss7_as_has_asp(const struct osmo_ss7_as *as,
			 const struct osmo_ss7_asp *asp)
{
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] == asp)
			return true;
	}
	return false;
}

/*! Determine amount of ASPs associated to an AS.
 *  \param[in] as Application Server.
 *  \returns number of ASPs associated to as */
unsigned int osmo_ss7_as_count_asp(const struct osmo_ss7_as *as)
{
	unsigned int i;
	unsigned int cnt = 0;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i])
			cnt++;
	}
	return cnt;
}

/* Determine which role (SG/ASP/IPSP) we operate in.
 * return enum osmo_ss7_asp_role on success, negative otherwise. */
int ss7_as_get_local_role(const struct osmo_ss7_as *as)
{
	unsigned int i;

	/* this is a bit tricky. "osmo_ss7_as" has no configuration of a role,
	 * only the ASPs have.  As they all must be of the same role, let's simply
	 * find the first one and return its role */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];

		if (!asp)
			continue;

		return asp->cfg.role;
	}
	/* No ASPs associated to this AS yet? */
	return -1;
}

/*! Determine if given AS is in the active state.
 *  \param[in] as Application Server.
 *  \returns true in case as is active; false otherwise. */
bool osmo_ss7_as_active(const struct osmo_ss7_as *as)
{
	if (!as->fi)
		return false;
	return as->fi->state == XUA_AS_S_ACTIVE;
}

/*! Determine if given AS is in the down state.
 *  \param[in] as Application Server.
 *  \returns true in case as is down; false otherwise. */
bool osmo_ss7_as_down(const struct osmo_ss7_as *as)
{
	OSMO_ASSERT(as);

	if (!as->fi)
		return true;
	return as->fi->state == XUA_AS_S_DOWN;
}

static struct osmo_ss7_asp *ss7_as_select_asp_override(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;

	/* FIXME: proper selection of the ASP based on the SLS! */
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (asp && osmo_ss7_asp_active(asp))
			break;
	}
	return asp;
}

/* Pick an ASP serving AS in a round-robin fashion.
 * During Loadshare eSLS table generation we want to pick Normal ASP
 * in a distributed fashion, regardless of active state (Alternative ASP will
 * be picked up temporarily later on if needed).
 * Moreover, we must use a different index from the "active"
 * ss7_as_select_asp_roundrobin() below, in order to avoid tainting the
 * distribution. */
static struct osmo_ss7_asp *ss7_as_assign_asp_roundrobin(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;
	unsigned int first_idx;

	first_idx = (as->cfg.last_asp_idx_assigned + 1) % ARRAY_SIZE(as->cfg.asps);
	i = first_idx;
	do {
		asp = as->cfg.asps[i];
		if (asp)
			break;
		i = (i + 1) % ARRAY_SIZE(as->cfg.asps);
	} while (i != first_idx);
	as->cfg.last_asp_idx_assigned = i;

	return asp;
}

/* Pick an active ASP serving AS in a round-robin fashion, to send a message to. */
static struct osmo_ss7_asp *ss7_as_select_asp_roundrobin(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	unsigned int i;
	unsigned int first_idx;

	first_idx = (as->cfg.last_asp_idx_sent + 1) % ARRAY_SIZE(as->cfg.asps);
	i = first_idx;
	do {
		asp = as->cfg.asps[i];
		if (asp && osmo_ss7_asp_active(asp))
			break;
		i = (i + 1) % ARRAY_SIZE(as->cfg.asps);
	} while (i != first_idx);
	as->cfg.last_asp_idx_sent = i;

	return asp;
}

/* Reset loadshare bindings table. It will be filled in as needed.
 * This is useful for instance when user changes the ASP set inside an AS, or
 * changes the way the binding seed (eSLS) is calculated. */
void ss7_as_loadshare_binding_table_reset(struct osmo_ss7_as *as)
{
	memset(&as->aesls_table[0], 0, sizeof(as->aesls_table));
	as->cfg.last_asp_idx_assigned = ARRAY_SIZE(as->cfg.asps) - 1;
}

static as_ext_sls_t osmo_ss7_instance_calc_itu_as_ext_sls(const struct osmo_ss7_as *as, uint32_t opc, uint8_t sls)
{
	uint16_t opc12;
	uint8_t opc3;
	as_ext_sls_t as_ext_sls;

	if (as->cfg.loadshare.opc_sls) {
		/* Take 12 bits from OPC according to config: */
		opc12 = (uint16_t)((opc >> as->cfg.loadshare.opc_shift) & 0x3fff);

		/* Derivate 3-bit value from 12-bit value: */
		opc3 = ((opc12 >> 9) & 0x07) ^
		       ((opc12 >> 6) & 0x07) ^
		       ((opc12 >> 3) & 0x07) ^
		       (opc12 & 0x07);
		opc3 &= 0x07;

		/* Generate 7 bit AS-extended-SLS: 3-bit OPC + 4 bit SLS: */
		as_ext_sls = (opc3 << 4) | ((sls) & 0x0f);
		OSMO_ASSERT(as_ext_sls < NUM_AS_EXT_SLS);
	} else {
		as_ext_sls = sls;
	}

	/* Pick extended-SLS bits according to config: */
	as_ext_sls = as_ext_sls >> as->cfg.loadshare.sls_shift;
	return as_ext_sls;
}

/* ITU Q.704 4.2.1: "current signalling link". Pick available already selected ASP */
static struct osmo_ss7_asp *current_asp(const struct osmo_ss7_as *as, const struct osmo_ss7_as_esls_entry *aeslse)
{
	if (aeslse->normal_asp && osmo_ss7_asp_active(aeslse->normal_asp))
		return aeslse->normal_asp;
	if (aeslse->alt_asp && osmo_ss7_asp_active(aeslse->alt_asp))
		return aeslse->alt_asp;
	return NULL;
}

static struct osmo_ss7_asp *ss7_as_select_asp_loadshare(struct osmo_ss7_as *as, const struct osmo_mtp_transfer_param *mtp)
{
	as_ext_sls_t as_ext_sls;
	struct osmo_ss7_asp *asp;

	as_ext_sls = osmo_ss7_instance_calc_itu_as_ext_sls(as, mtp->opc, mtp->sls);
	struct osmo_ss7_as_esls_entry *aeslse = &as->aesls_table[as_ext_sls];

	/* First check if we have a cached route for this ESLS */
	asp = current_asp(as, aeslse);
	if (asp) {
		if (asp == aeslse->normal_asp) {
			/* We can transmit over normal ASP.
			 * Clean up alternative ASP since it's not needed anymore */
			if (aeslse->alt_asp) {
				LOGPAS(as, DLSS7, LOGL_NOTICE, "Tx Loadshare: OPC=%u=%s,SLS=%u -> eSLS=%u: "
				       "Normal ASP '%s' became available, drop use of Alternative ASP '%s'\n",
				       mtp->opc, osmo_ss7_pointcode_print(as->inst, mtp->opc),
				       mtp->sls, as_ext_sls, asp->cfg.name, aeslse->alt_asp->cfg.name);
				aeslse->alt_asp = NULL;
			}
			LOGPAS(as, DLSS7, LOGL_DEBUG, "Tx Loadshare: OPC=%u=%s,SLS=%u -> eSLS=%u: use Normal ASP '%s'\n",
			       mtp->opc, osmo_ss7_pointcode_print(as->inst, mtp->opc),
			       mtp->sls, as_ext_sls, asp->cfg.name);
			return asp;
		}
		/* We can transmit over alternative ASP: */
		LOGPAS(as, DLSS7, LOGL_INFO, "Tx Loadshare: OPC=%u=%s,SLS=%u -> eSLS=%u: use Alternative ASP '%s'\n",
		       mtp->opc, osmo_ss7_pointcode_print(as->inst, mtp->opc),
		       mtp->sls, as_ext_sls, asp->cfg.name);
		return asp;
	}

	/* No current ASP available, try to find a new current ASP: */

	/* No normal route assigned yet: */
	if (!aeslse->normal_asp) {
		/* Establish a Normal ASP, regardless of active state: */
		asp = ss7_as_assign_asp_roundrobin(as);
		/* No ASP found for Normal ASP, regardless of state... */
		if (!asp)
			return NULL;
		aeslse->normal_asp = asp;
		LOGPAS(as, DLSS7, LOGL_DEBUG, "Tx Loadshare: OPC=%u=%s,SLS=%u -> eSLS=%u: "
		       "picked Normal ASP '%s' round-robin style\n",
		       mtp->opc, osmo_ss7_pointcode_print(as->inst, mtp->opc),
		       mtp->sls, as_ext_sls, aeslse->normal_asp->cfg.name);
		if (osmo_ss7_asp_active(aeslse->normal_asp)) {
			/* Found active Normal Route: */
			return aeslse->normal_asp;
		}
		/* Normal ASP was assigned, but it is not active, fall-through
		 * below to attempt transmission through Alternative ASP: */
	}

	/* Normal ASP unavailable and no alternative ASP (or unavailable too).
	 * start ITU Q.704 section 7 "forced rerouting" procedure: */
	asp = ss7_as_select_asp_roundrobin(as);
	if (asp) {
		aeslse->alt_asp = asp;
		LOGPAS(as, DLSS7, LOGL_NOTICE, "Tx Loadshare: OPC=%u=%s,SLS=%u -> eSLS=%u: "
			"Normal ASP '%s' unavailable, picked Alternative ASP '%s' round-robin style\n",
			 mtp->opc, osmo_ss7_pointcode_print(as->inst, mtp->opc),
			 mtp->sls, as_ext_sls, aeslse->normal_asp->cfg.name, asp->cfg.name);
	}
	return asp;
}

/* returns NULL if multiple ASPs would need to be selected. */
static struct osmo_ss7_asp *ss7_as_select_asp_broadcast(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp;
	struct osmo_ss7_asp *asp_found = NULL;

	for (unsigned int i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		asp = as->cfg.asps[i];
		if (!asp || !osmo_ss7_asp_active(asp))
			continue;
		if (asp_found) /* >1 ASPs selected, early return */
			return NULL;
		asp_found = asp;
	}
	return asp_found;
}

/*! Select an AS to transmit a message, according to AS configuration and ASP availability.
 *  \param[in] as Application Server.
 *  \returns asp to send the message to, NULL if no possible asp found
 *
 *  This function returns NULL too if multiple ASPs would be selected, ie. AS is
 *  configured in broadcast mode and more than one ASP is configured.
 */
struct osmo_ss7_asp *ss7_as_select_asp(struct osmo_ss7_as *as, const struct xua_msg *xua)
{
	const struct osmo_mtp_transfer_param *mtp = &xua->mtp;
	struct osmo_ss7_asp *asp = NULL;

	switch (as->cfg.mode) {
	case OSMO_SS7_AS_TMOD_OVERRIDE:
		asp = ss7_as_select_asp_override(as);
		break;
	case OSMO_SS7_AS_TMOD_LOADSHARE:
		asp = ss7_as_select_asp_loadshare(as, mtp);
		break;
	case OSMO_SS7_AS_TMOD_ROUNDROBIN:
		asp = ss7_as_select_asp_roundrobin(as);
		break;
	case OSMO_SS7_AS_TMOD_BCAST:
		return ss7_as_select_asp_broadcast(as);
	case _NUM_OSMO_SS7_ASP_TMOD:
		OSMO_ASSERT(false);
	}

	if (!asp) {
		LOGPFSM(as->fi, "No selectable ASP in AS\n");
		return NULL;
	}
	return asp;
}
/*! Select an AS to transmit a message, according to AS configuration and ASP availability.
 *  \param[in] as Application Server.
 *  \returns asp to send the message to, NULL if no possible asp found
 *
 *  This function returns NULL too if multiple ASPs would be selected, ie. AS is
 *  configured in broadcast mode and more than one ASP is configured.
 */
struct osmo_ss7_asp *osmo_ss7_as_select_asp(struct osmo_ss7_as *as)
{
	struct osmo_ss7_asp *asp = NULL;
	struct osmo_mtp_transfer_param mtp;

	switch (as->cfg.mode) {
	case OSMO_SS7_AS_TMOD_OVERRIDE:
		asp = ss7_as_select_asp_override(as);
		break;
	case OSMO_SS7_AS_TMOD_LOADSHARE:
		/* We don't have OPC and SLS information in this API (which is
		actually only used to route IPA msgs nowadays by osmo-bsc, so we
		don't care. Use hardcoded value to provide some fallback for this scenario: */
		mtp = (struct osmo_mtp_transfer_param){0};
		asp = ss7_as_select_asp_loadshare(as, &mtp);
		break;
	case OSMO_SS7_AS_TMOD_ROUNDROBIN:
		asp = ss7_as_select_asp_roundrobin(as);
		break;
	case OSMO_SS7_AS_TMOD_BCAST:
		return ss7_as_select_asp_broadcast(as);
	case _NUM_OSMO_SS7_ASP_TMOD:
		OSMO_ASSERT(false);
	}

	if (!asp) {
		LOGPFSM(as->fi, "No selectable ASP in AS\n");
		return NULL;
	}
	return asp;
}

bool osmo_ss7_as_tmode_compatible_xua(struct osmo_ss7_as *as, uint32_t m3ua_tmt)
{
	if (!as->cfg.mode_set_by_vty && !as->cfg.mode_set_by_peer)
		return true;

	switch (m3ua_tmt) {
	case M3UA_TMOD_OVERRIDE:
		if (as->cfg.mode == OSMO_SS7_AS_TMOD_OVERRIDE)
			return true;
		break;
	case M3UA_TMOD_LOADSHARE:
		if (as->cfg.mode == OSMO_SS7_AS_TMOD_LOADSHARE ||
		    as->cfg.mode == OSMO_SS7_AS_TMOD_ROUNDROBIN)
			return true;
		break;
	case M3UA_TMOD_BCAST:
		if (as->cfg.mode == OSMO_SS7_AS_TMOD_BCAST)
			return true;
		break;
	default:
		break;
	}
	return false;

}
