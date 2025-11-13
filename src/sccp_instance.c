/* SCCP Instance related routines */

/* (C) 2017 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * based on my 2011 Erlang implementation osmo_ss7/src/sua_sccp_conv.erl
 *
 * References: ITU-T Q.713 and IETF RFC 3868
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

#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/sccp_helpers.h>
#include <osmocom/sccp/sccp_types.h>

#include "sccp_connection.h"
#include "sccp_internal.h"
#include "sccp_instance.h"
#include "sccp_user.h"
#include "xua_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"
#include "ss7_xua_srv.h"

/***********************************************************************
 * Timer Handling
 ***********************************************************************/

/* Mostly pasted from Appendix C.4 of ITU-T Q.714 (05/2001) -- some of their descriptions are quite
 * unintelligible out of context, for which we have our own description here. */
const struct osmo_tdef osmo_sccp_timer_defaults[OSMO_SCCP_TIMERS_LEN] = {
	{ .T = OSMO_SCCP_TIMER_CONN_EST,	.default_val = 1*60,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for connection confirm message, 1 to 2 minutes" },
	{ .T = OSMO_SCCP_TIMER_IAS,		.default_val = 7*60,	.unit = OSMO_TDEF_S,
	  .desc = "Send keep-alive: on an idle connection, delay before sending an Idle Timer message, 5 to 10 minutes" }, /* RFC 3868 Ch. 8. */
	{ .T = OSMO_SCCP_TIMER_IAR,		.default_val = 15*60,	.unit = OSMO_TDEF_S,
	  .desc = "Receive keep-alive: on an idle connection, delay until considering a connection as stale, 11 to 21 minutes" }, /* RFC 3868 Ch. 8. */
	{ .T = OSMO_SCCP_TIMER_REL,		.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for release complete message, 10 to 20 seconds" },
	{ .T = OSMO_SCCP_TIMER_REPEAT_REL,	.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for release complete message; or to repeat sending released message after the initial expiry, 10 to 20 seconds" },
	{ .T = OSMO_SCCP_TIMER_INT,		.default_val = 1*60,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting for release complete message; or to release connection resources, freeze the LRN and "
		  "alert a maintenance function after the initial expiry, extending to 1 minute" },
	{ .T = OSMO_SCCP_TIMER_GUARD,		.default_val = 23*60,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting to resume normal procedure for temporary connection sections during the restart procedure, 23 to 25 minutes" },
	{ .T = OSMO_SCCP_TIMER_RESET,		.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting to release temporary connection section or alert maintenance function after reset request message is sent, 10 to 20 seconds" },
	{ .T = OSMO_SCCP_TIMER_REASSEMBLY,	.default_val = 10,	.unit = OSMO_TDEF_S,
	  .desc = "Waiting to receive all the segments of the remaining segments, single segmented message after receiving the first segment, 10 to 20 seconds" },
	{}
};

/* Appendix C.4 of ITU-T Q.714 */
const struct value_string osmo_sccp_timer_names[] = {
	{ OSMO_SCCP_TIMER_CONN_EST, "conn_est" },
	{ OSMO_SCCP_TIMER_IAS, "ias" },
	{ OSMO_SCCP_TIMER_IAR, "iar" },
	{ OSMO_SCCP_TIMER_REL, "rel" },
	{ OSMO_SCCP_TIMER_REPEAT_REL, "repeat_rel" },
	{ OSMO_SCCP_TIMER_INT, "int" },
	{ OSMO_SCCP_TIMER_GUARD, "guard" },
	{ OSMO_SCCP_TIMER_RESET, "reset" },
	{ OSMO_SCCP_TIMER_REASSEMBLY, "reassembly" },
	{}
};

osmo_static_assert(ARRAY_SIZE(osmo_sccp_timer_defaults) == (OSMO_SCCP_TIMERS_LEN) &&
		   ARRAY_SIZE(osmo_sccp_timer_names) == (OSMO_SCCP_TIMERS_LEN),
		   assert_osmo_sccp_timers_count);

/*! \brief Find a SCCP User registered for given PC+SSN or SSN only
 * First search all users with a valid PC for a full PC+SSN match.
 * If no such match was found, search all users with an invalid PC for an SSN-only match.
 *  \param[in] inst SCCP Instance in which to search
 *  \param[in] ssn Sub-System Number to search for
 *  \param[in] pc Point Code to search for
 *  \returns Matching SCCP User; NULL if none found */
struct osmo_sccp_user *
sccp_user_find(struct osmo_sccp_instance *inst, uint16_t ssn, uint32_t pc)
{
	struct osmo_sccp_user *scu;

	if (osmo_ss7_pc_is_valid(pc)) {
		/* First try to find match for PC + SSN */
		llist_for_each_entry(scu, &inst->users, list) {
			if (osmo_ss7_pc_is_valid(scu->pc) && scu->pc == pc && scu->ssn == ssn)
				return scu;
		}
	}

	/* Then try to match on SSN only */
	llist_for_each_entry(scu, &inst->users, list) {
		if (!osmo_ss7_pc_is_valid(scu->pc) && scu->ssn == ssn)
			return scu;
	}

	return NULL;
}

/*! Find a SCCP User registered for given PC+SSN or SSN only.
 * First search all users with a valid PC for a full PC+SSN match.
 * If no match was found, search all users with an invalid PC for an SSN-only match.
 *  \param[in] inst SCCP Instance in which to search.
 *  \param[in] ssn Sub-System Number to search for.
 *  \param[in] pc Point Code to search for.
 *  \returns Matching SCCP User; NULL if none found.
 */
struct osmo_sccp_user *
osmo_sccp_user_find(struct osmo_sccp_instance *inst, uint16_t ssn, uint32_t pc)
{
	return sccp_user_find(inst, ssn, pc);
}

/*! \brief Bind a SCCP User to a given Point Code
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] prim_cb User provided callback to pass a primitive/msg up the stack
 *  \param[in] ssn Sub-System Number to bind to
 *  \param[in] pc Point Code to bind to, or OSMO_SS7_PC_INVALID if none.
 *  \returns Callee-allocated SCCP User on success; negative otherwise
 *
 * Ownership of oph->msg in prim_cb is transferred to the user of the
 * registered callback when called.
 */
static struct osmo_sccp_user *
sccp_user_bind_pc(struct osmo_sccp_instance *inst, const char *name,
		  osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc)
{
	struct osmo_sccp_user *scu;

	scu = sccp_user_find(inst, ssn, pc);
	if (scu) {
		LOGPSCI(inst, LOGL_ERROR,
			"Cannot bind user '%s' to SSN=%u PC=%s, this SSN and PC"
			" is already bound by '%s'\n",
			name, ssn, osmo_ss7_pointcode_print(inst->ss7, pc), scu->name);
		return NULL;
	}

	LOGPSCI(inst, LOGL_INFO, "Binding user '%s' to SSN=%u PC=%s\n",
		name, ssn, osmo_ss7_pointcode_print(inst->ss7, pc));

	scu = sccp_user_alloc(inst, name, prim_cb, ssn, pc);
	return scu;
}

/*! \brief Bind a given SCCP User to a given SSN+PC
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] prim_cb User provided callback to pass a primitive/msg up the stack
 *  \param[in] ssn Sub-System Number to bind to
 *  \param[in] pc Point Code to bind to
 *  \returns Callee-allocated SCCP User on success; negative otherwise
 *
 * Ownership of oph->msg in prim_cb is transferred to the user of the
 * registered callback when called.
 */
struct osmo_sccp_user *
osmo_sccp_user_bind_pc(struct osmo_sccp_instance *inst, const char *name,
		       osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc)
{
	return sccp_user_bind_pc(inst, name, prim_cb, ssn, pc);
}

/*! \brief Bind a given SCCP User to a given SSN (at any PC)
 *  \param[in] inst SCCP Instance
 *  \param[in] name human-readable name
 *  \param[in] prim_cb User provided callback to pass a primitive/msg up the stack
 *  \param[in] ssn Sub-System Number to bind to
 *  \returns Callee-allocated SCCP User on success; negative otherwise
 *
 * Ownership of oph->msg in prim_cb is transferred to the user of the
 * registered callback when called.
 */
struct osmo_sccp_user *
osmo_sccp_user_bind(struct osmo_sccp_instance *inst, const char *name,
		    osmo_prim_cb prim_cb, uint16_t ssn)
{
	return sccp_user_bind_pc(inst, name, prim_cb, ssn, OSMO_SS7_PC_INVALID);
}

/* Timer cb used to transmit queued Routing Failures asynchronously up the stack */
static void rout_fail_pending_cb(void *_inst)
{
	struct osmo_sccp_instance *inst = _inst;
	struct sccp_pending_rout_fail *prf;

	while ((prf = llist_first_entry_or_null(&inst->rout_fail_pending.queue, struct sccp_pending_rout_fail, list))) {
		struct xua_msg *xua = prf->xua;
		uint32_t cause = prf->cause;
		bool scoc = prf->scoc;
		llist_del(&prf->list);
		talloc_free(prf);
		if (scoc) /* Routing Failure SCRC -> SCOC */
			sccp_scoc_rx_scrc_rout_fail(inst, xua, cause);
		else /* Routing Failure SCRC -> SCLC */
			sccp_sclc_rx_scrc_rout_fail(inst, xua, cause);
		xua_msg_free(xua);
	}
}

/* Enqueue Routing Failure to submit it asynchronously to upper layers.
 * xua_msg is copied.
 * scoc: true if it's for SCOC, false if it's for SCLC. */
void sccp_rout_fail_enqueue(struct osmo_sccp_instance *inst, const struct xua_msg *xua, uint32_t cause, bool scoc)
{
	bool queue_was_empty = llist_empty(&inst->rout_fail_pending.queue);
	struct sccp_pending_rout_fail *prf;

	LOGPSCI(inst, LOGL_DEBUG, "Enqueuing SCRC Routing Failure (%s) for %s message %s\n",
		osmo_sccp_return_cause_name(cause),
		scoc ? "CO" : "CL",
		xua_hdr_dump(xua, &xua_dialect_sua));

	prf = talloc(inst, struct sccp_pending_rout_fail);
	OSMO_ASSERT(prf);
	*prf = (struct sccp_pending_rout_fail){
		.xua = xua_msg_copy(xua),
		.cause = cause,
		.scoc = scoc,
	};
	OSMO_ASSERT(prf->xua);
	llist_add_tail(&prf->list, &inst->rout_fail_pending.queue);

	if (queue_was_empty)
		osmo_timer_schedule(&inst->rout_fail_pending.timer, 0, 0);
}

/* prim_cb handed to MTP code for incoming MTP-TRANSFER.ind */
static int mtp_user_prim_cb(struct osmo_prim_hdr *oph, void *ctx)
{
	struct osmo_sccp_instance *inst = ctx;
	struct osmo_mtp_prim *omp = (struct osmo_mtp_prim *)oph;
	struct xua_msg *xua;
	int rc = 0;

	OSMO_ASSERT(oph->sap == MTP_SAP_USER);

	switch (OSMO_PRIM(oph->primitive, oph->operation)) {
	case OSMO_PRIM(OSMO_MTP_PRIM_TRANSFER, PRIM_OP_INDICATION):
		/* Convert from SCCP to SUA in xua_msg format */
		xua = osmo_sccp_to_xua(oph->msg);
		if (!xua) {
			LOGPSCI(inst, LOGL_ERROR, "Couldn't convert SCCP to SUA: %s\n",
				msgb_hexdump(oph->msg));
			rc = -1;
			break;
		}
		xua->mtp = omp->u.transfer;
		/* hand this primitive into SCCP via the SCRC code */
		rc = scrc_rx_mtp_xfer_ind_xua(inst, xua);
		xua_msg_free(xua);
		break;
	case OSMO_PRIM(OSMO_MTP_PRIM_RESUME, PRIM_OP_INDICATION):
		sccp_scmg_rx_mtp_resume(inst, omp->u.resume.affected_dpc);
		break;
	case OSMO_PRIM(OSMO_MTP_PRIM_PAUSE, PRIM_OP_INDICATION):
		sccp_scmg_rx_mtp_pause(inst, omp->u.pause.affected_dpc);
		break;
	default:
		LOGPSCI(inst, LOGL_ERROR, "Unknown primitive %u:%u receivd\n",
			oph->primitive, oph->operation);
		rc = -1;
	}
	msgb_free(oph->msg);
	return rc;
}

static LLIST_HEAD(sccp_instances);

/*! \brief create a SCCP Instance and register it as user with SS7 inst
 *  \param[in] ss7 SS7 instance to which this SCCP instance belongs
 *  \param[in] priv private data to be stored within SCCP instance
 *  \returns callee-allocated SCCP instance on success; NULL on error */
struct osmo_sccp_instance *
osmo_sccp_instance_create(struct osmo_ss7_instance *ss7, void *priv)
{
	struct osmo_sccp_instance *inst;
	int rc;

	inst = talloc_zero(ss7, struct osmo_sccp_instance);
	if (!inst)
		return NULL;

	inst->ss7 = ss7;
	inst->priv = priv;
	INIT_LLIST_HEAD(&inst->users);

	inst->max_optional_data = SCCP_MAX_OPTIONAL_DATA;

	inst->tdefs = talloc_memdup(inst, osmo_sccp_timer_defaults,
				    sizeof(osmo_sccp_timer_defaults));
	osmo_tdefs_reset(inst->tdefs);

	osmo_timer_setup(&inst->rout_fail_pending.timer, rout_fail_pending_cb, inst);
	INIT_LLIST_HEAD(&inst->rout_fail_pending.queue);

	rc = sccp_scmg_init(inst);
	if (rc < 0) {
		talloc_free(inst);
		return NULL;
	}

	inst->ss7_user = osmo_ss7_user_create(ss7, "SCCP");
	osmo_ss7_user_set_prim_cb(inst->ss7_user, mtp_user_prim_cb);
	osmo_ss7_user_set_priv(inst->ss7_user, inst);
	osmo_ss7_user_register(inst->ss7_user, MTP_SI_SCCP);

	llist_add_tail(&inst->list, &sccp_instances);

	return inst;
}

void osmo_sccp_instance_destroy(struct osmo_sccp_instance *inst)
{
	struct osmo_sccp_user *scu, *scu2;

	if (!inst)
		return;

	inst->ss7->sccp = NULL;
	osmo_ss7_user_unregister(inst->ss7_user, MTP_SI_SCCP);
	osmo_ss7_user_destroy(inst->ss7_user);
	inst->ss7_user = NULL;

	llist_for_each_entry_safe(scu, scu2, &inst->users, list) {
		osmo_sccp_user_unbind(scu);
	}
	OSMO_ASSERT(RB_EMPTY_ROOT(&inst->connections)); /* assert is empty */

	osmo_timer_del(&inst->rout_fail_pending.timer);
	/* Note: All entries in inst->rout_fail_pending.queue are freed by talloc. */

	llist_del(&inst->list);
	talloc_free(inst);
}

void osmo_sccp_set_priv(struct osmo_sccp_instance *sccp, void *priv)
{
	sccp->priv = priv;
}

void *osmo_sccp_get_priv(struct osmo_sccp_instance *sccp)
{
	return sccp->priv;
}

/*! \brief derive a basic local SCCP-Address from a given SCCP instance.
 *  \param[out] dest_addr pointer to output address memory
 *  \param[in] inst SCCP instance
 *  \param[in] ssn Subsystem Number */
void osmo_sccp_local_addr_by_instance(struct osmo_sccp_addr *dest_addr,
				      const struct osmo_sccp_instance *inst,
				      uint32_t ssn)
{
	struct osmo_ss7_instance *ss7;

	OSMO_ASSERT(dest_addr);
	OSMO_ASSERT(inst);
	ss7 = inst->ss7;
	OSMO_ASSERT(ss7);

	*dest_addr = (struct osmo_sccp_addr){};

	osmo_sccp_make_addr_pc_ssn(dest_addr, ss7->cfg.primary_pc, ssn);
}

/*! \brief check whether a given SCCP-Address is consistent.
 *  \param[in] addr SCCP address to check
 *  \param[in] presence mask with minimum required address components
 *  \returns true when address data seems plausible */
bool osmo_sccp_check_addr(struct osmo_sccp_addr *addr, uint32_t presence)
{
	/* Minimum requirements do not match */
	if ((addr->presence & presence) != presence)
		return false;

	/* GT ranges */
	if (addr->presence & OSMO_SCCP_ADDR_T_GT) {
		if (addr->gt.gti > 15)
			return false;
		if (addr->gt.npi > 15)
			return false;
		if (addr->gt.nai > 127)
			return false;
	}

	/* Routing by GT, but no GT present */
	if (addr->ri == OSMO_SCCP_RI_GT
	    && !(addr->presence & OSMO_SCCP_ADDR_T_GT))
		return false;

	/* Routing by PC/SSN, but no PC/SSN present */
	if (addr->ri == OSMO_SCCP_RI_SSN_PC) {
		if ((addr->presence & OSMO_SCCP_ADDR_T_PC) == 0)
			return false;
		if ((addr->presence & OSMO_SCCP_ADDR_T_SSN) == 0)
			return false;
	}

	if (addr->ri == OSMO_SCCP_RI_SSN_IP) {
		if ((addr->presence & OSMO_SCCP_ADDR_T_IPv4) == 0 &&
		    (addr->presence & OSMO_SCCP_ADDR_T_IPv6) == 0)
			return false;
	}

	return true;
}

/*! Compare two SCCP Global Titles.
 * \param[in] a  left side.
 * \param[in] b  right side.
 * \return -1 if a < b, 1 if a > b, and 0 if a == b.
 */
int osmo_sccp_gt_cmp(const struct osmo_sccp_gt *a, const struct osmo_sccp_gt *b)
{
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	return memcmp(a, b, sizeof(*a));
}

/*! Compare two SCCP addresses by given presence criteria.
 * Any OSMO_SCCP_ADDR_T_* type not set in presence_criteria is ignored.
 * In case all bits are set in presence_criteria, the comparison is in the order of:
 * OSMO_SCCP_ADDR_T_GT, OSMO_SCCP_ADDR_T_PC, OSMO_SCCP_ADDR_T_IPv4, OSMO_SCCP_ADDR_T_IPv6, OSMO_SCCP_ADDR_T_SSN.
 * The SCCP addresses' Routing Indicator is not compared, see osmo_sccp_addr_ri_cmp().
 * \param[in] a  left side.
 * \param[in] b  right side.
 * \param[in] presence_criteria  A bitmask of OSMO_SCCP_ADDR_T_* values, or OSMO_SCCP_ADDR_T_MASK to compare all parts,
 *                               except the routing indicator.
 * \return -1 if a < b, 1 if a > b, and 0 if all checked values match.
 */
int osmo_sccp_addr_cmp(const struct osmo_sccp_addr *a, const struct osmo_sccp_addr *b, uint32_t presence_criteria)
{
	int rc;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;

	if (presence_criteria & OSMO_SCCP_ADDR_T_GT) {
		if ((a->presence & OSMO_SCCP_ADDR_T_GT) != (b->presence & OSMO_SCCP_ADDR_T_GT))
			return (b->presence & OSMO_SCCP_ADDR_T_GT) ? -1 : 1;
		rc = osmo_sccp_gt_cmp(&a->gt, &b->gt);
		if (rc)
			return rc;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_PC) {
		if ((a->presence & OSMO_SCCP_ADDR_T_PC) != (b->presence & OSMO_SCCP_ADDR_T_PC))
			return (b->presence & OSMO_SCCP_ADDR_T_PC) ? -1 : 1;

		if ((a->presence & OSMO_SCCP_ADDR_T_PC)
		    && a->pc != b->pc)
			return (a->pc < b->pc) ? -1 : 1;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_IPv4) {
		if ((a->presence & OSMO_SCCP_ADDR_T_IPv4) != (b->presence & OSMO_SCCP_ADDR_T_IPv4))
			return (b->presence & OSMO_SCCP_ADDR_T_IPv4) ? -1 : 1;
		rc = memcmp(&a->ip.v4, &b->ip.v4, sizeof(a->ip.v4));
		if (rc)
			return rc;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_IPv6) {
		if ((a->presence & OSMO_SCCP_ADDR_T_IPv6) != (b->presence & OSMO_SCCP_ADDR_T_IPv6))
			return (b->presence & OSMO_SCCP_ADDR_T_IPv6) ? -1 : 1;
		rc = memcmp(&a->ip.v6, &b->ip.v6, sizeof(a->ip.v6));
		if (rc)
			return rc;
	}

	if (presence_criteria & OSMO_SCCP_ADDR_T_SSN) {
		if ((a->presence & OSMO_SCCP_ADDR_T_SSN) != (b->presence & OSMO_SCCP_ADDR_T_SSN))
			return (b->presence & OSMO_SCCP_ADDR_T_SSN) ? -1 : 1;
		if (a->ssn != b->ssn)
			return (a->ssn < b->ssn) ? -1 : 1;
	}

	return 0;
}

/*! Compare the routing information of two SCCP addresses.
 * Compare the ri of a and b, and, if equal, return osmo_sccp_addr_cmp() with presence criteria selected according to
 * ri.
 * \param[in] a  left side.
 * \param[in] b  right side.
 * \return -1 if a < b, 1 if a > b, and 0 if a == b.
 */
int osmo_sccp_addr_ri_cmp(const struct osmo_sccp_addr *a, const struct osmo_sccp_addr *b)
{
	uint32_t presence_criteria;
	if (a == b)
		return 0;
	if (!a)
		return -1;
	if (!b)
		return 1;
	if (a->ri != b->ri)
		return (a->ri < b->ri) ? -1 : 1;
	switch (a->ri) {
	case OSMO_SCCP_RI_NONE:
		return 0;
	case OSMO_SCCP_RI_GT:
		presence_criteria = OSMO_SCCP_ADDR_T_GT;
		break;
	case OSMO_SCCP_RI_SSN_PC:
		presence_criteria = OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC;
		break;
	case OSMO_SCCP_RI_SSN_IP:
		/* Pick IPv4 or v6 depending on what a->presence indicates. */
		presence_criteria = OSMO_SCCP_ADDR_T_SSN | (a->presence & (OSMO_SCCP_ADDR_T_IPv4 | OSMO_SCCP_ADDR_T_IPv6));
		break;
	default:
		return 0;
	}

	return osmo_sccp_addr_cmp(a, b, presence_criteria);
}

/***********************************************************************
 * Convenience function for CLIENT
 ***********************************************************************/

 /* Returns whether AS is already associated to any AS.
  * Helper function for osmo_sccp_simple_client_on_ss7_id(). */
static bool asp_serves_some_as(const struct osmo_ss7_asp *asp)
{
	struct osmo_ss7_as *as_i;
	llist_for_each_entry(as_i, &asp->inst->as_list, list) {
		if (osmo_ss7_as_has_asp(as_i, asp))
			return true;
	}
	return false;
}

/*! \brief request an sccp client instance
 *  \param[in] ctx talloc context
 *  \param[in] ss7_id of the SS7/CS7 instance
 *  \param[in] name human readable name
 *  \param[in] default_pc pointcode to be used on missing VTY setting
 *  \param[in] prot protocol to be used (e.g OSMO_SS7_ASP_PROT_M3UA)
 *  \param[in] default_local_port local port to be used on missing VTY setting
 *  \param[in] default_local_ip local IP-address to be used on missing VTY setting (NULL: use library own defaults)
 *  \param[in] default_remote_port remote port to be used on missing VTY setting
 *  \param[in] default_remote_ip remote IP-address to be used on missing VTY setting (NULL: use library own defaults)
 *  \returns callee-allocated SCCP instance on success; NULL on error */

struct osmo_sccp_instance *
osmo_sccp_simple_client_on_ss7_id(void *ctx, uint32_t ss7_id, const char *name,
				  uint32_t default_pc,
				  enum osmo_ss7_asp_protocol prot,
				  int default_local_port,
				  const char *default_local_ip,
				  int default_remote_port,
				  const char *default_remote_ip)
{
	struct osmo_ss7_instance *ss7;
	bool ss7_created = false;
	struct osmo_ss7_as *as;
	bool as_created = false;
	struct osmo_ss7_route *rt;
	bool rt_created = false;
	struct osmo_ss7_asp *asp;
	bool asp_created = false;
	char *as_name, *asp_name = NULL;
	int trans_proto;

	trans_proto = ss7_default_trans_proto_for_asp_proto(prot);

	/*! The function will examine the given CS7 instance and its sub
	 *  components (as, asp, etc.). If necessary it will allocate
	 *  the missing components. If no CS7 instance can be detected
	 *  under the caller supplied ID, a new instance will be created
	 *  beforehand. */

	/* Choose default ports when the caller does not supply valid port
	 * numbers. */
	if (!default_remote_port || default_remote_port < 0)
		default_remote_port = osmo_ss7_asp_protocol_port(prot);
	if (default_local_port < 0)
		default_local_port = osmo_ss7_asp_protocol_port(prot);

	/* Check if there is already an ss7 instance present under
	 * the given id. If not, we will create a new one. */
	ss7 = osmo_ss7_instance_find(ss7_id);
	if (!ss7) {
		LOGP(DLSCCP, LOGL_NOTICE, "%s: Creating SS7 instance\n",
		     name);

		/* Create a new ss7 instance */
		ss7 = osmo_ss7_instance_find_or_create(ctx, ss7_id);
		if (!ss7) {
			LOGP(DLSCCP, LOGL_ERROR,
			     "Failed to find or create SS7 instance\n");
			return NULL;
		}

		/* Setup primary pointcode
		 * NOTE: This means that the user must set the pointcode to a
		 * proper value when a cs7 instance is defined via the VTY. */
		ss7->cfg.primary_pc = default_pc;
		ss7_created = true;
	}

	/* In case no valid point-code has been configured via the VTY, we
	 * will fall back to the default pointcode. */
	if (!osmo_ss7_pc_is_valid(ss7->cfg.primary_pc)) {
		LOGP(DLSCCP, LOGL_ERROR,
		     "SS7 instance %u: no primary point-code set, using default point-code\n",
		     ss7->cfg.id);
		ss7->cfg.primary_pc = default_pc;
	}

	LOGP(DLSCCP, LOGL_NOTICE, "%s: Using SS7 instance %u, pc:%s\n", name,
	     ss7->cfg.id, osmo_ss7_pointcode_print(ss7, ss7->cfg.primary_pc));

	/* Check if there is already an application server that matches
	 * the protocol we intend to use. If not, we will create one. */
	as = osmo_ss7_as_find_by_proto(ss7, prot);
	if (!as) {
		LOGP(DLSCCP, LOGL_NOTICE, "%s: Creating AS instance\n",
		     name);
		as_name = talloc_asprintf(ctx, "as-clnt-%s", name);
		as = osmo_ss7_as_find_or_create(ss7, as_name, prot);
		talloc_free(as_name);
		if (!as)
			goto out_ss7;
		as_created = true;
		as->cfg.routing_key.pc = ss7->cfg.primary_pc;
		as->simple_client_allocated = true;
	}
	LOGP(DLSCCP, LOGL_NOTICE, "%s: Using AS instance %s\n", name,
	     as->cfg.name);

	/* Create a default dynamic route if necessary */
	rt = ss7_route_table_find_route_by_dpc_mask(ss7->rtable_system, 0, 0, true);
	if (!rt) {
		LOGP(DLSCCP, LOGL_NOTICE, "%s: Creating default route\n", name);
		rt = ss7_route_create(ss7->rtable_system, 0, 0,
				      true, as->cfg.name);
		if (!rt)
			goto out_as;
		rt_created = true;
	}

	/* Check if we do already have an application server process
	 * that is associated with the application server we have chosen
	 * the application server process must also match the protocol
	 * we intend to use. */
	asp = osmo_ss7_asp_find_by_proto(as, prot);
	if (!asp) {
		/* Check if the user has created an ASP for this proto that is not added on any AS yet. */
		struct osmo_ss7_asp *asp_i;
		llist_for_each_entry(asp_i, &ss7->asp_list, list) {
			if (asp_i->cfg.proto != prot)
				continue;
			if (asp_serves_some_as(asp_i)) {
				/* This ASP is already on another AS.
				 * If it was on this AS, we'd have found it above. */
				continue;
			}
			/* This ASP matches the protocol and is not yet associated to any AS. Use it. */
			asp = asp_i;
			LOGP(DLSCCP, LOGL_NOTICE, "%s: ASP %s for %s is not associated with any AS, using it\n",
			     name, asp->cfg.name, osmo_ss7_asp_protocol_name(prot));
			ss7_as_add_asp(as, asp);
			/* ASP became associated to a new AS, hence it needs to be
			 * restarted to announce/register its Routing Context.
			 * Make sure proper defaults are applied if app didn't
			 * provide specific default values, then restart the ASP: */
			ss7_asp_restart_after_reconfigure(asp);
			break;
		}
		if (!asp) {
			asp_name = talloc_asprintf(ctx, "asp-clnt-%s", name);
			LOGP(DLSCCP, LOGL_NOTICE, "%s: No unassociated ASP for %s, creating new ASP %s\n",
			     name, osmo_ss7_asp_protocol_name(prot), asp_name);
			asp = osmo_ss7_asp_find_or_create2(ss7, asp_name,
							   default_remote_port,
							   default_local_port,
							   trans_proto, prot);
			talloc_free(asp_name);
			if (!asp)
				goto out_rt;
			asp_created = true;
			asp->simple_client_allocated = true;
			/* Ensure that the ASP we use is set to operate as a client. */
			asp->cfg.is_server = false;
			/* Ensure that the ASP we use is set to role ASP. */
			asp->cfg.role = OSMO_SS7_ASP_ROLE_ASP;
			if (default_local_ip)
				ss7_asp_peer_set_hosts(&asp->cfg.local, asp, &default_local_ip, 1);
			if (default_remote_ip)
				ss7_asp_peer_set_hosts(&asp->cfg.remote, asp, &default_remote_ip, 1);
			ss7_as_add_asp(as, asp);
			/* Make sure proper defaults are applied if app didn't
			provide specific default values, then restart the ASP: */
			ss7_asp_restart_after_reconfigure(asp);
		}
	}

	/* Extra sanity checks if the ASP asp-clnt-* was pre-configured over VTY: */
	if (!asp->simple_client_allocated) {
		/* Forbid ASPs defined through VTY that are not entirely
		 * configured. "role" and "transport-role" must be explicitly provided:
		 */
		if (!asp->cfg.role_set_by_vty) {
			LOGP(DLSCCP, LOGL_ERROR,
			     "%s: ASP %s defined in VTY but 'role' was not set there, please set it.\n",
			     name, asp->cfg.name);
			goto out_asp;
		}
		if (!asp->cfg.trans_role_set_by_vty) {
			LOGP(DLSCCP, LOGL_ERROR,
			     "%s: ASP %s defined in VTY but 'transport-role' was not set there, please set it.\n",
			     name, asp->cfg.name);
			goto out_asp;
		}

		/* If ASP was configured through VTY it may be explicitly configured as
		 * SCTP server. It may be a bit confusing since this function is to create
		 * a "SCCP simple client", but this allows users of this API such as
		 * osmo-hnbgw to support transport-role server if properly configured through VTY.
		*/
		if (asp->cfg.is_server) {
			struct osmo_xua_server *xs;
			LOGP(DLSCCP, LOGL_NOTICE,
			     "%s: Requesting an SCCP simple client on ASP %s configured with 'transport-role server'\n",
			     name, asp->cfg.name);
			xs = ss7_xua_server_find2(ss7,
						       asp->cfg.trans_proto, prot,
						       asp->cfg.local.port);
			if (!xs) {
				LOGP(DLSCCP, LOGL_ERROR, "%s: Requesting an SCCP simple client on ASP %s configured "
				     "with 'transport-role server' but no matching xUA server was configured!\n",
				     name, asp->cfg.name);
				goto out_asp;
			}
		}
		/* ASP was already started here previously by VTY go_parent. */
	}

	LOGP(DLSCCP, LOGL_NOTICE, "%s: Using ASP instance %s\n", name,
	     asp->cfg.name);

	osmo_ss7_ensure_sccp(ss7);
	if (!ss7->sccp)
		goto out_asp;

	return ss7->sccp;

out_asp:
	if (asp_created)
		osmo_ss7_asp_destroy(asp);
out_rt:
	if (rt_created)
		ss7_route_destroy(rt);
out_as:
	if (as_created)
		osmo_ss7_as_destroy(as);
out_ss7:
	if (ss7_created)
		osmo_ss7_instance_destroy(ss7);

	return NULL;
}

/*! \brief request an sccp client instance
 *  \param[in] ctx talloc context
 *  \param[in] name human readable name
 *  \param[in] default_pc pointcode to be used on missing VTY setting
 *  \param[in] prot protocol to be used (e.g OSMO_SS7_ASP_PROT_M3UA)
 *  \param[in] default_local_port local port to be used on missing VTY setting
 *  \param[in] default_local_ip local IP-address to be used on missing VTY setting
 *  \param[in] default_remote_port remote port to be used on missing VTY setting
 *  \param[in] default_remote_ip remote IP-address to be used on missing VTY setting
 *  \returns callee-allocated SCCP instance on success; NULL on error */
struct osmo_sccp_instance *
osmo_sccp_simple_client(void *ctx, const char *name, uint32_t default_pc,
			enum osmo_ss7_asp_protocol prot, int default_local_port,
			const char *default_local_ip, int default_remote_port,
			const char *default_remote_ip)
{
	/*! This is simplified version of osmo_sccp_simple_client_on_ss7_id().
	 *  the only difference is that the ID of the CS7 instance will be
	 *  set to 0 statically */

	return osmo_sccp_simple_client_on_ss7_id(ctx, 0, name, default_pc, prot,
						 default_local_port,
						 default_local_ip,
						 default_remote_port,
						 default_remote_ip);
}

/***********************************************************************
 * Convenience function for SERVER
 ***********************************************************************/

struct osmo_sccp_instance *
osmo_sccp_simple_server_on_ss7_id(void *ctx, uint32_t ss7_id, uint32_t pc,
				  enum osmo_ss7_asp_protocol prot,
				  int local_port, const char *local_ip)
{
	struct osmo_ss7_instance *ss7;
	struct osmo_xua_server *xs;
	int trans_proto;
	int rc;

	trans_proto = ss7_default_trans_proto_for_asp_proto(prot);

	if (local_port < 0)
		local_port = osmo_ss7_asp_protocol_port(prot);

	/* allocate + initialize SS7 instance */
	ss7 = osmo_ss7_instance_find_or_create(ctx, ss7_id);
	if (!ss7)
		return NULL;
	ss7->cfg.primary_pc = pc;

	xs = ss7_xua_server_create2(ss7, trans_proto, prot, local_port, local_ip);
	if (!xs)
		goto out_ss7;

	rc = ss7_xua_server_bind(xs);
	if (rc < 0)
		goto out_xs;

	/* Allocate SCCP stack */
	osmo_ss7_ensure_sccp(ss7);
	if (!ss7->sccp)
		goto out_xs;

	return ss7->sccp;

out_xs:
	ss7_xua_server_destroy(xs);
out_ss7:
	osmo_ss7_instance_destroy(ss7);

	return NULL;
}

struct osmo_sccp_instance *
osmo_sccp_simple_server(void *ctx, uint32_t pc,
			enum osmo_ss7_asp_protocol prot, int local_port,
			const char *local_ip)
{
	return osmo_sccp_simple_server_on_ss7_id(ctx, 0, pc, prot,
						 local_port, local_ip);
}

struct osmo_sccp_instance *
osmo_sccp_simple_server_add_clnt(struct osmo_sccp_instance *inst,
				 enum osmo_ss7_asp_protocol prot,
				 const char *name, uint32_t pc,
				 int local_port, int remote_port,
				 const char *remote_ip)
{
	struct osmo_ss7_instance *ss7 = inst->ss7;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route *rt;
	struct osmo_ss7_asp *asp;
	struct osmo_xua_server *oxs;
	char *as_name, *asp_name;
	int trans_proto;

	trans_proto = ss7_default_trans_proto_for_asp_proto(prot);

	if (local_port < 0)
		local_port = osmo_ss7_asp_protocol_port(prot);

	if (remote_port < 0)
		remote_port = osmo_ss7_asp_protocol_port(prot);

	as_name = talloc_asprintf(ss7, "as-srv-%s", name);
	asp_name = talloc_asprintf(ss7, "asp-srv-%s", name);

	/* application server */
	as = osmo_ss7_as_find_or_create(ss7, as_name, prot);
	if (!as)
		goto out_strings;

	/* route only selected PC to the client */
	rt = ss7_route_create(ss7->rtable_system, pc, 0xffff, true, as_name);
	if (!rt)
		goto out_as;

	asp = osmo_ss7_asp_find_or_create2(ss7, asp_name,
					   remote_port, local_port,
					   trans_proto, prot);
	if (!asp)
		goto out_rt;
	oxs = ss7_xua_server_find2(ss7, asp->cfg.trans_proto, prot, local_port);
	if (!oxs)
		goto out_asp;
	if (ss7_asp_peer_set_hosts(&asp->cfg.local, asp,
					(const char * const*)oxs->cfg.local.host,
					oxs->cfg.local.host_cnt) < 0)
		goto out_asp;
	if (ss7_asp_peer_add_host(&asp->cfg.remote, asp, remote_ip) < 0)
		goto out_asp;
	asp->cfg.is_server = true;
	asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
	ss7_as_add_asp(as, asp);
	talloc_free(asp_name);
	talloc_free(as_name);
	osmo_ss7_asp_restart(asp);

	return ss7->sccp;

out_asp:
	osmo_ss7_asp_destroy(asp);
out_rt:
	ss7_route_destroy(rt);
out_as:
	osmo_ss7_as_destroy(as);
out_strings:
	talloc_free(as_name);
	talloc_free(asp_name);

	return NULL;
}

/*! Adjust the upper bound for the optional data length (the payload) for CR, CC, CREF and RLSD messages.
 * For any Optional Data part larger than this value in octets, send CR, CC, CREF and RLSD messages without any payload,
 * and send the data payload in a separate Data Form 1 message. ITU-T Q.713 sections 4.2 thru 4.5 define a limit of 130
 * bytes for the 'Data' parameter. This limit can be adjusted here. May be useful for interop with nonstandard SCCP
 * peers.
 * \param[in] sccp  SCCP instance to reconfigure.
 * \param[in] val  Number of bytes to set as upper bound for the optional data length, or pass a negative value to set
 *                 the standard value of SCCP_MAX_OPTIONAL_DATA == 130, which conforms to ITU-T Q.713.
 */
void osmo_sccp_set_max_optional_data(struct osmo_sccp_instance *inst, int val)
{
	if (!inst)
		return;
	if (val < 0)
		val = SCCP_MAX_OPTIONAL_DATA;
	inst->max_optional_data = val;
}

/*! \brief get the SS7 instance that is related to the given SCCP instance
 *  \param[in] sccp SCCP instance
 *  \returns SS7 instance; NULL if sccp was NULL */
struct osmo_ss7_instance *osmo_sccp_get_ss7(const struct osmo_sccp_instance *sccp)
{
	if (!sccp)
		return NULL;
	return sccp->ss7;
}
