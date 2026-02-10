/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 * Author: Pau Espin Pedrol <pespin@sysmocom.de>
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
#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_as.h"
#include "ss7_combined_linkset.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"

/******************************************************************************
 * SS7 Combined Linkset
 *
 * ITU Q.704 4.2.1: "Signalling traffic to be sent to a particular signalling
 * point in the network is normally routed to one or, in the case of load
 * sharing between link sets in the international network, two link sets. A load
 * sharing collection of two or more link sets is called a combined link set"
 * [...]
 * "The possible link set (combined link sets) appear in a certain priority
 * order. The link set (combined link set) having the highest priority is used
 * whenever it is available."
 * [...]
 * "It is defined that the normal link set (combined link set) for traffic to the
 * concerned destination. The link set (combined link set) which is in use at a
 * given time is called the current link set (combined link set). The current
 * link set (combined link set) consists either of the normal link set (combined
 * link set) or of an alternative link set (combined link set)."
 *****************************************************************************/

/*! \brief Insert combined_link into its routing table
 *  \param[in] clset Combined link to be inserted into its routing table
 *  \returns 0 on success, negative on error
 *
 * A combined link is only really used once it has been inserted into its routing table.
 *
 * insert the route in the ordered list of routes. The list is sorted by
 * mask length, so that the more specific (longer mask) routes are
 * first, while the less specific routes with shorter masks are last.
 * Within the same mask length, the routes are ordered by priority
 * (where lower value means higher prio).
 * Hence, the first matching route in a linear iteration is the most
 * specific match.
 */
static void ss7_combined_linkset_insert(struct osmo_ss7_combined_linkset *clset)
{
	struct osmo_ss7_route_table *rtbl = clset->rtable;
	struct osmo_ss7_combined_linkset *it;

	llist_for_each_entry(it, &rtbl->combined_linksets, list) {
		if (it->cfg.mask == clset->cfg.mask &&
		    it->cfg.priority > clset->cfg.priority) {
			/* insert before the current entry */
			llist_add(&clset->list, it->list.prev);
			return;
		}
		if (it->cfg.mask < clset->cfg.mask) {
			/* insert before the current entry */
			llist_add(&clset->list, it->list.prev);
			return;
		}
	}
	/* not added, i.e. no smaller mask length and priority found: we are the
	 * smallest mask and priority and thus should go last */
	llist_add_tail(&clset->list, &rtbl->combined_linksets);
}

struct osmo_ss7_combined_linkset *
ss7_combined_linkset_alloc(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask, uint32_t prio)
{
	struct osmo_ss7_combined_linkset *clset;

	clset = talloc_zero(rtbl, struct osmo_ss7_combined_linkset);
	if (!clset)
		return NULL;

	clset->rtable = rtbl;
	/* truncate mask to maximum. Let's avoid callers specifying arbitrary large
	 * masks to ensure we don't fail duplicate detection with longer mask lengths */
	clset->cfg.mask = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, mask);
	clset->cfg.pc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, pc);
	clset->cfg.priority = prio;
	INIT_LLIST_HEAD(&clset->routes);

	ss7_combined_linkset_insert(clset);
	return clset;
}

void
ss7_combined_linkset_free(struct osmo_ss7_combined_linkset *clset)
{
	if (!clset)
		return;
	llist_del(&clset->list);
	talloc_free(clset);
}

void ss7_combined_linkset_add_route(struct osmo_ss7_combined_linkset *clset, struct osmo_ss7_route *rt)
{
	llist_add_tail(&rt->list, &clset->routes);
	clset->num_routes++;
	rt->clset = clset;
}

/* clset may end up freed as a result: */
void ss7_combined_linkset_del_route(struct osmo_ss7_route *rt)
{
	struct osmo_ss7_combined_linkset *clset = rt->clset;

	/* Remove route from eSLS table: */
	for (unsigned int i = 0; i < ARRAY_SIZE(clset->esls_table); i++) {
		if (clset->esls_table[i].normal_rt == rt)
			clset->esls_table[i].normal_rt = NULL;
		if (clset->esls_table[i].alt_rt == rt)
			clset->esls_table[i].alt_rt = NULL;
	}

	/* Update round robin state */
	if (rt == clset->last_route_roundrobin_ass) {
		ss7_llist_round_robin(&clset->routes, &clset->last_route_roundrobin_ass, struct osmo_ss7_route, list);
		/* If there's only one left, remove state: */
		if (rt == clset->last_route_roundrobin_ass)
			clset->last_route_roundrobin_ass = NULL;
	}
	if (rt == clset->last_route_roundrobin_tx) {
		ss7_llist_round_robin(&clset->routes, &clset->last_route_roundrobin_tx, struct osmo_ss7_route, list);
		/* If there's only one left, remove state: */
		if (rt == clset->last_route_roundrobin_tx)
			clset->last_route_roundrobin_tx = NULL;
	}

	llist_del(&rt->list);
	rt->clset = NULL;
	clset->num_routes--;
	if (clset->num_routes == 0)
		ss7_combined_linkset_free(clset);
}

/* Whether any route in the combined linkset is available: */
bool ss7_combined_linkset_is_available(const struct osmo_ss7_combined_linkset *clset)
{
	bool avail = false;
	struct osmo_ss7_route *rt;
	llist_for_each_entry(rt, &clset->routes, list) {
		if (ss7_route_is_available(rt)) {
			avail = true;
			break;
		}
	}
	return avail;
}

static ext_sls_t osmo_ss7_instance_calc_itu_ext_sls(const struct osmo_ss7_instance *inst, const struct osmo_ss7_route_label *rtlabel)
{
	/* Take 6 bits from OPC and DPC according to config: */
	uint8_t opc6 = (uint8_t)((rtlabel->opc >> inst->cfg.opc_shift) & 0x3f);
	uint8_t dpc6 = (uint8_t)((rtlabel->dpc >> inst->cfg.dpc_shift) & 0x3f);

	/* Derivate 3-bit value from OPC and DPC: */
	uint8_t opc3 = ((opc6 >> 3) ^ (opc6 & 0x07)) & 0x07;
	uint8_t dpc3 = ((dpc6 >> 3) ^ (dpc6 & 0x07)) & 0x07;
	uint8_t opc_dpc3 = (opc3 ^ dpc3) & 0x07;

	/* Generate 7 bit extended-SLS: 3-bit OPC-DPC + 4 bit SLS: */
	uint8_t ext_sls = (opc_dpc3 << 4) | ((rtlabel->sls) & 0x0f);
	OSMO_ASSERT(ext_sls < NUM_EXT_SLS);

	/* Pick extended-SLS bits according to config: */
	ext_sls = ext_sls >> inst->cfg.sls_shift;
	return ext_sls;
}

/* ITU Q.704 4.2.1: "current link set (combined link set)". Pick available already selected route */
struct osmo_ss7_route *current_rt(const struct osmo_ss7_esls_entry *eslse)
{
	if (eslse->normal_rt && ss7_route_is_available(eslse->normal_rt))
		return eslse->normal_rt;
	if (eslse->alt_rt && ss7_route_is_available(eslse->alt_rt))
		return eslse->alt_rt;
	return NULL;
}

/* Pick a Route from Combined Linkset in a round-robin fashion.
 * During Loadshare eSLS table generation we want to pick Normal Route
 * in a distributed fashion, regardless of active state (Alternative Route will
 * be picked up temporarily later on if needed).
 * Moreover, we must use a different index from the "active"
 * ss7_combined_linkset_select_route_roundrobin() below, in order to avoid tainting
 * the distribution.
 */
static struct osmo_ss7_route *ss7_combined_linkset_assign_route_roundrobin(struct osmo_ss7_combined_linkset *clset)
{
	struct osmo_ss7_route *rt;

	for (unsigned int i = 0; i < clset->num_routes; i++) {
		rt = ss7_llist_round_robin(&clset->routes, &clset->last_route_roundrobin_ass, struct osmo_ss7_route, list);
		if (rt)
			return rt;
	}
	return NULL;
}

/* Pick an available route from Combined Linkset in a round-robin fashion, to send a message through. */
static struct osmo_ss7_route *ss7_combined_linkset_select_route_roundrobin(struct osmo_ss7_combined_linkset *clset)
{
	struct osmo_ss7_route *rt;

	for (unsigned int i = 0; i < clset->num_routes; i++) {
		rt = ss7_llist_round_robin(&clset->routes, &clset->last_route_roundrobin_tx, struct osmo_ss7_route, list);
		if (rt && ss7_route_is_available(rt))
			return rt;
	}
	return NULL;
}

struct osmo_ss7_route *
ss7_combined_linkset_lookup_route(struct osmo_ss7_combined_linkset *clset, const struct osmo_ss7_route_label *rtlabel)
{
	struct osmo_ss7_route *rt;
	struct osmo_ss7_instance *inst = clset->rtable->inst;
	ext_sls_t esls = osmo_ss7_instance_calc_itu_ext_sls(inst, rtlabel);
	struct osmo_ss7_esls_entry *eslse = &clset->esls_table[esls];
	char buf[256];

	/* First check if we have a cached route for this ESLS */
	rt = current_rt(eslse);
	if (rt) {
		if (rt == eslse->normal_rt) {
			/* We can transmit over normal route.
			 * Clean up alternative route since it's not needed anymore */
			if (eslse->alt_rt) {
				LOGPCLSET(clset, DLSS7, LOGL_NOTICE, "RT lookup: %s -> eSLS=%u: "
					  "Normal Route via '%s' became available, drop use of Alternative Route via '%s'\n",
					  ss7_route_label_to_str(buf, sizeof(buf), inst, rtlabel), esls,
					  eslse->normal_rt->dest.as ? eslse->normal_rt->dest.as->cfg.name : "<linkset>",
					  eslse->alt_rt->dest.as ? eslse->alt_rt->dest.as->cfg.name : "<linkset>");
				eslse->alt_rt = NULL;
			}
			LOGPCLSET(clset, DLSS7, LOGL_DEBUG,
				  "RT lookup: %s -> eSLS=%u: use Normal Route via '%s'\n",
				  ss7_route_label_to_str(buf, sizeof(buf), inst, rtlabel), esls,
				  eslse->normal_rt->dest.as ? eslse->normal_rt->dest.as->cfg.name : "<linkset>");
			return rt;
		}
		/* We can transmit over alternative route: */
		return rt;
	}

	/* No current route available, try to find a new current route: */

	/* No normal route selected yet: */
	if (!eslse->normal_rt) {
		bool rt_avail;
		/* Establish a Normal Route, regardless of available state: */
		rt = ss7_combined_linkset_assign_route_roundrobin(clset);
		/* No route found for Normal Route, regardless of state... */
		if (!rt)
			return NULL;
		eslse->normal_rt = rt;
		rt_avail = ss7_route_is_available(eslse->normal_rt);
		LOGPCLSET(clset, DLSS7, LOGL_INFO, "RT loookup: %s -> eSLS=%u: "
			  "picked Normal Route via '%s' round-robin style (%s)\n",
			  ss7_route_label_to_str(buf, sizeof(buf), inst, rtlabel), esls,
			  rt->dest.as ? rt->dest.as->cfg.name : "<linkset>",
			  rt_avail ? "available" : "unavailable");
		if (rt_avail) {
			/* Found available Normal Route: */
			return eslse->normal_rt;
		}
		/* Normal Route was assigned, but it is not active, fall-through
		 * below to attempt transmission through Alternative Route: */
	}

	/* Normal route unavailable and no alternative route (or unavailable too).
	 * start ITU Q.704 section 7 "forced rerouting" procedure: */
	rt = ss7_combined_linkset_select_route_roundrobin(clset);
	if (rt) {
		eslse->alt_rt = rt;
		LOGPCLSET(clset, DLSS7, LOGL_NOTICE, "RT Lookup: %s -> eSLS=%u: "
			  "Normal Route via '%s' unavailable, picked Alternative Route via '%s' round-robin style\n",
			  ss7_route_label_to_str(buf, sizeof(buf), inst, rtlabel), esls,
			  eslse->normal_rt->dest.as ? eslse->normal_rt->dest.as->cfg.name : "<linkset>",
			  eslse->alt_rt->dest.as ? eslse->alt_rt->dest.as->cfg.name : "<linkset>");
	} else {
		/* No alternative route found, NULL is returned. */
		LOGPCLSET(clset, DLSS7, LOGL_INFO, "RT Lookup: %s -> eSLS=%u: "
			  "Normal Route via '%s' unavailable, all Alternative Routes unavailable\n",
			  ss7_route_label_to_str(buf, sizeof(buf), inst, rtlabel), esls,
			  eslse->normal_rt->dest.as ? eslse->normal_rt->dest.as->cfg.name : "<linkset>");
	}
	return rt;
}
