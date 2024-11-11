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
 * Within the same mask length, the routes are ordered by priority.
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
	llist_del(&rt->list);
	rt->clset = NULL;
	clset->num_routes--;
	if (clset->num_routes == 0)
		ss7_combined_linkset_free(clset);
}
