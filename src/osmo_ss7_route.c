/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023-2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_linkset.h"
#include "ss7_as.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"

/***********************************************************************
 * SS7 Routes
 ***********************************************************************/

/*! \brief Allocate a route entry
 *  \param[in] rtbl Routing Table where the route belongs
 *  \param[in] pc Point Code of the destination of the route
 *  \param[in] mask Mask of the destination Point Code \ref pc
 *  \returns Allocated route (not yet inserted into its rtbl), NULL on error
 *
 * The returned route has no linkset associated yet, user *must* associate it
 * using API ss7_route_set_linkset() before inserting the route into its
 * routing table.
 *
 * Fields priority and qos_class may be set *before* inserting the route into
 * its routing table:
 * - A default priority of 0 is configured on the route.
 * - A default qos-class of 0 is configured on the route.
 *
 * Use API ss7_route_insert() to insert the route into its routing table.
 *
 * The route entry allocated with this API can be destroyed/freed at any point using API
 * ss7_route_destroy(), regardless of it being already inserted or not in
 * its routing table.
 */
struct osmo_ss7_route *
ss7_route_alloc(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask)
{
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(ss7_initialized);

	rt = talloc_zero(rtbl, struct osmo_ss7_route);
	if (!rt)
		return NULL;

	/* Mark it as not being inserted yet in rtbl */
	INIT_LLIST_HEAD(&rt->list);
	rt->rtable = rtbl;
	/* truncate mask to maximum. Let's avoid callers specifying arbitrary large
	 * masks to ensure we don't fail duplicate detection with longer mask lengths */
	rt->cfg.mask = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, mask);
	rt->cfg.pc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, pc);
	rt->cfg.priority = OSMO_SS7_ROUTE_PRIO_DEFAULT;
	return rt;
}

/*! \brief Check whether route has already been inserted into its routing table.
 *  \returns true if already inserted, false if not.
 */
static bool ss7_route_inserted(const struct osmo_ss7_route *rt)
{
	return !llist_empty(&rt->list);
}

/*! \brief Set linkset on route entry
 *  \param[in] rt Route to be configured
 *  \param[in] linkset_name string name of the linkset to be used
 *  \returns 0 on success, negative on error.
 */
int
ss7_route_set_linkset(struct osmo_ss7_route *rt, const char *linkset_name)
{
	struct osmo_ss7_linkset *lset;
	struct osmo_ss7_as *as = NULL;
	struct osmo_ss7_route_table *rtbl = rt->rtable;

	if (rt->cfg.linkset_name) {
		LOGSS7(rtbl->inst, LOGL_ERROR, "Attempt setting linkset on route already configured!\n");
		return -EBUSY;
	}

	if (ss7_route_inserted(rt)) {
		LOGSS7(rtbl->inst, LOGL_ERROR, "Attempt setting linkset on route already in the routing table!\n");
		return -EALREADY;
	}

	lset = ss7_linkset_find_by_name(rtbl->inst, linkset_name);
	if (!lset) {
		as = osmo_ss7_as_find_by_name(rtbl->inst, linkset_name);
		if (!as)
			return -ENODEV;
	}

	rt->cfg.linkset_name = talloc_strdup(rt, linkset_name);
	if (lset) {
		rt->dest.linkset = lset;
		LOGSS7(rtbl->inst, LOGL_INFO, "Creating route: pc=%u=%s mask=0x%x via linkset '%s'\n",
		       rt->cfg.pc, osmo_ss7_pointcode_print(rtbl->inst, rt->cfg.pc),
		       rt->cfg.mask, lset->cfg.name);
	} else {
		rt->dest.as = as;
		LOGSS7(rtbl->inst, LOGL_INFO, "Creating route: pc=%u=%s mask=0x%x via AS '%s'\n",
		       rt->cfg.pc, osmo_ss7_pointcode_print(rtbl->inst, rt->cfg.pc),
		       rt->cfg.mask, as->cfg.name);
	}
	return 0;
}

/* insert the route in the ordered list of routes. The list is sorted by
 * mask length, so that the more specific (longer mask) routes are
 * first, while the less specific routes with shorter masks are last.
 * Within the same mask length, the routes are ordered by priority.
 * Hence, the first matching route in a linear iteration is the most
 * specific match. */
static void route_insert_sorted(struct osmo_ss7_route_table *rtbl,
				struct osmo_ss7_route *cmp)
{
	struct osmo_ss7_route *rt;

	llist_for_each_entry(rt, &rtbl->routes, list) {
		if (rt->cfg.mask == cmp->cfg.mask &&
		    rt->cfg.priority > cmp->cfg.priority) {
			/* insert before the current entry */
			llist_add(&cmp->list, rt->list.prev);
			return;
		}
		if (rt->cfg.mask < cmp->cfg.mask) {
			/* insert before the current entry */
			llist_add(&cmp->list, rt->list.prev);
			return;
		}
	}
	/* not added, i.e. no smaller mask length and priority found: we are the
	 * smallest mask and priority and thus should go last */
	llist_add_tail(&cmp->list, &rtbl->routes);
}

/*! \brief Insert route into its routing table
 *  \param[in] rt Route to be inserted into its routing table
 *  \returns 0 on success, negative on error
 *
 * A route is only really used once it has been inserted into its routing table.
 */
int
ss7_route_insert(struct osmo_ss7_route *rt)
{
	struct osmo_ss7_route *prev_rt;
	struct osmo_ss7_route_table *rtbl = rt->rtable;

	if (ss7_route_inserted(rt)) {
		LOGSS7(rtbl->inst, LOGL_ERROR, "Attempt insert of route already in the routing table!\n");
		return -EALREADY;
	}

	if (!rt->cfg.linkset_name) {
		LOGSS7(rtbl->inst, LOGL_ERROR, "Attempt insert of route with unset linkset!\n");
		return -EINVAL;
	}

	/* check for duplicates */
	prev_rt = ss7_route_table_find_route_by_dpc_mask(rtbl, rt->cfg.pc, rt->cfg.mask);
	if (prev_rt && !strcmp(prev_rt->cfg.linkset_name, rt->cfg.linkset_name)) {
		LOGSS7(rtbl->inst, LOGL_ERROR,
		       "Refusing to create route with existing linkset name: pc=%u=%s mask=0x%x via linkset/AS '%s'\n",
		       rt->cfg.pc, osmo_ss7_pointcode_print(rtbl->inst, rt->cfg.pc),
		       rt->cfg.mask, rt->cfg.linkset_name);
		return -EADDRINUSE;
	}

	route_insert_sorted(rtbl, rt);
	return 0;
}

/*! \brief Create a new route in the given routing table
 *  \param[in] rtbl Routing Table in which the route is to be created
 *  \param[in] pc Point Code of the destination of the route
 *  \param[in] mask Mask of the destination Point Code \ref pc
 *  \param[in] linkset_name string name of the linkset to be used
 *  \returns callee-allocated + initialized route, NULL on error
 *
 * The route allocated and returned by this API is already inserted into the
 * routing table, with priority and qos-class set to 0.
 * If you plan to use different values for priority and qos-class, avoid using
 * this API and use ss7_route_alloc() + ss7_route_set_linkset() +
 * ss7_route_insert() instead.
 */
struct osmo_ss7_route *
ss7_route_create(struct osmo_ss7_route_table *rtbl, uint32_t pc,
		      uint32_t mask, const char *linkset_name)
{
	struct osmo_ss7_route *rt;
	int rc;

	rt = ss7_route_alloc(rtbl, pc, mask);
	if (!rt)
		return NULL;

	if (ss7_route_set_linkset(rt, linkset_name) < 0) {
		talloc_free(rt);
		return NULL;
	}

	rc = ss7_route_insert(rt);
	/* Keep old behavior, return already existing route: */
	if (rc == -EADDRINUSE) {
		talloc_free(rt);
		return ss7_route_table_find_route_by_dpc_mask(rtbl, pc, mask);
	}

	return rt;
}

/*! \brief Destroy a given SS7 route */
void ss7_route_destroy(struct osmo_ss7_route *rt)
{
	OSMO_ASSERT(ss7_initialized);

	if (!rt)
		return;

	if (ss7_route_inserted(rt)) {
		struct osmo_ss7_instance *inst = rt->rtable->inst;
		LOGSS7(inst, LOGL_INFO,
			"Destroying route: pc=%u=%s mask=0x%x via linkset/ASP '%s'\n",
			rt->cfg.pc, osmo_ss7_pointcode_print(inst, rt->cfg.pc),
			rt->cfg.mask, rt->cfg.linkset_name);
		llist_del(&rt->list);
	}
	talloc_free(rt);
}

/* count number of consecutive leading (MSB) bits that are '1' */
static unsigned int count_leading_one_bits(uint32_t inp, unsigned int nbits)
{
	unsigned int i;

	for (i = 0; i < nbits; i++) {
		if (!(inp & (1 << (nbits-1-i))))
			return i;
	}
	return i;
}

/* determine the mask length in number of bits; negative if non-consecutive mask */
static int u32_masklen(uint32_t mask, unsigned int nbits)
{
	unsigned int i;
	unsigned int leading_one_bits = count_leading_one_bits(mask, nbits);

	/* are there any bits set after the initial bits? */
	for (i = leading_one_bits; i < nbits; i++) {
		if (mask & (1 << (nbits-1-i)))
			return -1; /* not a simple prefix mask */
	}
	return leading_one_bits;
}

const char *osmo_ss7_route_print(const struct osmo_ss7_route *rt)
{
	const struct osmo_ss7_instance *inst = rt->rtable->inst;
	unsigned int pc_width = osmo_ss7_pc_width(&inst->cfg.pc_fmt);
	static char buf[64];
	int rc = u32_masklen(rt->cfg.mask, pc_width);

	if (rc < 0)
		snprintf(buf, sizeof(buf), "%s/%s", osmo_ss7_pointcode_print(inst, rt->cfg.pc),
			 osmo_ss7_pointcode_print2(inst, rt->cfg.mask));
	else
		snprintf(buf, sizeof(buf), "%s/%u", osmo_ss7_pointcode_print(inst, rt->cfg.pc), rc);
	return buf;
}

/*! \brief Find a SS7 route for given destination point code in given SS7 */
struct osmo_ss7_route *
osmo_ss7_route_lookup(struct osmo_ss7_instance *inst, uint32_t dpc)
{
	OSMO_ASSERT(ss7_initialized);
	return ss7_route_table_find_route_by_dpc(inst->rtable_system, dpc);
}

/*! \brief Get destination AS of route
 *  \param[in] rt Route entry holding the AS destination
 *  \returns pointer to Application Server on success; NULL if rt doesn't route
 *  to an AS (i.e. routes to a linkset). */
struct osmo_ss7_as *
osmo_ss7_route_get_dest_as(struct osmo_ss7_route *rt)
{
	return rt->dest.as;
}
