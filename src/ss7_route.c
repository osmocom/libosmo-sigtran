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

#include "ss7_combined_linkset.h"
#include "ss7_linkset.h"
#include "ss7_as.h"
#include "ss7_asp.h"
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
 *  \param[in] dynamic Whether the route is dynamic
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
 *
 * Dynamic routes are not configured by the user (VTY), and hence cannot be
 * removed by the user. Dynamic routes are not stored in the config and hence
 * they don't show up in eg "show running-config"; they can be listed using
 * specific VTY commands like "show cs7 instance 0 route".
 */
struct osmo_ss7_route *
ss7_route_alloc(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask, bool dynamic)
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
	rt->cfg.dyn_allocated = dynamic;
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


/*! \brief Insert route into its routing table
 *  \param[in] rt Route to be inserted into its routing table
 *  \returns 0 on success, negative on error
 *
 * A route is only really used once it has been inserted into its routing table.
 */
int
ss7_route_insert(struct osmo_ss7_route *rt)
{
	struct osmo_ss7_combined_linkset *clset;
	struct osmo_ss7_route_table *rtbl = rt->rtable;

	if (ss7_route_inserted(rt)) {
		LOGSS7(rtbl->inst, LOGL_ERROR, "Attempt insert of route already in the routing table!\n");
		return -EALREADY;
	}

	if (!rt->cfg.linkset_name) {
		LOGSS7(rtbl->inst, LOGL_ERROR, "Attempt insert of route with unset linkset!\n");
		return -EINVAL;
	}

	clset = ss7_route_table_find_combined_linkset(rtbl, rt->cfg.pc, rt->cfg.mask, rt->cfg.priority);
	if (clset) { /* check for duplicates */
		struct osmo_ss7_route *prev_rt;
		llist_for_each_entry(prev_rt, &clset->routes, list) {
			if (strcmp(prev_rt->cfg.linkset_name, rt->cfg.linkset_name) == 0 &&
			    prev_rt->cfg.dyn_allocated == rt->cfg.dyn_allocated) {
				LOGSS7(rtbl->inst, LOGL_ERROR,
				       "Refusing to create route with existing linkset name: pc=%u=%s mask=0x%x via linkset/AS '%s'\n",
				       rt->cfg.pc, osmo_ss7_pointcode_print(rtbl->inst, rt->cfg.pc),
				       rt->cfg.mask, rt->cfg.linkset_name);
				return -EADDRINUSE;
			}
		}
	} else {
		clset = ss7_combined_linkset_alloc(rtbl, rt->cfg.pc, rt->cfg.mask, rt->cfg.priority);
		OSMO_ASSERT(clset);
	}

	ss7_combined_linkset_add_route(clset, rt);
	return 0;
}

/*! \brief Create a new route in the given routing table
 *  \param[in] rtbl Routing Table in which the route is to be created
 *  \param[in] pc Point Code of the destination of the route
 *  \param[in] mask Mask of the destination Point Code \ref pc
 *  \param[in] dynamic Whether the route is dynamic
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
		 uint32_t mask, bool dynamic, const char *linkset_name)
{
	struct osmo_ss7_route *rt;
	int rc;

	rt = ss7_route_alloc(rtbl, pc, mask, dynamic);
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
		return ss7_route_table_find_route_by_dpc_mask(rtbl, pc, mask, dynamic);
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
		ss7_combined_linkset_del_route(rt);
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
	static char buf[64];
	struct osmo_strbuf sb = { .buf = buf, .len = sizeof(buf) };
	char buf_pc[MAX_PC_STR_LEN];
	const struct osmo_ss7_instance *inst = rt->rtable->inst;
	unsigned int pc_width = osmo_ss7_pc_width(&inst->cfg.pc_fmt);
	int rc = u32_masklen(rt->cfg.mask, pc_width);

	OSMO_STRBUF_PRINTF(sb, "%s/", osmo_ss7_pointcode_print_buf(buf_pc, sizeof(buf_pc), inst, rt->cfg.pc));

	if (rc < 0)
		OSMO_STRBUF_PRINTF(sb, "%s", osmo_ss7_pointcode_print_buf(buf_pc, sizeof(buf_pc), inst, rt->cfg.mask));
	else
		OSMO_STRBUF_PRINTF(sb, "%u", rc);
	return buf;
}

/*! Return human readable representation of the route, in a static buffer.
 * This uses both osmo_ss7_pointcode_print() and osmo_ss7_pointcode_print2(), so pairing
 * osmo_ss7_route_name() with osmo_ss7_pointcode_print() in the same printf statement is likely to
 * conflict.
 * \param[in] rt  The route information to print, or NULL.
 * \param[in] list_asps  If true, append info for all ASPs for the route's AS.
 * \returns A string constant or static buffer. */
const char *osmo_ss7_route_name(struct osmo_ss7_route *rt, bool list_asps)
{
	static char buf[256];
	char pc_str[MAX_PC_STR_LEN];
	char mask_str[MAX_PC_STR_LEN];
	char *pos = buf;
	struct osmo_ss7_instance *inst;
	size_t l;

	if (!rt)
		return "no route";

	inst = rt->rtable->inst;

#define APPEND(fmt, args ...) \
	do { \
		l = snprintf(pos, sizeof(buf) - (pos - buf), fmt, ## args); \
		pos += l; \
		if (pos - buf >= sizeof(buf)) \
			goto out; \
	} while (0)

	APPEND("pc=%u=%s mask=0x%x=%s prio=%u",
	       rt->cfg.pc, osmo_ss7_pointcode_print_buf(pc_str, sizeof(pc_str), inst, rt->cfg.pc),
	       rt->cfg.mask, osmo_ss7_pointcode_print_buf(mask_str, sizeof(mask_str), inst, rt->cfg.mask),
	       rt->cfg.priority);

	if (rt->cfg.dyn_allocated)
		APPEND(" dyn");

	if (rt->dest.as) {
		struct osmo_ss7_as *as = rt->dest.as;
		int i;
		APPEND(" via AS %s proto=%s", as->cfg.name, osmo_ss7_asp_protocol_name(as->cfg.proto));

		if (list_asps) {
			for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
				struct osmo_ss7_asp *asp = as->cfg.asps[i];
				if (!asp)
					continue;
				APPEND(" ASP");
				if (asp->cfg.name)
					APPEND(" %s", asp->cfg.name);
				if (asp->sock_name)
					APPEND(" %s", asp->sock_name);
			}
		}
	} else if (rt->dest.linkset)
		APPEND(" via linkset %s", rt->dest.linkset->cfg.name);
	else
		APPEND(" has no route set");
#undef APPEND

out:
	buf[sizeof(buf)-1] = '\0';
	return buf;
}

/*! \brief Find a SS7 route for given destination point code in given SS7
 *
 *   NOTE: DEPRECATED, use ss7_instance_lookup_route() instead
 */
struct osmo_ss7_route *
osmo_ss7_route_lookup(struct osmo_ss7_instance *inst, uint32_t dpc)
{
	OSMO_ASSERT(ss7_initialized);
	struct osmo_ss7_route_label rtlb = {
		.opc = 0,
		.dpc = dpc,
		.sls = 0,
	};

	return ss7_instance_lookup_route(inst, &rtlb);
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

/* Whether route is available, ITU Q.704 */
bool ss7_route_is_available(const struct osmo_ss7_route *rt)
{
	OSMO_ASSERT(rt);
	if (rt->dest.as)
		return osmo_ss7_as_active(rt->dest.as);
	if (rt->dest.linkset)
		return ss7_linkset_is_available(rt->dest.linkset);
	return false;
}
