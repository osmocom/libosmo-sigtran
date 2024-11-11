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

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_combined_linkset.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"

/***********************************************************************
 * SS7 Route Tables
 ***********************************************************************/

static struct osmo_ss7_route_table *ss7_route_table_alloc(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_route_table *rtbl;

	OSMO_ASSERT(name);
	LOGSS7(inst, LOGL_INFO, "Creating Route Table %s\n", name);

	rtbl = talloc_zero(inst, struct osmo_ss7_route_table);
	OSMO_ASSERT(rtbl);

	rtbl->inst = inst;
	rtbl->cfg.name = talloc_strdup(rtbl, name);
	INIT_LLIST_HEAD(&rtbl->combined_linksets);
	llist_add_tail(&rtbl->list, &inst->rtable_list);
	return rtbl;
}

struct osmo_ss7_route_table *
ss7_route_table_find(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_route_table *rtbl;
	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(rtbl, &inst->rtable_list, list) {
		if (!strcmp(rtbl->cfg.name, name))
			return rtbl;
	}
	return NULL;
}

struct osmo_ss7_route_table *
ss7_route_table_find_or_create(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_route_table *rtbl;

	OSMO_ASSERT(ss7_initialized);
	rtbl = ss7_route_table_find(inst, name);
	if (!rtbl)
		rtbl = ss7_route_table_alloc(inst, name);
	return rtbl;
}

void
ss7_route_table_destroy(struct osmo_ss7_route_table *rtbl)
{
	llist_del(&rtbl->list);
	/* combined links & routes are allocated as children of route table,
	 * will be automatically freed() */
	talloc_free(rtbl);
}

/*! \brief Find a SS7 route for given destination point code in given table */
struct osmo_ss7_route *
ss7_route_table_find_route_by_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc)
{
	struct osmo_ss7_combined_linkset *clset;
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(ss7_initialized);

	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);

	clset = ss7_route_table_find_combined_linkset_by_dpc(rtbl, dpc);
	if (!clset)
		return NULL;
	rt = llist_first_entry_or_null(&clset->routes, struct osmo_ss7_route, list);
	return rt;
}

/*! \brief Find a SS7 route for given destination point code + mask in given table */
struct osmo_ss7_route *
ss7_route_table_find_route_by_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
				uint32_t mask)
{
	struct osmo_ss7_combined_linkset *clset;
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(ss7_initialized);

	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);
	mask = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, mask);

	clset = ss7_route_table_find_combined_linkset_by_dpc_mask(rtbl, dpc, mask);
	if (!clset)
		return NULL;
	rt = llist_first_entry_or_null(&clset->routes, struct osmo_ss7_route, list);
	return rt;
}

struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset_by_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc)
{
	struct osmo_ss7_combined_linkset *clset;

	OSMO_ASSERT(ss7_initialized);

	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);
	/* we assume the combined_links are sorted by mask length, i.e. more
	 * specific combined links first, and less specific combined links with shorter
	 * mask later */
	llist_for_each_entry(clset, &rtbl->combined_linksets, list) {
		if ((dpc & clset->cfg.mask) != clset->cfg.pc)
			continue;
		return clset;
	}
	return NULL;
}

struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset_by_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask)
{
	struct osmo_ss7_combined_linkset *clset;

	OSMO_ASSERT(ss7_initialized);

	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);
	/* we assume the combined_links are sorted by mask length, i.e. more
	 * specific combined links first, and less specific combined links with shorter
	 * mask later */
	llist_for_each_entry(clset, &rtbl->combined_linksets, list) {
		if ((dpc & clset->cfg.mask) != clset->cfg.pc)
			continue;
		if (mask != clset->cfg.mask)
			continue;
		return clset;
	}
	return NULL;
}

struct osmo_ss7_combined_linkset *
ss7_route_table_find_combined_linkset(struct osmo_ss7_route_table *rtbl, uint32_t dpc, uint32_t mask, uint32_t prio)
{
	struct osmo_ss7_combined_linkset *clset;

	/* we assume the combined_links are sorted by mask length, i.e. more
	 * specific routes first, and less specific routes with shorter
	 * mask later */
	llist_for_each_entry(clset, &rtbl->combined_linksets, list) {
		if (mask < clset->cfg.mask)
			break;
		if (dpc == clset->cfg.pc && mask == clset->cfg.mask) {
			if (prio > clset->cfg.priority)
				break;
			if (prio == clset->cfg.priority)
				return clset;
		}
	}
	return NULL;
}

struct osmo_ss7_combined_linkset *
ss7_route_table_find_or_create_combined_linkset(struct osmo_ss7_route_table *rtable, uint32_t pc, uint32_t mask, uint32_t prio)
{
	struct osmo_ss7_combined_linkset *clset;
	clset = ss7_route_table_find_combined_linkset(rtable, pc, mask, prio);
	if (!clset)
		clset = ss7_combined_linkset_alloc(rtable, pc, mask, prio);
	return clset;
}

/* find any routes pointing to this AS and remove them */
void ss7_route_table_del_routes_by_as(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_as *as)
{
	struct osmo_ss7_combined_linkset *clset, *clset2;

	llist_for_each_entry_safe(clset, clset2, &rtbl->combined_linksets, list) {
		struct osmo_ss7_route *rt;
		llist_for_each_entry(rt, &clset->routes, list) {
			if (rt->dest.as == as) {
				ss7_route_destroy(rt);
				/* clset may have been freed here. Same AS can't be twice in a combined
				 * linkset, so simply continue iterating in the upper loop. */
				break;
			}
		}
	}
}

/* find any routes pointing to this linkset and remove them */
void ss7_route_table_del_routes_by_linkset(struct osmo_ss7_route_table *rtbl, struct osmo_ss7_linkset *lset)
{
	struct osmo_ss7_combined_linkset *clset, *clset2;

	llist_for_each_entry_safe(clset, clset2, &rtbl->combined_linksets, list) {
		struct osmo_ss7_route *rt;
		llist_for_each_entry(rt, &clset->routes, list) {
			if (rt->dest.linkset == lset) {
				ss7_route_destroy(rt);
				/* clset may have been freed here. Same linkset can't be twice in a combined
				 * linkset, so simply continue iterating in the upper loop. */
				break;
			}
		}
	}
}
