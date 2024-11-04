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

#include "ss7_route_table.h"
#include "ss7_internal.h"

/***********************************************************************
 * SS7 Route Tables
 ***********************************************************************/

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
	if (!rtbl) {
		LOGSS7(inst, LOGL_INFO, "Creating Route Table %s\n", name);
		rtbl = talloc_zero(inst, struct osmo_ss7_route_table);
		rtbl->inst = inst;
		rtbl->cfg.name = talloc_strdup(rtbl, name);
		INIT_LLIST_HEAD(&rtbl->routes);
		llist_add_tail(&rtbl->list, &inst->rtable_list);
	}
	return rtbl;
}

void
ss7_route_table_destroy(struct osmo_ss7_route_table *rtbl)
{
	llist_del(&rtbl->list);
	/* routes are allocated as children of route table, will be
	 * automatically freed() */
	talloc_free(rtbl);
}

/*! \brief Find a SS7 route for given destination point code in given table */
struct osmo_ss7_route *
ss7_route_table_find_route_by_dpc(struct osmo_ss7_route_table *rtbl, uint32_t dpc)
{
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(ss7_initialized);

	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);

	/* we assume the routes are sorted by mask length, i.e. more
	 * specific routes first, and less specific routes with shorter
	 * mask later */
	llist_for_each_entry(rt, &rtbl->routes, list) {
		if ((dpc & rt->cfg.mask) == rt->cfg.pc)
			return rt;
	}
	return NULL;
}

/*! \brief Find a SS7 route for given destination point code + mask in given table */
struct osmo_ss7_route *
ss7_route_table_find_route_by_dpc_mask(struct osmo_ss7_route_table *rtbl, uint32_t dpc,
				uint32_t mask)
{
	struct osmo_ss7_route *rt;

	OSMO_ASSERT(ss7_initialized);
	mask = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, mask);
	dpc = osmo_ss7_pc_normalize(&rtbl->inst->cfg.pc_fmt, dpc);

	/* we assume the routes are sorted by mask length, i.e. more
	 * specific routes first, and less specific routes with shorter
	 * mask later */
	llist_for_each_entry(rt, &rtbl->routes, list) {
		if (dpc == rt->cfg.pc && mask == rt->cfg.mask)
			return rt;
	}
	return NULL;
}
