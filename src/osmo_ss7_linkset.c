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
#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_linkset.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"

/***********************************************************************
 * SS7 Linkset
 ***********************************************************************/

/*! \brief Destroy a SS7 Linkset
 *  \param[in] lset Linkset to be destroyed */
void ss7_linkset_destroy(struct osmo_ss7_linkset *lset)
{
	struct osmo_ss7_route *rt, *rt2;
	unsigned int i;

	OSMO_ASSERT(ss7_initialized);
	LOGSS7(lset->inst, LOGL_INFO, "Destroying Linkset %s\n",
		lset->cfg.name);

	/* find any routes pointing to this AS and remove them */
	llist_for_each_entry_safe(rt, rt2, &lset->inst->rtable_system->routes, list) {
		if (rt->dest.linkset == lset)
			ss7_route_destroy(rt);
	}

	for (i = 0; i < ARRAY_SIZE(lset->links); i++) {
		struct osmo_ss7_link *link = lset->links[i];
		if (!link)
			continue;
		osmo_ss7_link_destroy(link);
	}
	llist_del(&lset->list);
	talloc_free(lset);
}

/*! \brief Find SS7 Linkset by given name
 *  \param[in] inst SS7 Instance in which to look
 *  \param[in] name Name of SS7 Linkset
 *  \returns pointer to linkset on success; NULL on error */
struct osmo_ss7_linkset *
ss7_linkset_find_by_name(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_linkset *lset;
	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(lset, &inst->linksets, list) {
		if (!strcmp(name, lset->cfg.name))
			return lset;
	}
	return NULL;
}

/*! \brief Find or allocate SS7 Linkset
 *  \param[in] inst SS7 Instance in which we operate
 *  \param[in] name Name of SS7 Linkset
 *  \param[in] pc Adjacent Pointcode
 *  \returns pointer to Linkset on success; NULL on error */
struct osmo_ss7_linkset *
ss7_linkset_find_or_create(struct osmo_ss7_instance *inst, const char *name, uint32_t pc)
{
	struct osmo_ss7_linkset *lset;

	OSMO_ASSERT(ss7_initialized);
	lset = ss7_linkset_find_by_name(inst, name);
	if (lset && lset->cfg.adjacent_pc != pc)
		return NULL;

	if (!lset) {
		LOGSS7(inst, LOGL_INFO, "Creating Linkset %s\n", name);
		lset = talloc_zero(inst, struct osmo_ss7_linkset);
		lset->inst = inst;
		lset->cfg.adjacent_pc = pc;
		lset->cfg.name = talloc_strdup(lset, name);
		llist_add_tail(&lset->list, &inst->linksets);
	}

	return lset;
}
