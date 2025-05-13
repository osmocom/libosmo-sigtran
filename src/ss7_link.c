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

#include "ss7_link.h"
#include "ss7_linkset.h"
#include "ss7_internal.h"

/***********************************************************************
 * SS7 Link
 ***********************************************************************/

/*! \brief Destroy SS7 Link
 *  \param[in] link SS7 Link to be destroyed */
void ss7_link_destroy(struct osmo_ss7_link *link)
{
	struct osmo_ss7_linkset *lset = link->linkset;

	OSMO_ASSERT(ss7_initialized);
	LOGSS7(lset->inst, LOGL_INFO, "Destroying Link %s:%u\n",
		lset->cfg.name, link->cfg.id);
	/* FIXME: do cleanup */
	lset->links[link->cfg.id] = NULL;
	talloc_free(link);
}

/*! \brief Find or create SS7 Link with given ID in given Linkset
 *  \param[in] lset SS7 Linkset on which we operate
 *  \param[in] id Link number within Linkset
 *  \returns pointer to SS7 Link on success; NULL on error */
struct osmo_ss7_link *
ss7_link_find_or_create(struct osmo_ss7_linkset *lset, uint32_t id)
{
	struct osmo_ss7_link *link;

	OSMO_ASSERT(ss7_initialized);
	if (id >= ARRAY_SIZE(lset->links))
		return NULL;

	if (lset->links[id]) {
		link = lset->links[id];
	} else {
		LOGSS7(lset->inst, LOGL_INFO, "Creating Link %s:%u\n",
			lset->cfg.name, id);
		link = talloc_zero(lset, struct osmo_ss7_link);
		if (!link)
			return NULL;
		link->linkset = lset;
		lset->links[id] = link;
		link->cfg.id = id;
	}

	return link;
}

/* Whether link is available, ITU Q.704 section 3.2 */
bool
ss7_link_is_available(const struct osmo_ss7_link *link)
{
	/* TODO: manage operational availability of a link... */
	return link->cfg.adm_state == OSMO_SS7_LS_ENABLED;
}
