/* SCCP User related routines */

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
#include "sccp_instance.h"
#include "sccp_internal.h"
#include "sccp_user.h"
#include "xua_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"
#include "ss7_xua_srv.h"

struct osmo_sccp_user *sccp_user_alloc(struct osmo_sccp_instance *inst, const char *name,
				       osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc)
{
	struct osmo_sccp_user *scu;

	scu = talloc_zero(inst, struct osmo_sccp_user);
	scu->name = talloc_strdup(scu, name);
	scu->inst = inst;
	scu->prim_cb = prim_cb;
	scu->ssn = ssn;
	scu->pc = pc;
	llist_add_tail(&scu->list, &inst->users);

	return scu;
}

static void sccp_user_flush_connections(struct osmo_sccp_user *scu)
{
	struct osmo_sccp_instance *inst = scu->inst;
	struct rb_node *node;

start:
	for (node = rb_first(&inst->connections); node; node = rb_next(node)) {
		struct sccp_connection *conn = container_of(node, struct sccp_connection, node);
		if (conn->user == scu) {
			sccp_conn_free(conn);
			/* node has been freed, rbtree has been changed, start again: */
			goto start;
		}
	}
}

void sccp_user_free(struct osmo_sccp_user *scu)
{
	if (!scu)
		return;
	sccp_user_flush_connections(scu);
	llist_del(&scu->list);
	talloc_free(scu);
}

/*! \brief Unbind a given SCCP user
 *  \param[in] scu SCCP User which is to be un-bound. Will be destroyed
 *  		at the time this function returns. */
void osmo_sccp_user_unbind(struct osmo_sccp_user *scu)
{
	LOGPSCU(scu, LOGL_INFO, "Unbinding user\n");
	sccp_user_free(scu);
}

void osmo_sccp_user_set_priv(struct osmo_sccp_user *scu, void *priv)
{
	scu->priv = priv;
}

void *osmo_sccp_user_get_priv(struct osmo_sccp_user *scu)
{
	return scu->priv;
}

/*! \brief Send a SCCP User SAP Primitive up to the User
 *  \param[in] scu SCCP User to whom to send the primitive
 *  \param[in] prim Primitive to send to the user
 *  \returns return value of the SCCP User's prim_cb() function
 *
 * Ownership of prim->oph->msg is passed to the user of the registered callback
 */
int sccp_user_prim_up(struct osmo_sccp_user *scu, struct osmo_scu_prim *prim)
{
	LOGPSCU(scu, LOGL_DEBUG, "Delivering to SCCP User: %s\n",
		osmo_scu_prim_name(&prim->oph));
	return scu->prim_cb(&prim->oph, scu);
}

/*! Compose a human readable string to describe the SCCP user's connection.
 * The output follows ['<scu.name>':]<local-sccp-addr>, e.g.  "'OsmoHNBW':RI=SSN_PC,PC=0.23.5,SSN=RANAP",
 * or just "RI=SSN_PC,PC=0.23.5,SSN=RANAP" if no scu->name is set.
 * This calls osmo_sccp_addr_name(), which returns a static buffer; hence calling this function and
 * osmo_sccp_addr_name() in the same printf statement is likely to conflict. */
const char *osmo_sccp_user_name(struct osmo_sccp_user *scu)
{
	static char buf[128];
	struct osmo_sccp_addr sca;
	/* Interestingly enough, the osmo_sccp_user stores an SSN and PC, but not in an osmo_sccp_addr
	 * struct. To be able to use osmo_sccp_addr_name(), we need to first create an osmo_sccp_addr. */
	osmo_sccp_make_addr_pc_ssn(&sca, scu->pc, scu->ssn);
	snprintf(buf, sizeof(buf),
		 "%s%s%s",
		 scu->name && *scu->name ? scu->name : "",
		 scu->name && *scu->name ? ":" : "",
		 osmo_sccp_addr_name(scu->inst->ss7, &sca));
	buf[sizeof(buf)-1] = '\0';
	return buf;
}

/*! \brief get the SCCP instance that is related to the given sccp user
 *  \param[in] scu SCCP user
 *  \returns SCCP instance; NULL if scu was NULL */
struct osmo_sccp_instance *osmo_sccp_get_sccp(const struct osmo_sccp_user *scu)
{
	if (!scu)
		return NULL;
	return scu->inst;
}
