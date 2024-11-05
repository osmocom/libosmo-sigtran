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
#include <osmocom/core/talloc.h>
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_user.h"
#include "ss7_internal.h"

/***********************************************************************
 * MTP Users (Users of MTP, such as SCCP or ISUP)
 ***********************************************************************/

struct osmo_ss7_user *osmo_ss7_user_create(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_user *user;
	user = talloc_zero(inst, struct osmo_ss7_user);
	if (!user)
		return NULL;

	user->inst = inst;
	user->name = talloc_strdup(user, name ? : "");
	return user;
}

void osmo_ss7_user_destroy(struct osmo_ss7_user *user)
{
	talloc_free(user);
}

struct osmo_ss7_instance *osmo_ss7_user_get_instance(const struct osmo_ss7_user *user)
{
	return user->inst;
}

void osmo_ss7_user_set_prim_cb(struct osmo_ss7_user *user, osmo_prim_cb prim_cb)
{
	user->prim_cb = prim_cb;
}

void osmo_ss7_user_set_priv(struct osmo_ss7_user *user, void *priv)
{
	user->priv = priv;
}

void *osmo_ss7_user_get_priv(const struct osmo_ss7_user *user)
{
	return user->priv;
}

/*! \brief Register a MTP user for a given service indicator
 *  \param[in] inst SS7 instance for which we register the user
 *  \param[in] service_ind Service (ISUP, SCCP, ...)
 *  \param[in] user SS7 user (including primitive call-back)
 *  \returns 0 on success; negative on error */
int osmo_ss7_user_register(struct osmo_ss7_instance *inst, uint8_t service_ind,
			   struct osmo_ss7_user *user)
{
	if (service_ind >= ARRAY_SIZE(inst->user))
		return -EINVAL;

	if (inst->user[service_ind])
		return -EBUSY;

	DEBUGP(DLSS7, "registering user=%s for SI %u with priv %p\n",
		user->name, service_ind, user->priv);

	user->inst = inst;
	inst->user[service_ind] = user;

	return 0;
}

/*! \brief Unregister a MTP user for a given service indicator
 *  \param[in] inst SS7 instance for which we register the user
 *  \param[in] service_ind Service (ISUP, SCCP, ...)
 *  \param[in] user (optional) SS7 user. If present, we will not
 *		unregister other users
 *  \returns 0 on success; negative on error */
int osmo_ss7_user_unregister(struct osmo_ss7_instance *inst, uint8_t service_ind,
			     struct osmo_ss7_user *user)
{
	if (service_ind >= ARRAY_SIZE(inst->user))
		return -EINVAL;

	if (!inst->user[service_ind])
		return -ENODEV;

	if (user && (inst->user[service_ind] != user))
		return -EINVAL;

	if (user)
		user->inst = NULL;
	inst->user[service_ind] = NULL;

	return 0;
}

/* deliver to a local MTP user */
int ss7_mtp_to_user(struct osmo_ss7_instance *inst, struct osmo_mtp_prim *omp)
{
	uint32_t service_ind;
	const struct osmo_ss7_user *osu;

	if (omp->oph.sap != MTP_SAP_USER ||
	    omp->oph.primitive != OSMO_MTP_PRIM_TRANSFER ||
	    omp->oph.operation != PRIM_OP_INDICATION) {
		LOGP(DLSS7, LOGL_ERROR, "Unsupported Primitive\n");
		return -EINVAL;
	}

	service_ind = omp->u.transfer.sio & 0xF;
	osu = inst->user[service_ind];

	if (!osu) {
		LOGP(DLSS7, LOGL_NOTICE, "No MTP-User for SI %u\n", service_ind);
		return -ENODEV;
	}

	DEBUGP(DLSS7, "delivering MTP-TRANSFER.ind to user %s, priv=%p\n",
		osu->name, osu->priv);
	return osu->prim_cb(&omp->oph, (void *) osu->priv);
}
