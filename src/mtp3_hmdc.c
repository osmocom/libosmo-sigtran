/***********************************************************************
 * MTP Level 3 - Message Discrimination (HMDC), ITU Q.704 Figure 24
 ***********************************************************************/

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <stdint.h>

#include <osmocom/core/logging.h>

#include "mtp3_hmdc.h"
#include "mtp3_hmdt.h"
#include "mtp3_hmrt.h"
#include "ss7_instance.h"
#include "xua_msg.h"


/* HMDC: Received Message L2 -> L3; Figure 24/Q.704 */
/* This means a message was received from L2 and we have to decide if it
 * is for the local stack (HMDT) or for routng (HMRT)
 * Ownership of xua_msg passed is transferred to this function. */
int mtp3_hmdc_rx_from_l2(struct osmo_ss7_instance *inst, struct xua_msg *xua)
{
	uint32_t dpc = xua->mtp.dpc;
	if (osmo_ss7_pc_is_local(inst, dpc)) {
		LOGSS7(inst, LOGL_DEBUG, "%s(): found dpc=%u=%s as local\n",
		       __func__, dpc, osmo_ss7_pointcode_print(inst, dpc));
		return mtp3_hmdt_message_for_distribution(inst, xua);
	}
	LOGSS7(inst, LOGL_DEBUG, "%s(): dpc=%u=%s not local, message is for routing\n",
		__func__, dpc, osmo_ss7_pointcode_print(inst, dpc));
	return mtp3_hmrt_message_for_routing(inst, xua);
}
