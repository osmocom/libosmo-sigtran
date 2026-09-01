/* Shared code between M3UA and SUA implementation */

/* (C) 2015-2021 by Harald Welte <laforge@gnumonks.org>
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
#include <unistd.h>
#include <string.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/logging.h>

#include "xua_msg.h"

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/m3ua.h>
#include <osmocom/sigtran/protocol/sua.h>

#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_internal.h"
#include "xua_internal.h"

/* this is why we can use the M3UA constants below in a function shared between M3UA + SUA */
osmo_static_assert(M3UA_ERR_INVAL_ROUT_CTX == SUA_ERR_INVAL_ROUT_CTX, _err_rctx);
osmo_static_assert(M3UA_ERR_NO_CONFGD_AS_FOR_ASP == SUA_ERR_NO_CONFGD_AS_FOR_ASP, _err_as_for_asp);
osmo_static_assert(M3UA_ERR_PARAM_FIELD_ERR == SUA_ERR_PARAM_FIELD_ERR, _err_param_field_err);
osmo_static_assert(M3UA_ERR_UNEXP_PARAM == SUA_ERR_UNEXP_PARAM, _err_unexp_param);

static int xua_find_as_for_asp_no_rctx(struct osmo_ss7_as **as, const struct osmo_ss7_asp *asp)
{
	int log_ss = osmo_ss7_asp_get_log_subsys(asp);
	*as = NULL;
	if (asp->num_assoc_as != 1) {
		LOGPASP(asp, log_ss, LOGL_ERROR,
			"%s(): ASP sent M3UA without Routing Context IE but unable to uniquely "
			"identify the AS for this message\n", __func__);
		return M3UA_ERR_INVAL_ROUT_CTX;
	}
	*as = ss7_asp_get_first_as(asp);
	OSMO_ASSERT(*as);
	return 0;
}
/*! Find the AS for given ASP + optional routing context IE.
 *
 *  \param[out] as caller-provided address-of-pointer to store the found AS
 *  \param[in] asp ASP for which we want to look-up the AS
 *  \param[in] rctx_ie routing context IE (may be NULL) to use for look-up
 *  \returns 0 in case of success; {M3UA,SUA}_ERR_* code in case of error.
 *
 *  if rctx_ie == NULL, we assume that this ASP is only part of a single AS;
 *  if rctx_ie is given, then we look-up the AS on the ASP based on the routing context.
 */
int xua_find_as_for_asp(struct osmo_ss7_as **as, const struct osmo_ss7_asp *asp,
			const struct xua_msg_part *rctx_ie)
{
	int log_ss;

	if (!rctx_ie)
		return xua_find_as_for_asp_no_rctx(as, asp);

	log_ss = osmo_ss7_asp_get_log_subsys(asp);
	*as = NULL;

	if (rctx_ie->len < 4) {
		LOGPASP(asp, log_ss, LOGL_ERROR, "%s(): Received Routing Context with len < 4\n", __func__);
		return M3UA_ERR_PARAM_FIELD_ERR;
	}
	/* Use routing context IE to look up the AS for which the
	 * message was received. */
	uint32_t rctx = xua_msg_part_get_u32(rctx_ie);
	*as = ss7_asp_find_as_by_rctx(asp, rctx);
	if (!*as) {
		LOGPASP(asp, log_ss, LOGL_ERROR,
			"%s(): This Application Server Process is not serving any AS with routing context: %u\n",
			__func__, rctx);
		return M3UA_ERR_NO_CONFGD_AS_FOR_ASP;
	}
	return 0;
}

/*! Find multiple AS for given ASP + optional routing context IE.
 *  \param[out] as_array caller-provided address of array to store the found ASs.
 *			 Usually of OSMO_SS7_MAX_RCTX_COUNT elements.
 *  \param[out] as_array_count filled by the callee, contains number of elements filled in as_array
 *  \param[in] as_array_len caller provided, provides the amount of elements allocated in as_array.
 *			    Usually OSMO_SS7_MAX_RCTX_COUNT.
 *  \param[in] asp ASP for which we want to look-up the AS
 *  \param[in] rctx_ie routing context IE (may be NULL) to use for look-up
 *  \returns 0 in case of success; {M3UA,SUA}_ERR_* code in case of error.
 *
 *  if rctx_ie == NULL, we assume that this ASP is only psart of a single AS;
 *  if rctx_ie is given, then we look-up the ASs on the ASP based on the routing contexts.
 *  This function always returns at least one AS in the as_array if it succeeds.
 **/
int xua_find_multiple_as_for_asp(struct osmo_ss7_as **as_array,
				 unsigned int *as_array_count,
				 unsigned int as_array_len,
				 const struct osmo_ss7_asp *asp,
				 const struct xua_msg_part *rctx_ie)
{
	int log_ss;
	unsigned int rctx_count = 0;
	*as_array_count = 0;

	if (!rctx_ie) {
		int rc = xua_find_as_for_asp_no_rctx(&as_array[0], asp);
		if (rc == 0)
			*as_array_count = 1;
		return rc;
	}

	log_ss = osmo_ss7_asp_get_log_subsys(asp);

	if (rctx_ie->len == 0) {
		LOGPASP(asp, log_ss, LOGL_ERROR, "%s(): Received Routing Context with len 0\n", __func__);
		return M3UA_ERR_PARAM_FIELD_ERR;
	}

	if (rctx_ie->len & 0x03) {
		LOGPASP(asp, log_ss, LOGL_ERROR,
			"%s(): Received Routing Context IE length non-multiple of 4!\n", __func__);
		return M3UA_ERR_PARAM_FIELD_ERR;
	}

	rctx_count = rctx_ie->len >> 2;
	if (rctx_count > as_array_len) {
		LOGP(DLM3UA, LOGL_ERROR,
			"%s(): Received Routing Context IE containing > %u items not supported!\n",
			__func__, as_array_len);
		return M3UA_ERR_UNEXP_PARAM;
	}

	for (unsigned int i = 0; i < rctx_count; i++) {
		/* Use routing context IE to look up the AS for which the message was received. */
		uint32_t rctx = ntohl(*(uint32_t *)&rctx_ie->dat[i << 2]);

		as_array[*as_array_count] = ss7_asp_find_as_by_rctx(asp, rctx);
		if (!as_array[*as_array_count]) {
			LOGPASP(asp, log_ss, LOGL_ERROR,
				"%s(): This Application Server Process is not serving any AS with routing context: %u\n",
				__func__, rctx);
			return M3UA_ERR_NO_CONFGD_AS_FOR_ASP;
		}
		(*as_array_count)++;
	}
	return 0;
}
