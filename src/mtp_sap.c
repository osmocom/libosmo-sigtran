/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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
#include <osmocom/sigtran/mtp_sap.h>

const struct value_string osmo_mtp_prim_type_names[] = {
	{ OSMO_MTP_PRIM_TRANSFER,	"MTP-TRANSFER" },
	{ OSMO_MTP_PRIM_PAUSE,		"MTP-PAUSE" },
	{ OSMO_MTP_PRIM_RESUME,		"MTP-RESUME" },
	{ OSMO_MTP_PRIM_STATUS,		"MTP-STATUS" },
	{ 0, NULL }
};

static char prim_name_buf[128];

static int mtp_prim_hdr_name_buf(char *buf, size_t buflen, const struct osmo_prim_hdr *oph)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	if (!oph) {
		OSMO_STRBUF_PRINTF(sb, "null");
		return sb.chars_needed;
	}

	OSMO_STRBUF_PRINTF(sb, "%s.%s",
			   osmo_mtp_prim_type_name(oph->primitive),
			   osmo_prim_operation_name(oph->operation));
	return sb.chars_needed;
}

char *osmo_mtp_prim_name(const struct osmo_prim_hdr *oph)
{
	mtp_prim_hdr_name_buf(prim_name_buf, sizeof(prim_name_buf), oph);
	return prim_name_buf;
}
