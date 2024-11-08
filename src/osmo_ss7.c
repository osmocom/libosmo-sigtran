/* Core SS7 Instance/Linkset/Link/AS/ASP Handling */

/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/sctp.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/mtp_sap.h>
#include <osmocom/sigtran/protocol/mtp.h>
#include <osmocom/sigtran/protocol/sua.h>
#include <osmocom/sigtran/protocol/m3ua.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/select.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/sockaddr_str.h>

#include <osmocom/netif/stream.h>
#include <osmocom/netif/ipa.h>
#include <osmocom/netif/sctp.h>

#include "sccp_internal.h"
#include "xua_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_internal.h"
#include "ss7_linkset.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "xua_asp_fsm.h"
#include "xua_as_fsm.h"

bool ss7_initialized = false;

LLIST_HEAD(osmo_ss7_instances);
/* This API allows iterating over the public global list of ss7 instances,
 * without knowing the structure internal layout.
 */
struct osmo_ss7_instance *osmo_ss7_instances_llist_entry(struct llist_head *list)
{
	struct osmo_ss7_instance *pos;
	pos = llist_entry(list, struct osmo_ss7_instance, list);
	return pos;
}

const struct value_string mtp_unavail_cause_vals[] = {
	{ MTP_UNAVAIL_C_UNKNOWN,		"unknown" },
	{ MTP_UNAVAIL_C_UNEQUIP_REM_USER,	"unequipped-remote-user" },
	{ MTP_UNAVAIL_C_INACC_REM_USER,		"inaccessible-remote-user" },
	{ 0, NULL }
};

/***********************************************************************
 * SS7 Point Code Parsing / Printing
 ***********************************************************************/

/* get the total width (in bits) of the point-codes in this ss7_instance */
uint8_t osmo_ss7_pc_width(const struct osmo_ss7_pc_fmt *pc_fmt)
{
	return pc_fmt->component_len[0] + pc_fmt->component_len[1] + pc_fmt->component_len[2];
}

/* truncate pc or mask to maximum permitted length. This solves
 * callers specifying arbitrary large masks which then evade duplicate
 * detection with longer mask lengths */
uint32_t osmo_ss7_pc_normalize(const struct osmo_ss7_pc_fmt *pc_fmt, uint32_t pc)
{
	uint32_t mask = (1 << osmo_ss7_pc_width(pc_fmt))-1;
	return pc & mask;
}

/***********************************************************************
 * SS7 Instance
 ***********************************************************************/

/*! \brief Find a SS7 Instance with given ID
 *  \param[in] id ID for which to search
 *  \returns \ref osmo_ss7_instance on success; NULL on error */
struct osmo_ss7_instance *
osmo_ss7_instance_find(uint32_t id)
{
	OSMO_ASSERT(ss7_initialized);

	struct osmo_ss7_instance *inst;
	llist_for_each_entry(inst, &osmo_ss7_instances, list) {
		if (inst->cfg.id == id)
			return inst;
	}
	return NULL;
}

/*! \brief Find or create a SS7 Instance
 *  \param[in] ctx talloc allocation context to use for allocations
 *  \param[in] id ID of SS7 Instance
 *  \returns \ref osmo_ss7_instance on success; NULL on error */
struct osmo_ss7_instance *
osmo_ss7_instance_find_or_create(void *ctx, uint32_t id)
{
	struct osmo_ss7_instance *inst;

	OSMO_ASSERT(ss7_initialized);

	inst = osmo_ss7_instance_find(id);
	if (!inst)
		inst = ss7_instance_alloc(ctx, id);
	return inst;
}

bool ss7_ipv6_sctp_supported(const char *host, bool bind)
{
	int rc;
	struct addrinfo hints;
	struct addrinfo *result;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_NUMERICHOST;
	hints.ai_protocol = 0; /* Any protocol */

	if (bind)  /* For wildcard IP address */
		hints.ai_flags |= AI_PASSIVE;

	/* man getaddrinfo: Either node or service, but not both, may be NULL. */
	OSMO_ASSERT(host);
	rc = getaddrinfo(host, NULL, &hints, &result);
	if (rc != 0) {
		LOGP(DLSS7, LOGL_NOTICE, "Default IPv6 address %s not supported: %s\n",
		     host, gai_strerror(rc));
		return false;
	}
	freeaddrinfo(result);
	return true;
}

int osmo_ss7_init(void)
{
	int rc;

	if (ss7_initialized)
		return 1;
	rc = osmo_fsm_register(&sccp_scoc_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&xua_as_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&xua_asp_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&ipa_asp_fsm);
	if (rc < 0)
		return rc;
	rc = osmo_fsm_register(&xua_default_lm_fsm);
	if (rc < 0)
		return rc;

	ss7_initialized = true;
	return 0;
}

int osmo_ss7_tmode_to_xua(enum osmo_ss7_as_traffic_mode tmod)
{
	switch (tmod) {
	case OSMO_SS7_AS_TMOD_OVERRIDE:
		return M3UA_TMOD_OVERRIDE;
	case OSMO_SS7_AS_TMOD_LOADSHARE:
		return M3UA_TMOD_LOADSHARE;
	case OSMO_SS7_AS_TMOD_BCAST:
		return M3UA_TMOD_BCAST;
	default:
		return -1;
	}
}

enum osmo_ss7_as_traffic_mode osmo_ss7_tmode_from_xua(uint32_t in)
{
	switch (in) {
	case M3UA_TMOD_OVERRIDE:
		return OSMO_SS7_AS_TMOD_OVERRIDE;
	case M3UA_TMOD_LOADSHARE:
		return OSMO_SS7_AS_TMOD_LOADSHARE;
	case M3UA_TMOD_BCAST:
		return OSMO_SS7_AS_TMOD_BCAST;
	default:
		OSMO_ASSERT(false);
	}
}
