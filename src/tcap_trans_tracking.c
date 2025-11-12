/* TCAP transaction cache */

/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 * Author: Alexander Couzens <lynxis@fe80.eu>
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

#include <osmocom/core/msgb.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>

#include "ss7_asp.h"
#include "ss7_as.h"
#include "tcap_trans_tracking.h"


static inline void entry_update_tstamp(struct tcap_trans_track_entry *entry)
{
	struct timespec now;
	int rc;

	rc = osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	OSMO_ASSERT(rc >= 0);

	entry->tstamp = now.tv_sec;
}

static inline uint64_t gen_hash(uint32_t tid, uint8_t ssn, uint32_t pc)
{
	return ((uint64_t)tid << 32) | ssn | (pc & (0xffffff));
}

static inline uint64_t gen_hash_addr(uint32_t tid, const struct osmo_sccp_addr *addr)
{
	uint8_t ssn = 0;
	uint32_t pc = 0;

	if (addr->presence & OSMO_SCCP_ADDR_T_PC)
		pc = addr->pc;

	if (addr->presence & OSMO_SCCP_ADDR_T_SSN)
		ssn = addr->ssn;

	return gen_hash(tid, ssn, pc);
}

static void trans_sccp_addr_cpy(struct osmo_sccp_addr *dst, const struct osmo_sccp_addr *src)
{
	/* FIXME: reduce the sccp_addr in the txact tracking? */
	memset(dst, 0, sizeof(*dst));
	dst->presence = src->presence & (OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC);

	if (src->presence & OSMO_SCCP_ADDR_T_SSN)
		dst->ssn = src->ssn;

	if (src->presence & OSMO_SCCP_ADDR_T_PC)
		dst->pc = src->pc;
}

struct tcap_trans_track_entry *tcap_trans_track_entry_create(
		struct osmo_ss7_as *as,
		struct osmo_ss7_asp *asp,
		const struct osmo_sccp_addr *own_addr,
		const uint32_t *own_tid,
		const struct osmo_sccp_addr *peer_addr,
		const uint32_t *peer_tid)
{
	char own_pc[MAX_PC_STR_LEN], peer_pc[MAX_PC_STR_LEN];
	struct tcap_trans_track_entry *entry;

	OSMO_ASSERT(own_addr);
	OSMO_ASSERT(peer_addr);
	OSMO_ASSERT(own_tid || peer_tid);
	entry = talloc_zero(as, struct tcap_trans_track_entry);
	if (!entry)
		return NULL;

	entry->asp = asp;

	entry->own_addr = talloc_zero(entry, struct osmo_sccp_addr);
	if (!entry->own_addr)
		goto err;

	trans_sccp_addr_cpy(entry->own_addr, own_addr);
	if (own_tid) {
		entry->own_tid.tid_valid = true;
		entry->own_tid.tid = *own_tid;
		hash_add(as->tcap.trans_track_own, &entry->own_tid.list, gen_hash_addr(*own_tid, own_addr));
	}

	entry->peer_addr = talloc_zero(entry, struct osmo_sccp_addr);
	if (!entry->peer_addr)
		goto err_own;

	trans_sccp_addr_cpy(entry->peer_addr, peer_addr);
	if (peer_tid) {
		entry->peer_tid.tid_valid = true;
		entry->peer_tid.tid = *peer_tid;
		hash_add(as->tcap.trans_track_peer, &entry->peer_tid.list, gen_hash_addr(*peer_tid, peer_addr));
	}

	entry_update_tstamp(entry);
	/* TODO: optimisation: add a llist to asp to allow cleaning it up easier */


	LOGPASP(entry->asp, DLSS7, LOGL_DEBUG, "Creating tcap cache, entry (own) pc/ssn/tid %s/%u/%u -> %s/%u/%u\n",
		osmo_ss7_pointcode_print_buf(own_pc, sizeof(own_pc), as->inst, entry->own_addr->pc),
		entry->own_addr->ssn, entry->own_tid.tid,
		osmo_ss7_pointcode_print_buf(peer_pc, sizeof(peer_pc), as->inst, entry->peer_addr->pc),
		entry->peer_addr->ssn, entry->peer_tid.tid);

	return entry;

err_own:
	if (entry->own_tid.tid_valid)
		hash_del(&entry->own_tid.list);
err:
	talloc_free(entry);
	return NULL;
}

void tcap_trans_track_entry_free(struct tcap_trans_track_entry *entry)
{
	if (!entry)
		return;

	if (entry->own_tid.tid_valid)
		hash_del(&entry->own_tid.list);

	if (entry->peer_tid.tid_valid)
		hash_del(&entry->peer_tid.list);

	talloc_free(entry);
}

struct tcap_trans_track_entry *tcap_trans_track_entry_find(
		struct osmo_ss7_as *as,
		const struct osmo_sccp_addr *own_addr,
		const uint32_t *own_tid,
		const struct osmo_sccp_addr *peer_addr,
		const uint32_t *peer_tid)
{
	struct tcap_trans_track_entry *entry = NULL;
	OSMO_ASSERT(own_tid || peer_tid);

	/* TODO: possible optimisation: deref own_tid / peer_tid once here?
	 *       or does the compiler figure this out on its own?
	 */

	if (own_tid && !peer_tid) {
		hash_for_each_possible(as->tcap.trans_track_own, entry, own_tid.list, gen_hash_addr(*own_tid, own_addr)) {
			if (entry->own_tid.tid != *own_tid)
				continue;

			if (osmo_sccp_addr_cmp(entry->own_addr, own_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC) ||
			    osmo_sccp_addr_cmp(entry->peer_addr, peer_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
				continue;

			return entry;
		}

		return NULL;
	}

	if (!own_tid && peer_tid) {
		hash_for_each_possible(as->tcap.trans_track_peer, entry, peer_tid.list, gen_hash_addr(*peer_tid, peer_addr)) {
			if (entry->peer_tid.tid != *peer_tid)
				continue;

			if (osmo_sccp_addr_cmp(entry->own_addr, own_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC) ||
			    osmo_sccp_addr_cmp(entry->peer_addr, peer_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
				continue;

			return entry;
		}

		return NULL;
	}

	/* if (own_tid && peer_tid) */
	hash_for_each_possible(as->tcap.trans_track_own, entry, own_tid.list, gen_hash_addr(*own_tid, own_addr)) {
		if (entry->own_tid.tid != *own_tid)
			continue;

		if (entry->peer_tid.tid_valid && (entry->peer_tid.tid != *peer_tid))
			continue;

		if (osmo_sccp_addr_cmp(entry->own_addr, own_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC) ||
		    osmo_sccp_addr_cmp(entry->peer_addr, peer_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
			continue;

		/* tid is either not set in the entry or equals */
		return entry;
	}

	/* only check for remaining entries which don't have an own_tid */
	hash_for_each_possible(as->tcap.trans_track_peer, entry, peer_tid.list, gen_hash_addr(*peer_tid, peer_addr)) {
		if (entry->peer_tid.tid != *peer_tid)
			continue;

		/* can't be a match, otherwise already found by own_tid hash_for_each */
		if (entry->own_tid.tid_valid)
			continue;

		if (osmo_sccp_addr_cmp(entry->own_addr, own_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC) ||
		    osmo_sccp_addr_cmp(entry->peer_addr, peer_addr, OSMO_SCCP_ADDR_T_SSN | OSMO_SCCP_ADDR_T_PC))
			continue;

		return entry;
	}

	return NULL;
}

struct tcap_trans_track_entry *tcap_trans_track_begin(
	struct osmo_ss7_as *as,
	struct osmo_ss7_asp *asp,
	const struct osmo_sccp_addr *own_addr,
	const uint32_t *own_tid,
	const struct osmo_sccp_addr *peer_addr,
	const uint32_t *peer_tid)
{
	struct tcap_trans_track_entry *entry = tcap_trans_track_entry_find(as,
									   own_addr, own_tid,
									   peer_addr, peer_tid);
	if (entry) {
		entry_update_tstamp(entry);
		return entry;
	}

	return tcap_trans_track_entry_create(as, asp, own_addr, own_tid, peer_addr, peer_tid);
}

struct osmo_ss7_asp *tcap_trans_track_continue(
		struct osmo_ss7_as *as,
		const struct osmo_sccp_addr *own_addr,
		const uint32_t *own_tid,
		const struct osmo_sccp_addr *peer_addr,
		const uint32_t *peer_tid)
{
	struct tcap_trans_track_entry *entry = tcap_trans_track_entry_find(as,
							       own_addr, own_tid,
							       peer_addr, peer_tid);
	if (!entry)
		return NULL;

	/* ensure half complete entries are updated. A TCAP Begin only contains
	 * the oTID, the following Continue will contain dTID.
	 */
	if (!entry->own_tid.tid_valid && own_tid) {
		entry->own_tid.tid_valid = true;
		entry->own_tid.tid = *own_tid;
		hash_add(as->tcap.trans_track_own, &entry->own_tid.list, gen_hash_addr(*own_tid, own_addr));
	}

	if (!entry->peer_tid.tid_valid && peer_tid) {
		entry->peer_tid.tid_valid = true;
		entry->peer_tid.tid = *peer_tid;
		hash_add(as->tcap.trans_track_peer, &entry->peer_tid.list, gen_hash_addr(*peer_tid, peer_addr));
	}

	entry_update_tstamp(entry);
	return entry->asp;
}

/* find an entry, if entry exists, free it and return the associated asp */
struct osmo_ss7_asp *tcap_trans_track_end(
		struct osmo_ss7_as *as,
		const struct osmo_sccp_addr *own_addr,
		const uint32_t *own_tid,
		const struct osmo_sccp_addr *peer_addr,
		const uint32_t *peer_tid)
{
	struct osmo_ss7_asp *asp;
	struct tcap_trans_track_entry *entry = tcap_trans_track_entry_find(as, own_addr, own_tid, peer_addr, peer_tid);
	if (!entry)
		return NULL;

	asp = entry->asp;
	tcap_trans_track_entry_free(entry);

	return asp;
}


int tcap_trans_track_garbage_collect(struct osmo_ss7_as *as)
{
	int i, count = 0;
	struct tcap_trans_track_entry *entry;
	struct hlist_node *tmp;
	struct timespec now;
	time_t expiry;

	if (!as->cfg.loadshare.tcap.timeout_s)
		return 0;

	osmo_clock_gettime(CLOCK_MONOTONIC, &now);
	expiry = now.tv_sec - as->cfg.loadshare.tcap.timeout_s;

	hash_for_each_safe(as->tcap.trans_track_own, i, tmp, entry, own_tid.list) {
		if (entry->tstamp < expiry) {
			count++;
			LOGPASP(entry->asp, DLSS7, LOGL_DEBUG, "Remove Cache entry for tcap own tid %u (expired)\n", entry->own_tid.tid);
			tcap_trans_track_entry_free(entry);
		}
	}

	hash_for_each_safe(as->tcap.trans_track_peer, i, tmp, entry, peer_tid.list) {
		if (entry->tstamp < expiry) {
			count++;
			LOGPASP(entry->asp, DLSS7, LOGL_DEBUG, "Remove Cache entry for tcap peer tid %u (expired)\n", entry->peer_tid.tid);
			tcap_trans_track_entry_free(entry);
		}
	}

	return count;
}

static void tcap_trans_track_garbage_collect_cb(void *data)
{
	struct osmo_ss7_as *as = data;
	int counts = tcap_trans_track_garbage_collect(as);

	if (counts)
		LOGPAS(as, DLSS7, LOGL_DEBUG, "Removed %d cache entry (expired)", counts);

	osmo_timer_schedule(&as->tcap.gc_timer, as->cfg.loadshare.tcap.timeout_s, 0);
}


void tcap_trans_track_garbage_collect_start(struct osmo_ss7_as *as)
{
	osmo_timer_setup(&as->tcap.gc_timer, tcap_trans_track_garbage_collect_cb, as);
	tcap_trans_track_garbage_collect_cb(as);
}

void tcap_trans_track_garbage_collect_stop(struct osmo_ss7_as *as)
{
	osmo_timer_del(&as->tcap.gc_timer);
}

int tcap_trans_track_entries_free_by_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp)
{
	int i, count = 0;
	struct tcap_trans_track_entry *entry;
	struct hlist_node *tmp;

	hash_for_each_safe(as->tcap.trans_track_own, i, tmp, entry, own_tid.list) {
		if (entry->asp == asp) {
			count++;
			LOGPASP(entry->asp, DLSS7, LOGL_DEBUG, "Remove Cache entry for tcap own tid %u (asp removed)", entry->own_tid.tid);
			tcap_trans_track_entry_free(entry);
		}
	}

	hash_for_each_safe(as->tcap.trans_track_peer, i, tmp, entry, peer_tid.list) {
		if (entry->asp == asp) {
			count++;
			LOGPASP(entry->asp, DLSS7, LOGL_DEBUG, "Remove Cache entry for tcap own tid %u (asp removed)", entry->peer_tid.tid);
			tcap_trans_track_entry_free(entry);
		}
	}

	return count;
}

int tcap_trans_track_entries_free_all(struct osmo_ss7_as *as)
{
	int i, count = 0;
	struct tcap_trans_track_entry *entry;
	struct hlist_node *tmp;

	hash_for_each_safe(as->tcap.trans_track_own, i, tmp, entry, own_tid.list) {
		count++;
		LOGPASP(entry->asp, DLSS7, LOGL_DEBUG, "Remove Cache entry for tcap own tid %u (as removed)", entry->own_tid.tid);
		tcap_trans_track_entry_free(entry);
	}

	hash_for_each_safe(as->tcap.trans_track_peer, i, tmp, entry, peer_tid.list) {
		count++;
		LOGPASP(entry->asp, DLSS7, LOGL_DEBUG, "Remove Cache entry for tcap own tid %u (as removed)", entry->peer_tid.tid);
		tcap_trans_track_entry_free(entry);
	}

	return count;
}

