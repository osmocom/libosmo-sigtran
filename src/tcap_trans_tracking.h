#pragma once

/* TCAP transaction tracking */

#include <stdint.h>

#include <osmocom/core/hashtable.h>
#include <osmocom/core/msgb.h>

#include <osmocom/sigtran/sccp_sap.h>

struct osmo_ss7_as;
struct osmo_ss7_asp;

struct tcap_trans_track_tid_entry {
	struct hlist_node list;
	bool tid_valid;
	uint32_t tid;
};

struct tcap_trans_track_entry {
	struct tcap_trans_track_tid_entry peer_tid; /* of the peer. If peer initiate transaction, this is otid */
	struct tcap_trans_track_tid_entry own_tid; /* assigned by this asp */

	struct osmo_sccp_addr *own_addr;
	struct osmo_sccp_addr *peer_addr;

	time_t tstamp; /* last time this cache was used */

	struct osmo_ss7_asp *asp;
};

/* Entry centric API
 * Managing entries without management (e.g. update entries when used)
 */
struct tcap_trans_track_entry *tcap_trans_track_entry_create(
	struct osmo_ss7_as *as,
	struct osmo_ss7_asp *asp,
	const struct osmo_sccp_addr *own_addr,
	const uint32_t *own_tid,
	const struct osmo_sccp_addr *peer_addr,
	const uint32_t *peer_tid);

struct tcap_trans_track_entry *tcap_trans_track_entry_find(
	struct osmo_ss7_as *as,
	const struct osmo_sccp_addr *own_addr,
	const uint32_t *own_tid,
	const struct osmo_sccp_addr *peer_addr,
	const uint32_t *peer_tid);

void tcap_trans_track_entry_free(struct tcap_trans_track_entry *entry);

int tcap_trans_track_entries_free_all(struct osmo_ss7_as *as);
int tcap_trans_track_entries_free_by_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp);

/* Transaction centric API
 * It will update timestamp and used out of a TCAP transaction context
 */
struct tcap_trans_track_entry *tcap_trans_track_begin(
	struct osmo_ss7_as *as,
	struct osmo_ss7_asp *asp,
	const struct osmo_sccp_addr *own_addr,
	const uint32_t *own_tid,
	const struct osmo_sccp_addr *peer_addr,
	const uint32_t *peer_tid);

struct osmo_ss7_asp *tcap_trans_track_continue(
	struct osmo_ss7_as *as,
	const struct osmo_sccp_addr *own_addr,
	const uint32_t *own_tid,
	const struct osmo_sccp_addr *peer_addr,
	const uint32_t *peer_tid);

struct osmo_ss7_asp *tcap_trans_track_end(
	struct osmo_ss7_as *as,
	const struct osmo_sccp_addr *own_addr,
	const uint32_t *own_tid,
	const struct osmo_sccp_addr *peer_addr,
	const uint32_t *peer_tid);

/* Garbage collection */
int tcap_trans_track_garbage_collect(struct osmo_ss7_as *as);

void tcap_trans_track_garbage_collect_start(struct osmo_ss7_as *as);
void tcap_trans_track_garbage_collect_stop(struct osmo_ss7_as *as);

