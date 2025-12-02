/* TCAP parsing tests */
#include <complex.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <osmocom/core/msgb.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/talloc.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>

#include "ss7_asp.h"
#include "ss7_as.h"
#include "tcap_trans_tracking.h"

typedef void (*tcap_trans_track_test_func_t)(void);
tcap_trans_track_test_func_t tcap_trans_track_tests[];

static struct osmo_sccp_addr gvlr = {
	.presence = OSMO_SCCP_ADDR_T_GT | OSMO_SCCP_ADDR_T_SSN,
	.ri = OSMO_SCCP_RI_GT,
	.gt = {
		.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI,
		.tt = 0,
		.npi = OSMO_SCCP_NPI_E164_ISDN,
		.nai = OSMO_SCCP_NAI_INTL,
		.digits = "919969679389",
	},
	.ssn = OSMO_SCCP_SSN_VLR,
};

static struct osmo_sccp_addr ghlr = {
	.presence = OSMO_SCCP_ADDR_T_GT | OSMO_SCCP_ADDR_T_SSN,
	.ri = OSMO_SCCP_RI_GT,
	.gt = {
		.gti = OSMO_SCCP_GTI_TT_NPL_ENC_NAI,
		.tt = 0,
		.npi = OSMO_SCCP_NPI_E164_ISDN,
		.nai = OSMO_SCCP_NAI_INTL,
		.digits = "919911111111",
	},
	.ssn = OSMO_SCCP_SSN_VLR,
};

static void init_as(struct osmo_ss7_as *as)
{
	as->cfg.loadshare.tcap.enabled = true;
	as->cfg.loadshare.tcap.timeout_s = 10;

	hash_init(as->tcap.tid_ranges);
	hash_init(as->tcap.trans_track_own);
	hash_init(as->tcap.trans_track_peer);
}

static void init_asp(struct osmo_ss7_asp *asp)
{
	asp->tcap.enabled = true;
}

static size_t count_unique_hash_entries(struct osmo_ss7_as *as)
{
	size_t counter = 0;
	struct tcap_trans_track_entry *entry;
	struct hlist_node *tmp;
	int i;

	/* count entries with only own_tid and own_tid && peer_tid */
	hash_for_each_safe(as->tcap.trans_track_own, i, tmp, entry, own_tid.list) {
		counter++;
	}

	/* only count those who doesn't have a valid own tid */
	hash_for_each_safe(as->tcap.trans_track_peer, i, tmp, entry, peer_tid.list) {
		if (!entry->own_tid.tid_valid)
			counter++;
	}

	return counter;
}

void tcap_trans_track_test_create_find_free(void)
{
	void *ctx = talloc_new(NULL);
	struct osmo_ss7_as *as = talloc_zero(ctx, struct osmo_ss7_as);
	init_as(as);

	struct osmo_ss7_asp *asp = talloc_zero(ctx, struct osmo_ss7_asp);
	init_asp(asp);

	size_t before_test = talloc_total_size(ctx), after_test;
	uint32_t hlr_tid = 23;
	uint32_t vlr_tid = 42;

	struct tcap_trans_track_entry *entry1, *entry2, *entry3, *search;

	printf("Create/Find/Free test\n");

	/* create an entry */
	entry1 = tcap_trans_track_entry_create(as, asp,
					&ghlr, NULL,
					&gvlr, &vlr_tid);
	OSMO_ASSERT(entry1);

	/* should find it regardless of the missing own tid in the entry */
	search = tcap_trans_track_entry_find(as,
				       &ghlr, &hlr_tid,
				       &gvlr, &vlr_tid);
	OSMO_ASSERT(search == entry1);


	/* should not find it (entry still without own tid) */
search = tcap_trans_track_entry_find(as,
				       &ghlr, &hlr_tid,
				       &gvlr, NULL);
	OSMO_ASSERT(!search);

	search = tcap_trans_track_entry_find(as,
				       &ghlr, NULL,
				       &gvlr, &vlr_tid);
	OSMO_ASSERT(search == entry1);
	tcap_trans_track_entry_free(search);

	OSMO_ASSERT(hash_empty(as->tcap.trans_track_own));
	OSMO_ASSERT(hash_empty(as->tcap.trans_track_peer));


	/* create an entries */
	entry1 = tcap_trans_track_entry_create(as, asp,
					&ghlr, &hlr_tid,
					&gvlr, NULL);
	OSMO_ASSERT(entry1);

	hlr_tid = 24;
	entry2 = tcap_trans_track_entry_create(as, asp,
					 &ghlr, &hlr_tid,
					 &gvlr, NULL);
	OSMO_ASSERT(entry2);

	hlr_tid = 25;
	entry3 = tcap_trans_track_entry_create(as, asp,
					 &ghlr, &hlr_tid,
					 &gvlr, NULL);
	OSMO_ASSERT(entry3);

	search = tcap_trans_track_entry_find(as,
				       &ghlr, &hlr_tid,
				       &gvlr, NULL);
	OSMO_ASSERT(search == entry3);
	tcap_trans_track_entries_free_by_asp(as, asp);

	OSMO_ASSERT(hash_empty(as->tcap.trans_track_own));
	OSMO_ASSERT(hash_empty(as->tcap.trans_track_peer));

	after_test = talloc_total_size(ctx);
	fprintf(stderr, "Consuming %lu bytes after test. Failing if not %lu.\n",
		after_test, before_test);
	OSMO_ASSERT(after_test == before_test);
	talloc_free(ctx);
}

void tcap_trans_track_test_transaction(void)
{
	void *ctx = talloc_new(NULL);
	struct osmo_ss7_as *as = talloc_zero(ctx, struct osmo_ss7_as);
	init_as(as);

	struct osmo_ss7_asp *asp = talloc_zero(ctx, struct osmo_ss7_asp);
	init_asp(asp);

	size_t before_test = talloc_total_size(ctx), after_test;
	uint32_t hlr_tid = 23;
	uint32_t vlr_tid = 42;

	struct tcap_trans_track_entry *entry;
	struct osmo_ss7_asp *search_asp;


	printf("Full transaction test\n");

	/* create an entry (VLR -> HLR (TCAP Begin otid 23) */
	entry = tcap_trans_track_begin(as, asp,
					   &ghlr, NULL,
					   &gvlr, &vlr_tid);
	OSMO_ASSERT(entry);
	OSMO_ASSERT(count_unique_hash_entries(as) == 1);

	/* should find it regardless of the missing own tid and update the missing tid */
	search_asp = tcap_trans_track_continue(as,
					       &ghlr, &hlr_tid,
					       &gvlr, &vlr_tid);
	OSMO_ASSERT(search_asp == asp);
	OSMO_ASSERT(count_unique_hash_entries(as) == 1);

	/* update entry by use tcap_trans_track_connection_get() */
	search_asp = tcap_trans_track_continue(as,
					   &ghlr, &hlr_tid,
					   &gvlr, NULL);
	OSMO_ASSERT(search_asp == asp);

	search_asp = tcap_trans_track_end(as,
						 &gvlr, NULL,
						 &gvlr, &vlr_tid);
	OSMO_ASSERT(search_asp);
	OSMO_ASSERT(search_asp == asp);

	OSMO_ASSERT(hash_empty(as->tcap.trans_track_own));
	OSMO_ASSERT(hash_empty(as->tcap.trans_track_peer));
	after_test = talloc_total_size(ctx);
	fprintf(stderr, "Consuming %lu bytes after test. Failing if not %lu.\n",
		after_test, before_test);
	OSMO_ASSERT(after_test == before_test);
	talloc_free(ctx);
}

static void tcap_trans_track_test_gc(void)
{
	void *ctx = talloc_new(NULL);
	struct osmo_ss7_as *as = talloc_zero(ctx, struct osmo_ss7_as);
	init_as(as);

	struct osmo_ss7_asp *asp = talloc_zero(ctx, struct osmo_ss7_asp);
	init_asp(asp);

	size_t before_test = talloc_total_size(ctx), after_test;
	uint32_t hlr_tids[] = { 24, 25, 26};
	uint32_t vlr_tids[] = { 44, 45, 46};

	struct tcap_trans_track_entry *entry = NULL;

	printf("GC test\n");

	/* create 3 entries */
	for (int i = 0; i < ARRAY_SIZE(hlr_tids); i++) {
		entry = tcap_trans_track_entry_create(as, asp,
						&ghlr, &hlr_tids[i],
						&gvlr, &vlr_tids[i]);
		OSMO_ASSERT(entry);
	}
	OSMO_ASSERT(entry);

	OSMO_ASSERT(count_unique_hash_entries(as) == 3);
	/* No entries should be GC'ed, because all entries should be within 10 secs */
	OSMO_ASSERT(tcap_trans_track_garbage_collect(as) == 0);
	OSMO_ASSERT(count_unique_hash_entries(as) == 3);

	entry->tstamp = 1;
	OSMO_ASSERT(tcap_trans_track_garbage_collect(as) == 1);
	OSMO_ASSERT(count_unique_hash_entries(as) == 2);

	tcap_trans_track_entries_free_all(as);
	OSMO_ASSERT(count_unique_hash_entries(as) == 0);
	OSMO_ASSERT(hash_empty(as->tcap.trans_track_own));
	OSMO_ASSERT(hash_empty(as->tcap.trans_track_peer));
	after_test = talloc_total_size(ctx);
	fprintf(stderr, "Consuming %lu bytes after test. Failing if not %lu.\n",
		after_test, before_test);
	OSMO_ASSERT(after_test == before_test);
	talloc_free(ctx);
}

int main(int argc, char **argv)
{
	printf("Start running tests.\n");

	tcap_trans_track_test_func_t iter = NULL;
	for (int i = 0; ((iter = tcap_trans_track_tests[i])); i++) {
		printf("Starting test %d\n", i);
		iter();
		printf("Finished test %d\n", i);
	}

	printf("All tests passed.\n");
	return 0;
}


tcap_trans_track_test_func_t tcap_trans_track_tests[] = {
	tcap_trans_track_test_create_find_free,
	tcap_trans_track_test_transaction,
	tcap_trans_track_test_gc,
	NULL
};

