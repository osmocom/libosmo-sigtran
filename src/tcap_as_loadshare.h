#pragma once

#include <stdint.h>

#include <osmocom/core/msgb.h>
#include <osmocom/sigtran/osmo_ss7.h>

struct xua_msg;

#define TCAP_PC_WILDCARD 0xffffffff
#define TCAP_SSN_WILDCARD 0

struct tcap_range {
	struct hlist_node list;
	struct osmo_ss7_asp *asp;
	uint32_t tid_start;
	uint32_t tid_end;
	uint32_t pc;
	uint8_t ssn;
};

/* IPA entry point */
int ipa_rx_msg_osmo_ext_tcap_routing(struct osmo_ss7_asp *asp, struct msgb *msg);

struct tcap_range *tcap_range_alloc(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp,
				    uint32_t tid_start, uint32_t tid_end, uint32_t pc, uint8_t ssn);
void tcap_range_free(struct tcap_range *tcrng);

bool tcap_range_matches(const struct tcap_range *tcrng, uint32_t tid);
bool tcap_range_overlaps(const struct tcap_range *a, uint32_t tid_min, uint32_t tid_max);

/* Traffic ASP -> AS -> STP (Rx path) From TCAP Routing AS, only used for connection tracking */
int tcap_as_rx_sccp_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp, uint32_t opc, uint32_t dpc, struct msgb *sccp_msg);

/* Traffic STP -> AS -> ASP (Tx path) Loadshare towards the TCAP routing AS */
int tcap_as_select_asp_loadshare(struct osmo_ss7_asp **asp, struct osmo_ss7_as *as, const struct xua_msg *xua);

/* When the ASP got removed */
void tcap_as_del_asp(struct osmo_ss7_as *as, struct osmo_ss7_asp *asp);

void tcap_enable(struct osmo_ss7_as *as);
void tcap_disable(struct osmo_ss7_as *as);
