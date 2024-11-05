#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

/***********************************************************************
 * SS7 ASP Peer
 ***********************************************************************/

struct osmo_ss7_asp_peer {
	char *host[OSMO_SOCK_MAX_ADDRS];
	size_t host_cnt;
	uint16_t port;
	/* index in "hosts" array marking the SCTP Primary Address, -1 if no explicit Primary Address set */
	int idx_primary;
};

int ss7_asp_peer_snprintf(char *buf, size_t buf_len, struct osmo_ss7_asp_peer *peer);
void ss7_asp_peer_init(struct osmo_ss7_asp_peer *peer);
int ss7_asp_peer_set_hosts(struct osmo_ss7_asp_peer *peer, void *talloc_ctx,
				const char *const*hosts, size_t host_cnt);
int ss7_asp_peer_set_hosts2(struct osmo_ss7_asp_peer *peer, void *talloc_ctx,
				 const char *const*hosts, size_t host_cnt, int idx_primary);
int ss7_asp_peer_add_host(struct osmo_ss7_asp_peer *peer, void *talloc_ctx, const char *host);
int ss7_asp_peer_add_host2(struct osmo_ss7_asp_peer *peer, void *talloc_ctx, const char *host, bool is_primary_addr);
int ss7_asp_peer_del_host(struct osmo_ss7_asp_peer *peer, const char *host);

bool ss7_asp_peer_match_host(const struct osmo_ss7_asp_peer *peer, const char *host, bool host_is_v6);
int ss7_asp_peer_find_host(const struct osmo_ss7_asp_peer *peer, const char *host);
