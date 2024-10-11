#pragma once

/* Internal header used by libosmo-sccp, not available publicly for lib users */

#include <stdbool.h>
#include <stdint.h>
#include <osmocom/sigtran/osmo_ss7.h>

extern bool ss7_initialized;
uint32_t ss7_find_free_l_rk_id(struct osmo_ss7_instance *inst);

bool ss7_ipv6_sctp_supported(const char *host, bool bind);

struct osmo_ss7_as *ss7_as_alloc(struct osmo_ss7_instance *inst, const char *name,
				 enum osmo_ss7_asp_protocol proto);

struct osmo_ss7_asp *ss7_asp_alloc(struct osmo_ss7_instance *inst, const char *name,
				   uint16_t remote_port, uint16_t local_port,
				   int trans_proto, enum osmo_ss7_asp_protocol proto);
bool ss7_asp_set_default_peer_hosts(struct osmo_ss7_asp *asp);
bool ss7_asp_is_started(const struct osmo_ss7_asp *asp);
int ss7_asp_get_fd(const struct osmo_ss7_asp *asp);
struct osmo_ss7_asp *ss7_asp_find_by_socket_addr(int fd, int trans_proto);

bool ss7_asp_protocol_check_trans_proto(enum osmo_ss7_asp_protocol proto, int trans_proto);
int ss7_default_trans_proto_for_asp_proto(enum osmo_ss7_asp_protocol proto);
int ss7_asp_ipa_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_xua_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_m3ua_tcp_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_xua_srv_conn_closed_cb(struct osmo_stream_srv *srv);
int ss7_asp_apply_peer_primary_address(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_primary_address(const struct osmo_ss7_asp *asp);
int ss7_asp_apply_new_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx);
int ss7_asp_apply_drop_local_address(const struct osmo_ss7_asp *asp, unsigned int loc_idx);

bool ss7_asp_peer_match_host(const struct osmo_ss7_asp_peer *peer, const char *host, bool host_is_v6);
int ss7_asp_peer_find_host(const struct osmo_ss7_asp_peer *peer, const char *host);

bool ss7_xua_server_set_default_local_hosts(struct osmo_xua_server *oxs);

int xua_tcp_segmentation_cb(struct msgb *msg);

enum ss7_as_ctr {
	SS7_AS_CTR_RX_MSU_TOTAL,
	SS7_AS_CTR_TX_MSU_TOTAL,
};

enum ss7_asp_ctr {
	SS7_ASP_CTR_PKT_RX_TOTAL,
	SS7_ASP_CTR_PKT_RX_UNKNOWN,
	SS7_ASP_CTR_PKT_TX_TOTAL,
};

/***********************************************************************
 * SS7 Routes
 ***********************************************************************/
#define OSMO_SS7_ROUTE_PRIO_DEFAULT 5

struct osmo_ss7_route *
ss7_route_alloc(struct osmo_ss7_route_table *rtbl, uint32_t pc, uint32_t mask);
int ss7_route_set_linkset(struct osmo_ss7_route *rt, const char *linkset_name);
int ss7_route_insert(struct osmo_ss7_route *rt);
