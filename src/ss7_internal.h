#pragma once

/* Internal header used by libosmo-sccp, not available publicly for lib users */

#include <stdbool.h>
#include <stdint.h>
#include <osmocom/netif/stream.h>
#include <osmocom/sigtran/osmo_ss7.h>

extern bool ss7_initialized;
uint32_t ss7_find_free_l_rk_id(struct osmo_ss7_instance *inst);

bool ss7_ipv6_sctp_supported(const char *host, bool bind);

struct osmo_ss7_as *ss7_as_alloc(struct osmo_ss7_instance *inst, const char *name,
				 enum osmo_ss7_asp_protocol proto);

struct osmo_ss7_asp *ss7_asp_find_by_socket_addr(int fd, int trans_proto);

bool ss7_asp_protocol_check_trans_proto(enum osmo_ss7_asp_protocol proto, int trans_proto);
int ss7_default_trans_proto_for_asp_proto(enum osmo_ss7_asp_protocol proto);
int ss7_asp_ipa_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_xua_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_m3ua_tcp_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_xua_srv_conn_closed_cb(struct osmo_stream_srv *srv);

int xua_tcp_segmentation_cb(struct msgb *msg);

enum ss7_as_ctr {
	SS7_AS_CTR_RX_MSU_TOTAL,
	SS7_AS_CTR_TX_MSU_TOTAL,
};

#define _LOGSS7(inst, subsys, level, fmt, args ...) \
	LOGP(subsys, level, "%u: " fmt, inst ? (inst)->cfg.id : 0, ## args)
#define LOGSS7(inst, level, fmt, args ...) \
	_LOGSS7(inst, DLSS7, level, fmt, ## args)

#define LOGPAS(as, subsys, level, fmt, args ...) \
	_LOGSS7((as)->inst, subsys, level, "as-%s: " fmt, (as)->cfg.name, ## args)
