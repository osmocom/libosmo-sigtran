#pragma once

/* Internal header used by libosmo-sccp, not available publicly for lib users */

#include <stdbool.h>
#include <stdint.h>
#include <osmocom/netif/stream.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_instance.h"

#define MAX_PC_STR_LEN 32

extern bool ss7_initialized;

bool ss7_ipv6_sctp_supported(const char *host, bool bind);

uint32_t ss7_pc_full_mask(const struct osmo_ss7_pc_fmt *pc_fmt);

struct osmo_ss7_asp *ss7_asp_find_by_socket_addr(int fd, int trans_proto);

bool ss7_asp_protocol_check_trans_proto(enum osmo_ss7_asp_protocol proto, int trans_proto);
int ss7_default_trans_proto_for_asp_proto(enum osmo_ss7_asp_protocol proto);
int ss7_asp_ipa_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_xua_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_m3ua_tcp_srv_conn_rx_cb(struct osmo_stream_srv *conn, int res, struct msgb *msg);
int ss7_asp_xua_srv_conn_closed_cb(struct osmo_stream_srv *srv);

int xua_tcp_segmentation_cb(struct msgb *msg);

/* VTY */
#define XUA_VAR_STR	"(sua|m3ua|ipa)"
