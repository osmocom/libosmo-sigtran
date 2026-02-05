#pragma once

#include <stdint.h>
#include <unistd.h>
#include <osmocom/core/defs.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/prim.h>
#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/osmo_ss7.h>

/***********************************************************************
 * xUA Servers
 ***********************************************************************/

struct osmo_ss7_instance;

struct osmo_xua_server {
	struct llist_head list;
	struct osmo_ss7_instance *inst;

	/* list of ASPs established via this server */
	struct llist_head asp_list;

	struct osmo_stream_srv_link *server;

	struct {
		bool accept_dyn_reg;
		struct osmo_ss7_asp_peer local;
		enum osmo_ss7_asp_protocol proto;
		struct {
			bool num_ostreams_present;
			bool max_instreams_present;
			uint16_t num_ostreams_value;
			uint16_t max_instreams_value;
		} sctp_init;

		/*! The underlaying transport protocol (one of IPPROTO_*) */
		int trans_proto;
	} cfg;
};

struct osmo_xua_server *
ss7_xua_server_find(struct osmo_ss7_instance *inst,
			 enum osmo_ss7_asp_protocol proto,
			 uint16_t local_port)
	OSMO_DEPRECATED("Use ss7_xua_server_find2() instead");
struct osmo_xua_server *
ss7_xua_server_find2(struct osmo_ss7_instance *inst,
			  int trans_proto,
			  enum osmo_ss7_asp_protocol proto,
			  uint16_t local_port);

struct osmo_xua_server *
ss7_xua_server_create(struct osmo_ss7_instance *inst,
			   enum osmo_ss7_asp_protocol proto,
			   uint16_t local_port, const char *local_host)
	OSMO_DEPRECATED("Use ss7_xua_server_create2() instead");
struct osmo_xua_server *
ss7_xua_server_create2(struct osmo_ss7_instance *inst,
			    int trans_proto, enum osmo_ss7_asp_protocol proto,
			    uint16_t local_port, const char *local_host);

int
ss7_xua_server_bind(struct osmo_xua_server *xs);

int
ss7_xua_server_set_local_host(struct osmo_xua_server *xs, const char *local_host);
int
ss7_xua_server_set_local_hosts(struct osmo_xua_server *xs, const char **local_hosts, size_t local_host_cnt);
int ss7_xua_server_add_local_host(struct osmo_xua_server *xs, const char *local_host);
int ss7_xua_server_del_local_host(struct osmo_xua_server *xs, const char *local_host);
void ss7_xua_server_destroy(struct osmo_xua_server *xs);

bool ss7_xua_server_set_default_local_hosts(struct osmo_xua_server *oxs);
