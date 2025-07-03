#pragma once

/* Internal header used by libosmo-sccp, not available publicly for lib users */

#include <stdbool.h>
#include <stdint.h>

#include <osmocom/vty/vty.h>

#include <osmocom/netif/stream.h>
#include <osmocom/sigtran/osmo_ss7.h>

#include "ss7_instance.h"

enum cs7_role_t {
	CS7_ROLE_SG,
	CS7_ROLE_ASP
};

extern void *g_ctx;
extern const struct value_string ipproto_vals[];

#define CS7_STR	"ITU-T Signaling System 7\n"
#define PC_STR	"Point Code\n"
#define INST_STR "An instance of the SS7 stack\n"

#define XUA_VAR_STR	"(sua|m3ua|ipa)"

#define XUA_VAR_HELP_STR		\
	"SCCP User Adaptation\n"	 \
	"MTP3 User Adaptation\n"	\
	"IPA Multiplex (SCCP Lite)\n"

#define IPPROTO_VAR_STR "(sctp|tcp)"
#define IPPROTO_VAR_HELP_STR \
	"SCTP (Stream Control Transmission Protocol)\n" \
	"TCP (Transmission Control Protocol)\n"

#define QOS_CLASS_RANGE_STR "<0-7>"
#define QOS_CLASS_RANGE_HELP_STR "QoS Class\n"
#define QOS_CLASS_VAR_STR "(" QOS_CLASS_RANGE_STR "|default)"
#define QOS_CLASS_VAR_HELP_STR \
	QOS_CLASS_RANGE_HELP_STR \
	"Default QoS Class (0)\n"

int parse_trans_proto(const char *protocol);
enum osmo_ss7_asp_protocol parse_asp_proto(const char *protocol);

/* ss7_asp_vty.c */
void ss7_vty_init_node_asp(void);
void ss7_vty_write_one_asp(struct vty *vty, struct osmo_ss7_asp *asp, bool show_dyn_config);
int ss7_vty_node_asp_go_parent(struct vty *vty);

/* ss7_as_vty.c */
void ss7_vty_init_node_as(void);
void ss7_vty_write_one_as(struct vty *vty, struct osmo_ss7_as *as, bool show_dyn_config);
int ss7_vty_node_as_go_parent(struct vty *vty);

/* ss7_xua_srv_vty.c */
void ss7_vty_init_node_oxs(void);
void ss7_vty_init_show_oxs(void);
void ss7_vty_write_one_oxs(struct vty *vty, struct osmo_xua_server *xs);
int ss7_vty_node_oxs_go_parent(struct vty *vty);
