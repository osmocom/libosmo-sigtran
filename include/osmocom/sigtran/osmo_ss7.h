#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/rate_ctr.h>

/* Maximum number of supported RCTXs present in RFC4666 Routing Context IE. */
#define OSMO_SS7_MAX_RCTX_COUNT 128

struct osmo_ss7_instance;

extern struct llist_head osmo_ss7_instances;
/* Get an entry pointer from a list item in osmo_ss7_instances: */
struct osmo_ss7_instance *osmo_ss7_instances_llist_entry(struct llist_head *list);

int osmo_ss7_init(void);

/* All known point-code formats have a length of or below 24 bit.
 * A point-code value exceeding that is used to indicate an unset PC. */
#define OSMO_SS7_PC_INVALID 0xffffffff
static inline bool osmo_ss7_pc_is_valid(uint32_t pc)
{
	return pc <= 0x00ffffff;
}

/***********************************************************************
 * xUA Servers
 ***********************************************************************/

struct osmo_xua_layer_manager;

struct osmo_xua_server;

/***********************************************************************
 * SS7 Instances
 ***********************************************************************/

struct osmo_ss7_pc_fmt;
struct osmo_ss7_instance;

struct osmo_ss7_instance *osmo_ss7_instance_find(uint32_t id);
struct osmo_ss7_instance *
osmo_ss7_instance_find_or_create(void *ctx, uint32_t id);
void osmo_ss7_instance_destroy(struct osmo_ss7_instance *inst);

uint32_t osmo_ss7_instance_get_id(const struct osmo_ss7_instance *inst);
const char *osmo_ss7_instance_get_name(const struct osmo_ss7_instance *inst);

int osmo_ss7_instance_set_pc_fmt(struct osmo_ss7_instance *inst,
				uint8_t c0, uint8_t c1, uint8_t c2);
const struct osmo_ss7_pc_fmt *
osmo_ss7_instance_get_pc_fmt(const struct osmo_ss7_instance *inst);

uint32_t osmo_ss7_instance_get_primary_pc(const struct osmo_ss7_instance *inst);
uint8_t osmo_ss7_instance_get_network_indicator(const struct osmo_ss7_instance *inst);

struct osmo_sccp_instance *osmo_ss7_ensure_sccp(struct osmo_ss7_instance *inst);
struct osmo_sccp_instance *osmo_ss7_get_sccp(const struct osmo_ss7_instance *inst);

int osmo_ss7_find_free_rctx(struct osmo_ss7_instance *inst);

bool osmo_ss7_pc_is_local(const struct osmo_ss7_instance *inst, uint32_t pc);
int osmo_ss7_pointcode_parse(const struct osmo_ss7_instance *inst, const char *str);
int osmo_ss7_pointcode_parse_mask_or_len(const struct osmo_ss7_instance *inst, const char *in);
const char *osmo_ss7_pointcode_print_buf(char *buf, size_t buf_len, const struct osmo_ss7_instance *inst, uint32_t pc);
const char *osmo_ss7_pointcode_print(const struct osmo_ss7_instance *inst, uint32_t pc);
const char *osmo_ss7_pointcode_print2(const struct osmo_ss7_instance *inst, uint32_t pc);

uint8_t osmo_ss7_pc_width(const struct osmo_ss7_pc_fmt *pc_fmt);
uint32_t osmo_ss7_pc_normalize(const struct osmo_ss7_pc_fmt *pc_fmt, uint32_t pc);

/***********************************************************************
 * MTP Users (Users of MTP, such as SCCP or ISUP)
 ***********************************************************************/

struct osmo_ss7_user;
struct osmo_mtp_prim;


struct osmo_ss7_user *osmo_ss7_user_create(struct osmo_ss7_instance *inst, const char *name);
void osmo_ss7_user_destroy(struct osmo_ss7_user *user);

struct osmo_ss7_instance *osmo_ss7_user_get_instance(const struct osmo_ss7_user *user);
void osmo_ss7_user_set_prim_cb(struct osmo_ss7_user *user, osmo_prim_cb prim_cb);
void osmo_ss7_user_set_priv(struct osmo_ss7_user *user, void *priv);
void *osmo_ss7_user_get_priv(const struct osmo_ss7_user *user);

int osmo_ss7_user_register(struct osmo_ss7_user *user, uint8_t service_ind);
int osmo_ss7_user_unregister(struct osmo_ss7_user *user, uint8_t service_ind);


/* MTP User wants to submit a primitive down to MTP SAP */
int osmo_ss7_user_mtp_sap_prim_down(struct osmo_ss7_user *user,
				    struct osmo_mtp_prim *omp);

/***********************************************************************
 * SCCP Instance
 ***********************************************************************/

struct osmo_sccp_instance;

void osmo_sccp_set_max_optional_data(struct osmo_sccp_instance *inst, int val);

/***********************************************************************
 * SS7 Links
 ***********************************************************************/

struct osmo_ss7_link;

/***********************************************************************
 * SS7 Linksets
 ***********************************************************************/

struct osmo_ss7_linkset;

/***********************************************************************
 * SS7 Routes
 ***********************************************************************/

struct osmo_ss7_route;

struct osmo_ss7_route *
osmo_ss7_route_lookup(struct osmo_ss7_instance *inst, uint32_t dpc)
	OSMO_DEPRECATED("Use internal ss7_instance_lookup_route() instead");
const char *osmo_ss7_route_print(const struct osmo_ss7_route *rt);
const char *osmo_ss7_route_name(struct osmo_ss7_route *rt, bool list_asps);
struct osmo_ss7_as *
osmo_ss7_route_get_dest_as(struct osmo_ss7_route *rt);

/***********************************************************************
 * SS7 Routing key
 ***********************************************************************/

struct osmo_ss7_routing_key {
	uint32_t context;
	uint32_t l_rk_id;

	uint32_t pc;
	uint8_t si;
	uint32_t ssn;
	/* FIXME: more complex routing keys */
};


/***********************************************************************
 * SS7 ASP Protocols
 ***********************************************************************/

enum osmo_ss7_asp_protocol {
	OSMO_SS7_ASP_PROT_NONE,
	OSMO_SS7_ASP_PROT_SUA,
	OSMO_SS7_ASP_PROT_M3UA,
	OSMO_SS7_ASP_PROT_IPA,
	_NUM_OSMO_SS7_ASP_PROT
};

extern struct value_string osmo_ss7_asp_protocol_vals[];
static inline const char *
osmo_ss7_asp_protocol_name(enum osmo_ss7_asp_protocol mode)
{
	return get_value_string(osmo_ss7_asp_protocol_vals, mode);
}

int osmo_ss7_asp_protocol_port(enum osmo_ss7_asp_protocol prot);


/***********************************************************************
 * SS7 AS Traffic Mode
 ***********************************************************************/

 /* Traffic mode implementations which can be configured on an AS, either by
  * peer (eg. RFC4666 M3UA "Traffic Mode Type") or locally through VTY.
  * Note: This is related but not exactly RFC4666 M3UA "Traffic Mode Type" (enum
  * m3ua_traffic_mode). */
enum osmo_ss7_as_traffic_mode {
	/* RFC4666 M3UA "Traffic Mode Type" "Override". Default traffic mode: */
	OSMO_SS7_AS_TMOD_OVERRIDE = 0,
	/* RFC4666 M3UA "Traffic Mode Type" "Broadcast": */
	OSMO_SS7_AS_TMOD_BCAST,
	/* RFC4666 M3UA "Traffic Mode Type" "Loadshare",
	 * traffic distribution based on OPC+SLS: */
	OSMO_SS7_AS_TMOD_LOADSHARE,
	/* RFC4666 M3UA "Traffic Mode Type" "Loadshare",
	 * traffic distribution implemented as round-robin: */
	OSMO_SS7_AS_TMOD_ROUNDROBIN,
	_NUM_OSMO_SS7_ASP_TMOD
};

extern struct value_string osmo_ss7_as_traffic_mode_vals[];

static inline const char *
osmo_ss7_as_traffic_mode_name(enum osmo_ss7_as_traffic_mode mode)
{
	return get_value_string(osmo_ss7_as_traffic_mode_vals, mode);
}

enum osmo_ss7_as_traffic_mode osmo_ss7_tmode_from_xua(uint32_t in);
int osmo_ss7_tmode_to_xua(enum osmo_ss7_as_traffic_mode tmod);


/***********************************************************************
 * SS7 Application Servers
 ***********************************************************************/

struct osmo_ss7_as;
struct osmo_ss7_asp;

struct osmo_ss7_as *
osmo_ss7_as_find_by_name(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_as *
osmo_ss7_as_find_by_rctx(struct osmo_ss7_instance *inst, uint32_t rctx);
struct osmo_ss7_as *
osmo_ss7_as_find_by_l_rk_id(struct osmo_ss7_instance *inst, uint32_t l_rk_id);
struct osmo_ss7_as *osmo_ss7_as_find_by_proto(struct osmo_ss7_instance *inst,
					      enum osmo_ss7_asp_protocol proto);
struct osmo_ss7_as *
osmo_ss7_as_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			  enum osmo_ss7_asp_protocol proto);
enum osmo_ss7_asp_protocol osmo_ss7_as_get_asp_protocol(const struct osmo_ss7_as *as);
int osmo_ss7_as_add_asp(struct osmo_ss7_as *as, const char *asp_name);
int osmo_ss7_as_del_asp(struct osmo_ss7_as *as, const char *asp_name);
void osmo_ss7_as_destroy(struct osmo_ss7_as *as);
bool osmo_ss7_as_has_asp(const struct osmo_ss7_as *as,
			 const struct osmo_ss7_asp *asp);
struct osmo_ss7_asp *osmo_ss7_as_select_asp(struct osmo_ss7_as *as);
bool osmo_ss7_as_down(const struct osmo_ss7_as *as);
bool osmo_ss7_as_active(const struct osmo_ss7_as *as);
bool osmo_ss7_as_tmode_compatible_xua(struct osmo_ss7_as *as, uint32_t m3ua_tmt);


/***********************************************************************
 * SS7 Application Server Processes
 ***********************************************************************/

enum osmo_ss7_asp_admin_state {
	/*! no SCTP association with peer */
	OSMO_SS7_ASP_ADM_S_SHUTDOWN,
	/*! SCP association, but reject ASP-ACTIVE */
	OSMO_SS7_ASP_ADM_S_BLOCKED,
	/*! in normal operation */
	OSMO_SS7_ASP_ADM_S_ENABLED,
};
extern const struct value_string osmo_ss7_asp_admin_state_names[];

enum osmo_ss7_asp_role {
	OSMO_SS7_ASP_ROLE_ASP,
	OSMO_SS7_ASP_ROLE_SG,
	OSMO_SS7_ASP_ROLE_IPSP,
};

extern const struct value_string osmo_ss7_asp_role_names[];

struct osmo_ss7_asp;

/*! Peer SG doesn't send NTFY(AS-INACTIVE) after ASP-UP procedure */
#define OSMO_SS7_ASP_QUIRK_NO_NOTIFY		0x00000001
/*! Accept DAUD in ASP role (RFC states only permitted in ASP->SG role) */
#define OSMO_SS7_ASP_QUIRK_DAUD_IN_ASP		0x00000002
/*! Accept SSNM even if ASP is in AS-INACTIVE state */
#define OSMO_SS7_ASP_QUIRK_SNM_INACTIVE		0x00000004


struct osmo_ss7_asp *
osmo_ss7_asp_find_by_name(struct osmo_ss7_instance *inst, const char *name);
struct osmo_ss7_asp *
osmo_ss7_asp_find_by_proto(struct osmo_ss7_as *as,
			   enum osmo_ss7_asp_protocol proto);
struct osmo_ss7_asp *
osmo_ss7_asp_find(struct osmo_ss7_instance *inst, const char *name,
		  uint16_t remote_port, uint16_t local_port,
		  enum osmo_ss7_asp_protocol proto)
	OSMO_DEPRECATED("Use osmo_ss7_asp_find2() instead");
struct osmo_ss7_asp *
osmo_ss7_asp_find2(struct osmo_ss7_instance *inst, const char *name,
		   uint16_t remote_port, uint16_t local_port,
		   int trans_proto, enum osmo_ss7_asp_protocol proto);
struct osmo_ss7_asp *
osmo_ss7_asp_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			    uint16_t remote_port, uint16_t local_port,
			    enum osmo_ss7_asp_protocol proto)
	OSMO_DEPRECATED("Use osmo_ss7_asp_find_or_create2() instead");
struct osmo_ss7_asp *
osmo_ss7_asp_find_or_create2(struct osmo_ss7_instance *inst, const char *name,
			     uint16_t remote_port, uint16_t local_port,
			     int trans_proto, enum osmo_ss7_asp_protocol proto);
void osmo_ss7_asp_disconnect(struct osmo_ss7_asp *asp);
void osmo_ss7_asp_destroy(struct osmo_ss7_asp *asp);
int osmo_ss7_asp_send(struct osmo_ss7_asp *asp, struct msgb *msg);
int osmo_ss7_asp_restart(struct osmo_ss7_asp *asp);
int osmo_ss7_asp_use_default_lm(struct osmo_ss7_asp *asp, int log_level);
bool osmo_ss7_asp_active(const struct osmo_ss7_asp *asp);
int osmo_ss7_asp_get_log_subsys(const struct osmo_ss7_asp *asp);
const char *osmo_ss7_asp_get_name(const struct osmo_ss7_asp *asp);
enum osmo_ss7_asp_protocol osmo_ss7_asp_get_proto(const struct osmo_ss7_asp *asp);
int osmo_ss7_asp_get_trans_proto(const struct osmo_ss7_asp *asp);

/*! Weak function to handle payload for unknown/unsupported PPID or IPA StreamID.
 *  This function can be overridden by application code to implement whatever handling
 *  it wants for such additional payloads/streams.
 *  \param[in] asp Application Server Process through which data was received
 *  \param[in] ppid_sid SCTP PPID (in sigtran case) or IPA Stream ID
 *  \param[in] msg Message buffer containing received data. Continues to be owned by caller!
 *  \return 0 on success; negative on error */
typedef int osmo_ss7_asp_rx_unknown_cb(struct osmo_ss7_asp *asp, int ppid_mux, struct msgb *msg);

void osmo_ss7_register_rx_unknown_cb(osmo_ss7_asp_rx_unknown_cb *cb);


/***********************************************************************
 * Simple Client
 ***********************************************************************/

struct osmo_sccp_instance *
osmo_sccp_simple_client(void *ctx, const char *name, uint32_t default_pc,
			enum osmo_ss7_asp_protocol prot, int default_local_port,
			const char *default_local_ip, int default_remote_port,
			const char *default_remote_ip);

struct osmo_sccp_instance *
osmo_sccp_simple_client_on_ss7_id(void *ctx, uint32_t ss7_id, const char *name,
				  uint32_t default_pc,
				  enum osmo_ss7_asp_protocol prot,
				  int default_local_port,
				  const char *default_local_ip,
				  int default_remote_port,
				  const char *default_remote_ip);

/***********************************************************************
 * Simple Server
 ***********************************************************************/

struct osmo_sccp_instance *
osmo_sccp_simple_server(void *ctx, uint32_t pc,
			enum osmo_ss7_asp_protocol prot, int local_port,
			const char *local_ip);

struct osmo_sccp_instance *
osmo_sccp_simple_server_on_ss7_id(void *ctx, uint32_t ss7_id, uint32_t pc,
				  enum osmo_ss7_asp_protocol prot,
				  int local_port, const char *local_ip);

struct osmo_sccp_instance *
osmo_sccp_simple_server_add_clnt(struct osmo_sccp_instance *inst,
				 enum osmo_ss7_asp_protocol prot,
				 const char *name, uint32_t pc,
				 int local_port, int remote_port,
				 const char *remote_ip);

/* VTY related */
struct vty;
void osmo_ss7_vty_init_asp(void *ctx);
void osmo_ss7_vty_init_sg(void *ctx);
int osmo_ss7_vty_go_parent(struct vty *vty);
int osmo_ss7_is_config_node(struct vty *vty, int node)
	OSMO_DEPRECATED("Implicit parent node tracking has replaced the use of this callback. "
			"This callback is no longer called, ever, and can be left NULL.");
