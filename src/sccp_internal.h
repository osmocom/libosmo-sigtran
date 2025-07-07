#pragma once

#include <inttypes.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/linuxrbtree.h>
#include <osmocom/core/tdef.h>
#include <osmocom/sigtran/sccp_sap.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/mtp.h>

#define SCCP_STR "Signalling Connection Control Part\n"

struct osmo_sccp_instance;
struct osmo_sccp_user;

/* SCCP addressbook */
extern struct llist_head sccp_address_book_global;
struct osmo_sccp_addr_entry {
	struct llist_head list;
	struct llist_head list_global;
	struct osmo_ss7_instance *inst;
	char name[32];
	struct osmo_sccp_addr addr;
};
struct osmo_sccp_addr_entry *addr_entry_by_name_local(const char *name,
						      const struct osmo_ss7_instance *inst);
struct osmo_sccp_addr_entry *addr_entry_by_name_global(const char *name);

extern int DSCCP;

struct xua_msg;

struct sccp_connection *sccp_find_conn_by_id(const struct osmo_sccp_instance *inst, uint32_t id);

/* Message from SCOC -> SCRC */
int sccp_scrc_rx_scoc_conn_msg(struct osmo_sccp_instance *inst,
				struct xua_msg *xua);

/* Message from SCLC -> SCRC */
int sccp_scrc_rx_sclc_msg(struct osmo_sccp_instance *inst, struct xua_msg *xua);

/* Message from MTP (SUA) -> SCRC */
int scrc_rx_mtp_xfer_ind_xua(struct osmo_sccp_instance *inst,
			     struct xua_msg *xua);

/* Message from SCRC -> SCOC */
void sccp_scoc_rx_from_scrc(struct osmo_sccp_instance *inst,
			    struct xua_msg *xua);
void sccp_scoc_rx_scrc_rout_fail(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua, uint32_t cause);

/* Message from SCRC -> SCLC */
int sccp_sclc_rx_from_scrc(struct osmo_sccp_instance *inst,
			   struct xua_msg *xua);
void sccp_sclc_rx_scrc_rout_fail(struct osmo_sccp_instance *inst,
				 struct xua_msg *xua, uint32_t cause);

/* Route Failure from SCRX -> SCOC or SCLC */
void sccp_rout_fail_enqueue(struct osmo_sccp_instance *inst, const struct xua_msg *xua, uint32_t cause, bool scoc);

/* SCU -> SCLC */
int sccp_sclc_user_sap_down(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph);
int sccp_sclc_user_sap_down_nofree(struct osmo_sccp_user *scu, struct osmo_prim_hdr *oph);

struct msgb *sccp_msgb_alloc(const char *name);

void osmo_sccp_vty_write_cs7_node(struct vty *vty, const char *indent, struct osmo_sccp_instance *inst);

/* Local Broadcast (LBCS) */
void sccp_lbcs_local_bcast_pcstate(struct osmo_sccp_instance *inst,
				   const struct osmo_scu_pcstate_param *pcstate);
void sccp_lbcs_local_bcast_state(struct osmo_sccp_instance *inst,
				   const struct osmo_scu_state_param *state);

/* SCCP Management (SCMG) */
void sccp_scmg_rx_ssn_allowed(struct osmo_sccp_instance *inst, uint32_t dpc, uint32_t ssn, uint32_t smi);
void sccp_scmg_rx_ssn_prohibited(struct osmo_sccp_instance *inst, uint32_t dpc, uint32_t ssn, uint32_t smi);
void sccp_scmg_rx_mtp_pause(struct osmo_sccp_instance *inst, uint32_t dpc);
void sccp_scmg_rx_mtp_resume(struct osmo_sccp_instance *inst, uint32_t dpc);
void sccp_scmg_rx_mtp_status(struct osmo_sccp_instance *inst, uint32_t dpc, enum mtp_unavail_cause cause);
int sccp_scmg_init(struct osmo_sccp_instance *inst);
