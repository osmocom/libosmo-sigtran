#pragma once
#include <inttypes.h>

#include <osmocom/core/fsm.h>
#include <osmocom/core/prim.h>
#include <osmocom/core/linuxlist.h>

#include <osmocom/sigtran/sccp_sap.h>

struct osmo_sccp_instance;
enum sccp_refusal_cause;
enum osmo_sccp_originator;

struct osmo_sccp_user {
	/*! \brief entry in list of sccp users of \ref osmo_sccp_instance */
	struct llist_head list;
	/*! \brief pointer back to SCCP instance */
	struct osmo_sccp_instance *inst;
	/*! \brief human-readable name of this user */
	char *name;

	/*! \brief SSN and/or point code to which we are bound */
	uint16_t ssn;
	uint32_t pc;

	/* set if we are a server */
	struct llist_head links;

	/* user call-back function in case of incoming primitives */
	osmo_prim_cb prim_cb;
	void *priv;

	/* Application Server FSM Instance */
	struct osmo_fsm_inst *as_fi;
};

struct osmo_sccp_user *sccp_user_alloc(struct osmo_sccp_instance *inst, const char *name,
				       osmo_prim_cb prim_cb, uint16_t ssn, uint32_t pc);
void sccp_user_free(struct osmo_sccp_user *scu);

int sccp_user_prim_up(struct osmo_sccp_user *scut, struct osmo_scu_prim *prim);

enum sccp_refusal_cause scu_rel_reason_to_sccp_refusal_cause(enum osmo_sccp_originator originator, uint32_t reason);
enum sccp_release_cause scu_rel_reason_to_sccp_release_cause(enum osmo_sccp_originator originator, uint32_t reason);
void sccp_refusal_cause_to_scu_rel_reason(enum osmo_sccp_originator *originator, uint32_t *reason, uint32_t sccp_cause);
void sccp_release_cause_to_scu_rel_reason(enum osmo_sccp_originator *originator, uint32_t *reason, uint32_t sccp_cause);

#define _LOGPSCU(scu, subsys, level, fmt, args ...) \
	_LOGPSCI((scu)->inst, subsys, level, "SCU(%s) " fmt, osmo_sccp_user_name(scu), ## args)
#define LOGPSCU(scu, level, fmt, args ...) \
	_LOGPSCU(scu, DLSCCP, level, fmt, ## args)
