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

struct osmo_ss7_user;

/* Appendix C.4 of Q.714 */
enum osmo_sccp_timer {
	/* 0 kept unused on purpose since it's handled specially by osmo_fsm */
	OSMO_SCCP_TIMER_CONN_EST = 1,
	OSMO_SCCP_TIMER_IAS,
	OSMO_SCCP_TIMER_IAR,
	OSMO_SCCP_TIMER_REL,
	OSMO_SCCP_TIMER_REPEAT_REL,
	OSMO_SCCP_TIMER_INT,
	OSMO_SCCP_TIMER_GUARD,
	OSMO_SCCP_TIMER_RESET,
	OSMO_SCCP_TIMER_REASSEMBLY,
	/* This must remain the last item: */
	OSMO_SCCP_TIMERS_LEN
};

extern const struct osmo_tdef osmo_sccp_timer_defaults[OSMO_SCCP_TIMERS_LEN];

extern const struct value_string osmo_sccp_timer_names[];
static inline const char *osmo_sccp_timer_name(enum osmo_sccp_timer val)
{ return get_value_string(osmo_sccp_timer_names, val); }

struct sccp_pending_rout_fail {
	/* Item in inst->rout_fail_pending.queue: */
	struct llist_head list;
	struct xua_msg *xua;
	uint32_t cause;
	bool scoc; /* true if it's for SCOC, false if it's for SCLC. */
};

/* an instance of the SCCP stack */
struct osmo_sccp_instance {
	/* entry in global list of ss7 instances */
	struct llist_head list;
	/* rbtree root of 'struct sccp_connection' in this instance */
	struct rb_root connections;
	/* list of SCCP users in this instance */
	struct llist_head users;
	/* routing context to be used in all outbound messages */
	uint32_t route_ctx;
	/* next connection ID to allocate */
	uint32_t next_id;
	struct osmo_ss7_instance *ss7;
	void *priv;

	struct osmo_ss7_user *ss7_user;

	struct osmo_tdef *tdefs;

	uint32_t max_optional_data;

	/* Queued Routing Failures to transmit asynchronously up the stack: */
	struct {
		struct osmo_timer_list timer;
		struct llist_head queue;
	} rout_fail_pending;
};

struct osmo_sccp_user *
sccp_user_find(struct osmo_sccp_instance *inst, uint16_t ssn, uint32_t pc);

#define _LOGPSCI(sci, subsys, level, fmt, args ...) \
	_LOGSS7((sci)->ss7, subsys, level, "SCCP(rctx=%" PRIu32 ") " fmt, (sci)->route_ctx, ## args)
#define LOGPSCI(sci, level, fmt, args ...) \
	_LOGPSCI(sci, DLSCCP, level, fmt, ## args)

