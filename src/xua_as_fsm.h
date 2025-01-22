#pragma once

struct osmo_ss7_as;
struct osmo_ss7_asp;

enum xua_as_state {
	XUA_AS_S_DOWN,
	XUA_AS_S_INACTIVE,
	XUA_AS_S_ACTIVE,
	XUA_AS_S_PENDING,
};

struct xua_as_event_asp_inactive_ind_pars {
	struct osmo_ss7_asp *asp;
	/* RFC4666 4.3.4.5: "When an ASP moves from ASP-DOWN to ASP-INACTIVE within a
	 * particular AS, a Notify message SHOULD be sent, by the ASP-UP receptor,
	 * after sending the ASP-UP-ACK, in order to inform the ASP of the current AS
	 * state." */
	bool asp_requires_notify;
};

enum xua_as_event {
	XUA_ASPAS_ASP_INACTIVE_IND, /* param: struct xua_as_event_asp_inactive_ind_pars* */
	XUA_ASPAS_ASP_DOWN_IND,
	XUA_ASPAS_ASP_ACTIVE_IND,
	XUA_AS_E_RECOVERY_EXPD,
	XUA_AS_E_TRANSFER_REQ, /* param: struct xua_msg*, ownership transferred. */
};

extern struct osmo_fsm xua_as_fsm;

struct osmo_fsm_inst *xua_as_fsm_start(struct osmo_ss7_as *as, int log_level);
