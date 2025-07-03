#pragma once

#include <osmocom/core/fsm.h>

enum sccp_scoc_fsm_state {
	S_IDLE,
	S_CONN_PEND_IN,
	S_CONN_PEND_OUT,
	S_ACTIVE,
	S_DISCONN_PEND,
	S_RESET_IN,
	S_RESET_OUT,
	S_BOTHWAY_RESET,
	S_WAIT_CONN_CONF,
};

/* Events that this FSM can process */
enum sccp_scoc_fsm_event {
	/* Primitives from SCCP-User */
	SCOC_E_SCU_N_CONN_REQ,
	SCOC_E_SCU_N_CONN_RESP,
	SCOC_E_SCU_N_DISC_REQ,
	SCOC_E_SCU_N_DATA_REQ,
	SCOC_E_SCU_N_EXP_DATA_REQ,

	/* Events from RCOC (Routing for Connection Oriented) */
	SCOC_E_RCOC_CONN_IND,
	SCOC_E_RCOC_ROUT_FAIL_IND,
	SCOC_E_RCOC_RLSD_IND,
	SCOC_E_RCOC_REL_COMPL_IND,
	SCOC_E_RCOC_CREF_IND,
	SCOC_E_RCOC_CC_IND,
	SCOC_E_RCOC_DT1_IND,
	SCOC_E_RCOC_DT2_IND,
	SCOC_E_RCOC_IT_IND,
	SCOC_E_RCOC_OTHER_NPDU,
	SCOC_E_RCOC_ERROR_IND,

	/* Timer Events */
	SCOC_E_T_IAR_EXP,
	SCOC_E_T_IAS_EXP,

	SCOC_E_CONN_TMR_EXP,

	SCOC_E_T_REL_EXP,
	SCOC_E_T_INT_EXP,
	SCOC_E_T_REP_REL_EXP,
};

extern struct osmo_fsm sccp_scoc_fsm;
