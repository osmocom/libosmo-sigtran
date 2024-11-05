#pragma once

#include <stdint.h>
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/mtp_sap.h>

/***********************************************************************
 * SS7 Linksets
 ***********************************************************************/

struct osmo_ss7_instance;

struct osmo_ss7_user {
	/* pointer back to SS7 instance */
	struct osmo_ss7_instance *inst;
	/* name of the user */
	const char *name;
	/* primitive call-back for incoming MTP primitives */
	osmo_prim_cb prim_cb;
	/* private data */
	void *priv;
};

int ss7_mtp_to_user(struct osmo_ss7_instance *inst, struct osmo_mtp_prim *omp);
