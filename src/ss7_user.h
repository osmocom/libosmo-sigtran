#pragma once

#include <stdint.h>
#include <unistd.h>
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/mtp_sap.h>

/***********************************************************************
 * SS7 User (MTP SAP)
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

struct osmo_ss7_user *ss7_user_find(struct osmo_ss7_instance *inst, uint8_t service_indicator);
void ss7_user_unregister_all(struct osmo_ss7_user *user);
int ss7_user_mtp_sap_prim_up(const struct osmo_ss7_user *osu, struct osmo_mtp_prim *omp);

struct osmo_mtp_prim *mtp_prim_xfer_ind_alloc(const struct osmo_mtp_transfer_param *param,
					      const uint8_t *user_data, size_t user_data_len);

#define _LOGPSS7U(osu, subsys, level, fmt, args ...) \
	_LOGSS7((osu)->inst, subsys, level, "ss7_user(%s) " fmt, osu->name, ## args)
#define LOGPSS7U(osu, level, fmt, args ...) \
	_LOGPSS7U(osu, DLSS7, level, fmt, ## args)
