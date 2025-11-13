#pragma once

#include <stdint.h>
#include <unistd.h>
#include <osmocom/core/prim.h>
#include <osmocom/sigtran/protocol/mtp.h>
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

void ss7_user_unregister_all(struct osmo_ss7_user *user);
int ss7_user_mtp_sap_prim_up(const struct osmo_ss7_user *osu, struct osmo_mtp_prim *omp);

struct osmo_mtp_prim *mtp_prim_xfer_ind_alloc(const struct osmo_mtp_transfer_param *param,
					      const uint8_t *user_data, size_t user_data_len);

struct osmo_mtp_prim *mtp_prim_status_ind_alloc(uint32_t dpc,
						enum mtp_unavail_cause cause,
						bool cong_level_present,
						uint8_t cong_level);
void mtp_resume_ind_up_to_all_users(struct osmo_ss7_instance *s7i, uint32_t pc);
void mtp_pause_ind_up_to_all_users(struct osmo_ss7_instance *s7i, uint32_t pc);
void mtp_status_ind_up_to_all_users(struct osmo_ss7_instance *s7i,
				    uint32_t dpc, enum mtp_unavail_cause cause,
				    bool cong_level_present, uint8_t cong_level);


#define _LOGPSS7U(osu, subsys, level, fmt, args ...) \
	_LOGSS7((osu)->inst, subsys, level, "ss7_user(%s) " fmt, osu->name, ## args)
#define LOGPSS7U(osu, level, fmt, args ...) \
	_LOGPSS7U(osu, DLSS7, level, fmt, ## args)
