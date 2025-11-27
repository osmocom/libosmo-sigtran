#pragma once

#include <stdint.h>
#include <unistd.h>

#include <osmocom/sigtran/mtp_sap.h>

#include "ss7_instance.h"
#include "xua_msg.h"

int mtp3_hmrt_mtp_xfer_request_l4_to_l3(struct osmo_ss7_instance *inst, const struct osmo_mtp_transfer_param *param, uint8_t *user_data, size_t user_data_len);
int mtp3_hmrt_message_for_routing(struct osmo_ss7_instance *inst, struct xua_msg *xua);
