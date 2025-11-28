#pragma once

#include <stdint.h>
#include <unistd.h>

#include <osmocom/sigtran/mtp_sap.h>

#include "ss7_instance.h"
#include "xua_msg.h"

int mtp3_rtpc_rx_msg_for_inaccessible_sp(struct osmo_ss7_instance *inst, const struct xua_msg *xua);
