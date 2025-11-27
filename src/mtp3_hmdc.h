#pragma once

#include "ss7_instance.h"
#include "xua_msg.h"

int mtp3_hmdc_rx_from_l2(struct osmo_ss7_instance *inst, struct xua_msg *xua);
