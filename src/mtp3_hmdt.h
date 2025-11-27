#pragma once

#include "ss7_instance.h"
#include "xua_msg.h"

int mtp3_hmdt_message_for_distribution(struct osmo_ss7_instance *inst, struct xua_msg *xua);
