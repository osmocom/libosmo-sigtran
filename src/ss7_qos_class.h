#pragma once

#include "ss7_instance.h"

/***********************************************************************
 * QoS Class
 ***********************************************************************/

struct ss7_qos_class {
	struct llist_head list;
	struct osmo_ss7_instance *inst;

	uint8_t qos_class;
	uint8_t ip_dscp;
};

struct ss7_qos_class *
ss7_qos_class_find(struct osmo_ss7_instance *inst, uint8_t qos_class);
struct ss7_qos_class *
ss7_qos_class_create(struct osmo_ss7_instance *inst, uint8_t qos_class, uint8_t ip_dscp);
void ss7_qos_class_destroy(struct ss7_qos_class *qos);
struct ss7_qos_class *
ss7_qos_class_find_or_create(struct osmo_ss7_instance *inst, uint8_t qos_class, uint8_t ip_dscp);
void ss7_qos_class_update(struct ss7_qos_class *qos);
