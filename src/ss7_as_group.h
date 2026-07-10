#pragma once

#include <stdint.h>
#include <osmocom/core/linuxlist.h>

#define SS7_AS_GROUP_MAX 432

struct osmo_ss7_as;
struct osmo_ss7_asp;
struct osmo_ss7_instance;

struct ss7_as_group {
	const char *name;
	/*! Every group is assigned a single bit within a 32 bit mask */
	uint32_t mask;
};

int ss7_as_group_add_as(struct osmo_ss7_as *as, const char *name);
int ss7_as_group_del_as(struct osmo_ss7_as *as, const char *name);
void ss7_as_group_update_as(struct osmo_ss7_as *as);
void ss7_as_group_update_asp(struct osmo_ss7_asp *asp);

struct ss7_as_group *ss7_as_group_get(struct osmo_ss7_instance *inst, const char *name);
struct ss7_as_group *ss7_as_group_get_or_alloc(struct osmo_ss7_instance *inst, const char *name);
void ss7_as_group_free(struct osmo_ss7_instance *inst, struct ss7_as_group *group);
void ss7_as_group_free_unused(struct osmo_ss7_instance *inst, struct ss7_as_group *group);
