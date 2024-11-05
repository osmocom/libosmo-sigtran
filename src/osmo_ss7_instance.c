/* (C) 2015-2017 by Harald Welte <laforge@gnumonks.org>
 * (C) 2023-2024 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/***********************************************************************
 * SS7 Instance
 ***********************************************************************/

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sccp_sap.h>

#include "ss7_asp.h"
#include "ss7_internal.h"
#include "ss7_instance.h"
#include "ss7_linkset.h"
#include "ss7_route_table.h"

static int32_t next_rctx = 1;
static int32_t next_l_rk_id = 1;

static const struct osmo_ss7_pc_fmt default_pc_fmt = {
	.delimiter = '.',
	.component_len = { 3, 8, 3},
};

struct osmo_ss7_instance *
ss7_instance_alloc(void *ctx, uint32_t id)
{
	struct osmo_ss7_instance *inst;

	inst = talloc_zero(ctx, struct osmo_ss7_instance);
	if (!inst)
		return NULL;

	inst->cfg.primary_pc = OSMO_SS7_PC_INVALID;
	inst->cfg.secondary_pc = OSMO_SS7_PC_INVALID;

	inst->cfg.id = id;
	LOGSS7(inst, LOGL_INFO, "Creating SS7 Instance\n");

	INIT_LLIST_HEAD(&inst->linksets);
	INIT_LLIST_HEAD(&inst->as_list);
	INIT_LLIST_HEAD(&inst->asp_list);
	INIT_LLIST_HEAD(&inst->rtable_list);
	INIT_LLIST_HEAD(&inst->xua_servers);
	inst->rtable_system = ss7_route_table_find_or_create(inst, "system");

	/* default point code structure + formatting */
	inst->cfg.pc_fmt.delimiter = '.';
	inst->cfg.pc_fmt.component_len[0] = 3;
	inst->cfg.pc_fmt.component_len[1] = 8;
	inst->cfg.pc_fmt.component_len[2] = 3;

	llist_add_tail(&inst->list, &osmo_ss7_instances);

	INIT_LLIST_HEAD(&inst->cfg.sccp_address_book);

	return inst;
}


/*! \brief Destroy a SS7 Instance
 *  \param[in] inst SS7 Instance to be destroyed */
void osmo_ss7_instance_destroy(struct osmo_ss7_instance *inst)
{
	struct osmo_ss7_linkset *lset, *lset2;
	struct osmo_ss7_as *as, *as2;
	struct osmo_ss7_asp *asp, *asp2;

	OSMO_ASSERT(ss7_initialized);
	LOGSS7(inst, LOGL_INFO, "Destroying SS7 Instance\n");

	llist_for_each_entry_safe(asp, asp2, &inst->asp_list, list)
		osmo_ss7_asp_destroy(asp);

	llist_for_each_entry_safe(as, as2, &inst->as_list, list)
		osmo_ss7_as_destroy(as);

	llist_for_each_entry_safe(lset, lset2, &inst->linksets, list)
		ss7_linkset_destroy(lset);

	llist_del(&inst->list);
	talloc_free(inst);
}


uint32_t osmo_ss7_instance_get_id(const struct osmo_ss7_instance *inst)
{
	return inst->cfg.id;
}

const char *osmo_ss7_instance_get_name(const struct osmo_ss7_instance *inst)
{
	return inst->cfg.name;
}

uint32_t osmo_ss7_instance_get_primary_pc(const struct osmo_ss7_instance *inst)
{
	return inst->cfg.primary_pc;
}

/*! \brief Set the point code format used in given SS7 instance */
int osmo_ss7_instance_set_pc_fmt(struct osmo_ss7_instance *inst,
				uint8_t c0, uint8_t c1, uint8_t c2)
{
	if (c0+c1+c2 > 32)
		return -EINVAL;

	if (c0+c1+c2 > 14)
		LOGSS7(inst, LOGL_NOTICE, "Point Code Format %u-%u-%u "
			"is longer than 14 bits, odd?\n", c0, c1, c2);

	inst->cfg.pc_fmt.component_len[0] = c0;
	inst->cfg.pc_fmt.component_len[1] = c1;
	inst->cfg.pc_fmt.component_len[2] = c2;

	return 0;
}

const struct osmo_ss7_pc_fmt *
osmo_ss7_instance_get_pc_fmt(const struct osmo_ss7_instance *inst)
{
	return &inst->cfg.pc_fmt;
}

/*! Allocate an SCCP instance, if not present yet.
 * \returns inst->sccp. */
struct osmo_sccp_instance *osmo_ss7_ensure_sccp(struct osmo_ss7_instance *inst)
{
	if (inst->sccp)
		return inst->sccp;

	LOGSS7(inst, LOGL_NOTICE, "Creating SCCP instance\n");
	inst->sccp = osmo_sccp_instance_create(inst, NULL);
	return inst->sccp;
}

/*! Get the SCCP instance, if present.
 *  \param[in] inst SS7 Instance on which we operate
 * \returns inst->sccp, may be NULL if no SCCP instance was created yet (see osmo_ss7_ensure_sccp()).
 */
struct osmo_sccp_instance *osmo_ss7_get_sccp(const struct osmo_ss7_instance *inst)
{
	return inst->sccp;
}

bool osmo_ss7_pc_is_local(const struct osmo_ss7_instance *inst, uint32_t pc)
{
	OSMO_ASSERT(ss7_initialized);
	if (osmo_ss7_pc_is_valid(inst->cfg.primary_pc) && pc == inst->cfg.primary_pc)
		return true;
	if (osmo_ss7_pc_is_valid(inst->cfg.secondary_pc) && pc == inst->cfg.secondary_pc)
		return true;
	/* FIXME: Capability Point Codes */
	return false;
}

int osmo_ss7_find_free_rctx(struct osmo_ss7_instance *inst)
{
	int32_t rctx;

	for (rctx = next_rctx; rctx; rctx = ++next_rctx) {
		if (!osmo_ss7_as_find_by_rctx(inst, next_rctx))
			return rctx;
	}
	return -1;
}

uint32_t ss7_find_free_l_rk_id(struct osmo_ss7_instance *inst)
{
	uint32_t l_rk_id;

	for (l_rk_id = next_l_rk_id; next_l_rk_id; l_rk_id = ++next_l_rk_id) {
		if (!osmo_ss7_as_find_by_l_rk_id(inst, next_l_rk_id))
			return l_rk_id;
	}
	return -1;
}

/***********************************************************************
 * SS7 Application Server
 ***********************************************************************/

/*! \brief Find Application Server by given name
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of AS
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_by_name(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(as, &inst->as_list, list) {
		if (!strcmp(name, as->cfg.name))
			return as;
	}
	return NULL;
}

/*! \brief Find Application Server by given routing context
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] rctx Routing Context
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_by_rctx(struct osmo_ss7_instance *inst, uint32_t rctx)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(as, &inst->as_list, list) {
		if (as->cfg.routing_key.context == rctx)
			return as;
	}
	return NULL;
}

/*! \brief Find Application Server by given local routing key ID
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] l_rk_id Local Routing Key ID
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_by_l_rk_id(struct osmo_ss7_instance *inst, uint32_t l_rk_id)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(as, &inst->as_list, list) {
		if (as->cfg.routing_key.l_rk_id == l_rk_id)
			return as;
	}
	return NULL;
}

/*! \brief Find Application Server (AS) by given protocol.
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] proto Protocol identifier that must match
 *  \returns pointer to AS on success; NULL otherwise
 *  If an AS has an ASP also matching the given protocol, that AS is preferred.
 *  If there are multiple matches, return the first matching AS. */
struct osmo_ss7_as *osmo_ss7_as_find_by_proto(struct osmo_ss7_instance *inst,
					      enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_as *as;
	struct osmo_ss7_as *as_without_asp = NULL;

	OSMO_ASSERT(ss7_initialized);

	/* Loop through the list with AS and try to find one where the proto
	   matches up */
	llist_for_each_entry(as, &inst->as_list, list) {
		if (as->cfg.proto != proto)
			continue;

		/* Put down the first AS that matches the proto, just in
		 * case we will not find any matching ASP */
		if (!as_without_asp)
			as_without_asp = as;

		/* Check if the candicate we have here has any suitable ASP */
		if (osmo_ss7_asp_find_by_proto(as, proto))
			return as;
	}

	/* Return with the second best find, if there is any */
	return as_without_asp;
}

/*! \brief Find or Create Application Server
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] name Name of Application Server
 *  \param[in] proto Protocol of Application Server
 *  \returns pointer to Application Server on success; NULL otherwise */
struct osmo_ss7_as *
osmo_ss7_as_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			   enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_as *as;

	OSMO_ASSERT(ss7_initialized);
	as = osmo_ss7_as_find_by_name(inst, name);

	if (as && as->cfg.proto != proto)
		return NULL;

	if (!as) {
		as = ss7_as_alloc(inst, name, proto);
		if (!as)
			return NULL;
		LOGPAS(as, DLSS7, LOGL_INFO, "Created AS\n");
	}

	return as;
}

/***********************************************************************
 * SS7 Application Server Process
 ***********************************************************************/

struct osmo_ss7_asp *
osmo_ss7_asp_find_by_name(struct osmo_ss7_instance *inst, const char *name)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	llist_for_each_entry(asp, &inst->asp_list, list) {
		if (!strcmp(name, asp->cfg.name))
			return asp;
	}
	return NULL;
}

/*! \brief Find an ASP that matches the given ASP protocol (xUA variant).
 *  \param[in] as Application Server in which to look for \ref asp
 *  \param[in] proto ASP protocol (xUA variant) to match
 *  \returns SS7 ASP in case a matching one is found; NULL otherwise */
struct osmo_ss7_asp *
osmo_ss7_asp_find_by_proto(struct osmo_ss7_as *as,
			   enum osmo_ss7_asp_protocol proto)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		if (as->cfg.asps[i] && as->cfg.asps[i]->cfg.proto == proto)
			return as->cfg.asps[i];
	}

	return NULL;
}

struct osmo_ss7_asp *
osmo_ss7_asp_find2(struct osmo_ss7_instance *inst, const char *name,
		   uint16_t remote_port, uint16_t local_port,
		   int trans_proto, enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(inst, name);
	if (!asp)
		return NULL;

	if (asp->cfg.remote.port != remote_port || asp->cfg.local.port != local_port)
		return NULL;
	if (asp->cfg.trans_proto != trans_proto)
		return NULL;
	if (asp->cfg.proto != proto)
		return NULL;

	return asp;
}

struct osmo_ss7_asp *
osmo_ss7_asp_find(struct osmo_ss7_instance *inst, const char *name,
		  uint16_t remote_port, uint16_t local_port,
		  enum osmo_ss7_asp_protocol proto)
{
	const int trans_proto = ss7_default_trans_proto_for_asp_proto(proto);

	return osmo_ss7_asp_find2(inst, name,
				  remote_port, local_port,
				  trans_proto, proto);
}

struct osmo_ss7_asp *
osmo_ss7_asp_find_or_create2(struct osmo_ss7_instance *inst, const char *name,
			     uint16_t remote_port, uint16_t local_port,
			     int trans_proto, enum osmo_ss7_asp_protocol proto)
{
	struct osmo_ss7_asp *asp;

	OSMO_ASSERT(ss7_initialized);
	asp = osmo_ss7_asp_find_by_name(inst, name);
	if (asp) {
		if (asp->cfg.remote.port != remote_port || asp->cfg.local.port != local_port)
			return NULL;
		if (asp->cfg.trans_proto != trans_proto)
			return NULL;
		if (asp->cfg.proto != proto)
			return NULL;
		return asp;
	}

	return ss7_asp_alloc(inst, name, remote_port, local_port, trans_proto, proto);
}

struct osmo_ss7_asp *
osmo_ss7_asp_find_or_create(struct osmo_ss7_instance *inst, const char *name,
			    uint16_t remote_port, uint16_t local_port,
			    enum osmo_ss7_asp_protocol proto)
{
	const int trans_proto = ss7_default_trans_proto_for_asp_proto(proto);

	return osmo_ss7_asp_find_or_create2(inst, name,
					    remote_port, local_port,
					    trans_proto, proto);
}

/***********************************************************************
 * SS7 Point Code Parsing / Printing
 ***********************************************************************/

/* like strcat() but appends a single character */
static int strnappendchar(char *str, char c, size_t n)
{
	unsigned int curlen = strlen(str);

	if (n < curlen + 2)
		return -1;

	str[curlen] = c;
	str[curlen+1] = '\0';

	return curlen+1;
}

/* generate a format string for formatting a point code. The result can
 * e.g. be used with sscanf() or sprintf() */
static const char *gen_pc_fmtstr(const struct osmo_ss7_pc_fmt *pc_fmt,
				 unsigned int *num_comp_exp)
{
	static char buf[MAX_PC_STR_LEN];
	unsigned int num_comp = 0;

	buf[0] = '\0';
	strcat(buf, "%u");
	num_comp++;

	if (pc_fmt->component_len[1] == 0)
		goto out;
	strnappendchar(buf, pc_fmt->delimiter, sizeof(buf));
	strcat(buf, "%u");
	num_comp++;

	if (pc_fmt->component_len[2] == 0)
		goto out;
	strnappendchar(buf, pc_fmt->delimiter, sizeof(buf));
	strcat(buf, "%u");
	num_comp++;
out:
	if (num_comp_exp)
		*num_comp_exp = num_comp;
	return buf;
}

/* get number of components we expect for a point code, depending on the
 * configuration of this ss7_instance */
static unsigned int num_pc_comp_exp(const struct osmo_ss7_pc_fmt *pc_fmt)
{
	unsigned int num_comp_exp = 1;

	if (pc_fmt->component_len[1])
		num_comp_exp++;
	if (pc_fmt->component_len[2])
		num_comp_exp++;

	return num_comp_exp;
}

/* get the number of bits we must shift the given component of a point
 * code in this ss7_instance */
static unsigned int get_pc_comp_shift(const struct osmo_ss7_pc_fmt *pc_fmt,
					unsigned int comp_num)
{
	uint32_t pc_width = osmo_ss7_pc_width(pc_fmt);
	switch (comp_num) {
	case 0:
		return pc_width - pc_fmt->component_len[0];
	case 1:
		return pc_width - pc_fmt->component_len[0] - pc_fmt->component_len[1];
	case 2:
		return 0;
	default:
		/* Invalid number of components */
		OSMO_ASSERT(false);
	}
}

static uint32_t pc_comp_shift_and_mask(const struct osmo_ss7_pc_fmt *pc_fmt,
					unsigned int comp_num, uint32_t pc)
{
	unsigned int shift = get_pc_comp_shift(pc_fmt, comp_num);
	uint32_t mask = (1 << pc_fmt->component_len[comp_num]) - 1;

	return (pc >> shift) & mask;
}

/* parse a point code according to the structure configured for this
 * ss7_instance */
int osmo_ss7_pointcode_parse(const struct osmo_ss7_instance *inst, const char *str)
{
	unsigned int component[3];
	const struct osmo_ss7_pc_fmt *pc_fmt = inst ? &inst->cfg.pc_fmt : &default_pc_fmt;
	unsigned int num_comp_exp = num_pc_comp_exp(pc_fmt);
	const char *fmtstr = gen_pc_fmtstr(pc_fmt, &num_comp_exp);
	int i, rc;

	rc = sscanf(str, fmtstr, &component[0], &component[1], &component[2]);
	/* ensure all components were parsed */
	if (rc != num_comp_exp)
		goto err;

	/* check none of the component values exceeds what can be
	 * represented within its bit-width */
	for (i = 0; i < num_comp_exp; i++) {
		if (component[i] >= (1 << pc_fmt->component_len[i]))
			goto err;
	}

	/* shift them all together */
	rc = (component[0] << get_pc_comp_shift(pc_fmt, 0));
	if (num_comp_exp > 1)
		rc |= (component[1] << get_pc_comp_shift(pc_fmt, 1));
	if (num_comp_exp > 2)
		rc |= (component[2] << get_pc_comp_shift(pc_fmt, 2));

	return rc;

err:
	LOGSS7(inst, LOGL_NOTICE, "Error parsing Pointcode '%s'\n", str);
	return -EINVAL;
}

const char *osmo_ss7_pointcode_print_buf(char *buf, size_t len, const struct osmo_ss7_instance *inst, uint32_t pc)
{
	const struct osmo_ss7_pc_fmt *pc_fmt;
	unsigned int num_comp_exp;
	const char *fmtstr;

	if (!osmo_ss7_pc_is_valid(pc))
		return "(no PC)";

	pc_fmt = inst ? &inst->cfg.pc_fmt : &default_pc_fmt;
	num_comp_exp = num_pc_comp_exp(pc_fmt);
	fmtstr = gen_pc_fmtstr(pc_fmt, &num_comp_exp);
	OSMO_ASSERT(fmtstr);
	snprintf(buf, len, fmtstr,
		 pc_comp_shift_and_mask(pc_fmt, 0, pc),
		 pc_comp_shift_and_mask(pc_fmt, 1, pc),
		 pc_comp_shift_and_mask(pc_fmt, 2, pc));

	return buf;
}


/* print a pointcode according to the structure configured for this
 * ss7_instance */
const char *osmo_ss7_pointcode_print(const struct osmo_ss7_instance *inst, uint32_t pc)
{
	static char buf[MAX_PC_STR_LEN];
	return osmo_ss7_pointcode_print_buf(buf, sizeof(buf), inst, pc);
}

/* same as osmo_ss7_pointcode_print() but using a separate buffer, useful for multiple point codes in the
 * same LOGP/printf. */
const char *osmo_ss7_pointcode_print2(const struct osmo_ss7_instance *inst, uint32_t pc)
{
	static char buf[MAX_PC_STR_LEN];
	return osmo_ss7_pointcode_print_buf(buf, sizeof(buf), inst, pc);
}

int osmo_ss7_pointcode_parse_mask_or_len(const struct osmo_ss7_instance *inst, const char *in)
{
	unsigned int width = osmo_ss7_pc_width(inst ? &inst->cfg.pc_fmt : &default_pc_fmt);

	if (in[0] == '/') {
		/* parse mask by length */
		int masklen = atoi(in+1);
		if (masklen < 0 || masklen > 32)
			return -EINVAL;
		if (masklen == 0)
			return 0;
		return (0xFFFFFFFF << (width - masklen)) & ((1 << width)-1);
	}
	/* parse mask as point code */
	return osmo_ss7_pointcode_parse(inst, in);
}
