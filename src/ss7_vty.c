/* Core SS7 Instance/Linkset/Link VTY Interface */

/* (C) 2015-2021 by Harald Welte <laforge@gnumonks.org>
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

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/protocol/mtp.h>

#include "xua_internal.h"
#include <osmocom/sigtran/sccp_sap.h>
#include "sccp_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_combined_linkset.h"
#include <ss7_linkset.h>
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"
#include "ss7_user.h"
#include "ss7_vty.h"
#include "ss7_xua_srv.h"
#ifdef WITH_TCAP_LOADSHARING
#include "tcap_as_loadshare_vty.h"
#endif /* WITH_TCAP_LOADSHARING */

#define ROUTE_PRIO_RANGE_STR "<1-9>"
#define ROUTE_PRIO_RANGE_HELP_STR "Priority\n"
#define ROUTE_PRIO_VAR_STR "(" ROUTE_PRIO_RANGE_STR "|default)"
#define ROUTE_PRIO_VAR_HELP_STR \
	ROUTE_PRIO_RANGE_HELP_STR \
	"Default Priority (5)\n"

const struct value_string ipproto_vals[] = {
	{ IPPROTO_SCTP,		"sctp" },
	{ IPPROTO_TCP,		"tcp" },
	{ 0, NULL },
};

int parse_trans_proto(const char *protocol)
{
	return get_string_value(ipproto_vals, protocol);
}

enum osmo_ss7_asp_protocol parse_asp_proto(const char *protocol)
{
	return get_string_value(osmo_ss7_asp_protocol_vals, protocol);
}

/***********************************************************************
 * Core CS7 Configuration
 ***********************************************************************/

enum cs7_role_t cs7_role;
void *g_ctx;

static struct cmd_node cs7_node = {
	L_CS7_NODE,
	"%s(config-cs7)# ",
	1,
};

DEFUN_ATTR(cs7_instance, cs7_instance_cmd,
	   "cs7 instance <0-15>",
	   CS7_STR "Configure a SS7 Instance\n" INST_STR
	   "Number of the instance\n",
	   CMD_ATTR_IMMEDIATE)
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;

	inst = osmo_ss7_instance_find_or_create(g_ctx, id);
	if (!inst) {
		vty_out(vty, "Unable to create SS7 Instance %d%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = L_CS7_NODE;
	vty->index = inst;
	vty->index_sub = &inst->cfg.description;

	return CMD_SUCCESS;
}

const struct value_string mtp_network_indicator_vals[] = {
	{ MTP_NI_INTERNATIONAL,		"international" },
	{ MTP_NI_SPARE_INTERNATIONAL,	"spare" },
	{ MTP_NI_NATIONAL,		"national" },
	{ MTP_NI_RESERVED_NATIONAL,	"reserved" },
	{ 0,	NULL }
};

/* cs7 network-indicator */
DEFUN_ATTR(cs7_net_ind, cs7_net_ind_cmd,
	   "network-indicator (international | national | reserved | spare)",
	   "Configure the Network Indicator\n"
	   "International Network\n"
	   "National Network\n"
	   "Reserved Network\n"
	   "Spare Network\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	int ni = get_string_value(mtp_network_indicator_vals, argv[0]);

	inst->cfg.network_indicator = ni;
	return CMD_SUCCESS;
}

/* TODO: cs7 point-code format */
DEFUN_ATTR(cs7_pc_format, cs7_pc_format_cmd,
	   "point-code format <1-24> [<1-23>] [<1-22>]",
	   PC_STR "Configure Point Code Format\n"
	   "Length of first PC component\n"
	   "Length of second PC component\n"
	   "Length of third PC component\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	int argind = 0;

	inst->cfg.pc_fmt.component_len[0] = atoi(argv[argind++]);

	if (argc >= 2)
		inst->cfg.pc_fmt.component_len[1] = atoi(argv[argind++]);
	else
		inst->cfg.pc_fmt.component_len[1] = 0;

	if (argc >= 3)
		inst->cfg.pc_fmt.component_len[2] = atoi(argv[argind++]);
	else
		inst->cfg.pc_fmt.component_len[2] = 0;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_pc_format_def, cs7_pc_format_def_cmd,
	   "point-code format default",
	   PC_STR "Configure Point Code Format\n"
	   "Default Point Code Format (3.8.3)\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	inst->cfg.pc_fmt.component_len[0] = 3;
	inst->cfg.pc_fmt.component_len[1] = 8;
	inst->cfg.pc_fmt.component_len[2] = 3;
	return CMD_SUCCESS;
}


/* cs7 point-code delimiter */
DEFUN_ATTR(cs7_pc_delimiter, cs7_pc_delimiter_cmd,
	   "point-code delimiter (default|dash)",
	   PC_STR "Configure Point Code Delimiter\n"
	   "Use dot as delimiter\n"
	   "User dash as delimiter\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;

	if (!strcmp(argv[0], "dash"))
		inst->cfg.pc_fmt.delimiter = '-';
	else
		inst->cfg.pc_fmt.delimiter = '.';

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_point_code, cs7_point_code_cmd,
	   "point-code POINT_CODE",
	   "Configure the local Point Code\n"
	   "Point Code\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	int pc = osmo_ss7_pointcode_parse(inst, argv[0]);
	if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	inst->cfg.primary_pc = pc;
	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_secondary_pc, cs7_secondary_pc_cmd,
	   "secondary-pc POINT_CODE",
	   "Configure the local Secondary Point Code\n"
	   "Point Code\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	int pc = osmo_ss7_pointcode_parse(inst, argv[0]);
	if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	inst->cfg.secondary_pc = pc;
	return CMD_SUCCESS;
}

/* TODO: cs7 capability-pc */
DEFUN_ATTR(cs7_permit_dyn_rkm, cs7_permit_dyn_rkm_cmd,
	   "xua rkm routing-key-allocation (static-only|dynamic-permitted)",
	   "SIGTRAN xxxUA related\n" "Routing Key Management\n"
	   "Routing Key Management Allocation Policy\n"
	   "Only static (pre-configured) Routing Keys permitted\n"
	   "Dynamically allocate Routing Keys for what ASPs request\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;

	if (!strcmp(argv[0], "dynamic-permitted"))
		inst->cfg.permit_dyn_rkm_alloc = true;
	else
		inst->cfg.permit_dyn_rkm_alloc = false;

	return CMD_SUCCESS;
}


DEFUN_ATTR(cs7_opc_dpc_shift, cs7_opc_dpc_shift_cmd,
	   "sls-opc-dpc [opc-shift] [<0-8>] [dpc-shift] [<0-8>]",
	   "Shift OPC and DPC bits used during routing decision\n"
	   "Shift OPC bits used during routing decision\n"
	   "How many bits from ITU OPC field (starting from least-significant-bit) to skip (default=0). 6 bits are always used\n"
	   "Shift DPC bits used during routing decision\n"
	   "How many bits from ITU DPC field (starting from least-significant-bit) to skip (default=0). 6 bits are always used\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	if (argc == 4)
		inst->cfg.dpc_shift = atoi(argv[3]);
	else if (argc == 3)
		inst->cfg.dpc_shift = 0;
	if (argc >= 2)
		inst->cfg.opc_shift = atoi(argv[1]);
	else if (argc == 1)
		inst->cfg.opc_shift = 0;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_sls_shift, cs7_sls_shift_cmd,
	   "sls-shift <0-6>",
	   "Shift SLS bits used during routing decision\n"
	   "How many bits from derivated 7-bit extended-SLS (OPC, DPC, SLS) field (starting from least-significant-bit) to skip\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	inst->cfg.sls_shift = atoi(argv[0]);

	return CMD_SUCCESS;
}

/* timer xua <name> <1-999999>
 * (cmdstr and doc are dynamically generated from ss7_instance_xua_timer_names.) */
DEFUN_ATTR(cs7_timer_xua, cs7_timer_xua_cmd,
	   NULL, NULL, CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	enum ss7_instance_xua_timer timer = get_string_value(ss7_instance_xua_timer_names, argv[0]);

	if (timer <= 0 || timer >= SS7_INST_XUA_TIMERS_LEN) {
		vty_out(vty, "%% Invalid timer: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_tdef_set(inst->cfg.T_defs_xua, timer, atoi(argv[1]), OSMO_TDEF_S);
	return CMD_SUCCESS;
}

static void gen_cs7_timer_xua_cmd_strs(struct cmd_element *cmd)
{
	int i;
	char *cmd_str = NULL;
	char *doc_str = NULL;

	OSMO_ASSERT(cmd->string == NULL);
	OSMO_ASSERT(cmd->doc == NULL);

	osmo_talloc_asprintf(tall_vty_ctx, cmd_str, "timer xua (");
	osmo_talloc_asprintf(tall_vty_ctx, doc_str,
			     "Configure CS7 Instance default timer values\n"
			     "Configure CS7 Instance default xua timer values\n");

	for (i = 0; ss7_instance_xua_timer_names[i].str; i++) {
		const struct osmo_tdef *def;
		enum ss7_asp_xua_timer timer;

		timer = ss7_instance_xua_timer_names[i].value;
		def = osmo_tdef_get_entry((struct osmo_tdef *)&ss7_instance_xua_timer_defaults, timer);
		OSMO_ASSERT(def);

		osmo_talloc_asprintf(tall_vty_ctx, cmd_str, "%s%s",
				     i ? "|" : "",
				     ss7_instance_xua_timer_names[i].str);
		osmo_talloc_asprintf(tall_vty_ctx, doc_str, "%s (default: %lu)\n",
				     def->desc,
				     def->default_val);
	}

	osmo_talloc_asprintf(tall_vty_ctx, cmd_str, ") <1-999999>");
	osmo_talloc_asprintf(tall_vty_ctx, doc_str,
			     "Timer value, in seconds\n");

	cmd->string = cmd_str;
	cmd->doc = doc_str;
}

static void write_one_cs7(struct vty *vty, struct osmo_ss7_instance *inst, bool show_dyn_config);

static int write_all_cs7(struct vty *vty, bool show_dyn_config)
{
	struct osmo_ss7_instance *inst;

	llist_for_each_entry(inst, &osmo_ss7_instances, list)
		write_one_cs7(vty, inst, show_dyn_config);

	return 0;
}

static int config_write_cs7(struct vty *vty)
{
	return write_all_cs7(vty, false);
}

DEFUN(show_cs7_user, show_cs7_user_cmd,
	"show cs7 instance <0-15> users",
	SHOW_STR CS7_STR INST_STR INST_STR "User Table\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;
	unsigned int i;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	for (i = 0; i < ARRAY_SIZE(inst->user); i++) {
		const struct osmo_ss7_user *user = inst->user[i];
		if (!user)
			continue;
		vty_out(vty, "SI %u: %s%s", i, user->name, VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

/* TODO: Links + Linksets */

/***********************************************************************
 * Routing Table Configuration
 ***********************************************************************/

static struct cmd_node rtable_node = {
	L_CS7_RTABLE_NODE,
	"%s(config-cs7-rt)# ",
	1,
};

DEFUN_ATTR(cs7_route_table, cs7_route_table_cmd,
	   "route-table system",
	   "Specify the name of the route table\n"
	   "Name of the route table\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_ss7_route_table *rtable;

	rtable = inst->rtable_system;
	vty->node = L_CS7_RTABLE_NODE;
	vty->index = rtable;
	vty->index_sub = &rtable->cfg.description;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_rt_upd, cs7_rt_upd_cmd,
	   "update route POINT_CODE MASK linkset LS_NAME [priority] [" ROUTE_PRIO_VAR_STR "] [qos-class] [" QOS_CLASS_VAR_STR "]",
	   "Update the Route\n"
	   "Update the Route\n"
	   "Destination Point Code\n"
	   "Point Code Mask\n"
	   "Specify Destination Linkset\n"
	   "Linkset Name\n"
	   "Specify Priority (lower value means higher priority)\n"
	   ROUTE_PRIO_VAR_HELP_STR
	   "Specify QoS Class\n"
	   QOS_CLASS_VAR_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_route_table *rtable = vty->index;
	struct osmo_ss7_route *rt;
	int dpc = osmo_ss7_pointcode_parse(rtable->inst, argv[0]);
	int mask = osmo_ss7_pointcode_parse_mask_or_len(rtable->inst, argv[1]);
	const char *ls_name = argv[2];
	unsigned int argind;
	int rc;

	if (dpc < 0) {
		vty_out(vty, "%% Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mask < 0) {
		vty_out(vty, "%% Invalid point code (%s)%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	switch (argc) {
	case 3:
		break; /* Continue below */
	case 5:
		if (strcmp(argv[3], "priority") != 0 &&
		    strcmp(argv[3], "qos-class") != 0)
			return CMD_WARNING;
		break; /* Parse values below */
	case 7:
		if (strcmp(argv[3], "priority") != 0 &&
		    strcmp(argv[5], "qos-class") != 0)
			return CMD_WARNING;
		break; /* Parse values below */
	default:
		vty_out(vty, "%% Incomplete command (missing an argument?)%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	rt = ss7_route_alloc(rtable, dpc, mask, false);
	if (!rt) {
		vty_out(vty, "%% Cannot allocate new route%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if ((rc = ss7_route_set_linkset(rt, ls_name)) < 0) {
		vty_out(vty, "%% Cannot find linkset %s%s", ls_name, VTY_NEWLINE);
		goto destroy_warning;
	}

	argind = 3;
	if (argc > argind && !strcmp(argv[argind], "priority")) {
		argind++;
		if (strcmp(argv[argind], "default") != 0)
			rt->cfg.priority = atoi(argv[argind]);
		argind++;
	}

	if (argc > argind && !strcmp(argv[argind], "qos-class")) {
		argind++;
		if (strcmp(argv[argind], "default") != 0)
			rt->cfg.qos_class = atoi(argv[argind]);
		argind++;
	}

	if ((rc = ss7_route_insert(rt)) < 0) {
		char buf_err[128];
		strerror_r(-rc, buf_err, sizeof(buf_err));
		vty_out(vty, "%% Cannot insert route %s/%s to %s: %s (%d)%s",
			argv[0], argv[1], argv[2],
			buf_err, rc, VTY_NEWLINE);
		goto destroy_warning;
	}

	return CMD_SUCCESS;

destroy_warning:
	ss7_route_destroy(rt);
	return CMD_WARNING;
}

DEFUN_ATTR(cs7_rt_rem, cs7_rt_rem_cmd,
	   "remove route POINT_CODE MASK",
	   "Remove a Route\n"
	   "Remove a Route\n"
	   "Destination Point Code\n"
	   "Point Code Mask\n"
	   "Point Code Length\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_route_table *rtable = vty->index;
	struct osmo_ss7_route *rt;
	int dpc = osmo_ss7_pointcode_parse(rtable->inst, argv[0]);
	int mask = osmo_ss7_pointcode_parse_mask_or_len(rtable->inst, argv[1]);

	if (dpc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (mask < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	rt = ss7_route_table_find_route_by_dpc_mask(rtable, dpc, mask, false);
	if (!rt) {
		vty_out(vty, "cannot find route to be deleted%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ss7_route_destroy(rt);
	return CMD_SUCCESS;
}

static void write_one_rtable(struct vty *vty, struct osmo_ss7_route_table *rtable)
{
	struct osmo_ss7_combined_linkset *clset;
	struct osmo_ss7_route *rt;

	vty_out(vty, " route-table %s%s", rtable->cfg.name, VTY_NEWLINE);
	if (rtable->cfg.description)
		vty_out(vty, "  description %s%s", rtable->cfg.description, VTY_NEWLINE);
	llist_for_each_entry(clset, &rtable->combined_linksets, list) {
		llist_for_each_entry(rt, &clset->routes, list) {
			if (rt->cfg.dyn_allocated)
				continue;
			vty_out(vty, "  update route %s %s linkset %s",
				osmo_ss7_pointcode_print(rtable->inst, rt->cfg.pc),
				osmo_ss7_pointcode_print2(rtable->inst, rt->cfg.mask),
				rt->cfg.linkset_name);
			if (rt->cfg.priority != OSMO_SS7_ROUTE_PRIO_DEFAULT)
				vty_out(vty, " priority %u", rt->cfg.priority);
			if (rt->cfg.qos_class)
				vty_out(vty, " qos-class %u", rt->cfg.qos_class);
			vty_out(vty, "%s", VTY_NEWLINE);
		}
	}
}

/* "filter_pc == OSMO_SS7_PC_INVALID" means "show all" */
static void vty_dump_rtable(struct vty *vty, struct osmo_ss7_route_table *rtbl, uint32_t filter_pc)
{
	struct osmo_ss7_combined_linkset *clset;
	struct osmo_ss7_route *rt;

	vty_out(vty, "Routing table = %s%s", rtbl->cfg.name, VTY_NEWLINE);
	vty_out(vty, "C=Cong Q=QoS P=Prio%s", VTY_NEWLINE);
	vty_out(vty, "%s", VTY_NEWLINE);
	vty_out(vty, "Destination            C Q P Linkset Name        Linkset Non-adj Route%s", VTY_NEWLINE);
	vty_out(vty, "---------------------- - - - ------------------- ------- ------- -------%s", VTY_NEWLINE);

	llist_for_each_entry(clset, &rtbl->combined_linksets, list) {
		if ((filter_pc != OSMO_SS7_PC_INVALID) && ((filter_pc & clset->cfg.mask) != clset->cfg.pc))
			continue; /* Skip combined linksets not matching destination */

		bool clset_avail = ss7_combined_linkset_is_available(clset);
		llist_for_each_entry(rt, &clset->routes, list) {
			bool dst_avail = ss7_route_dest_is_available(rt);
			bool first_rt_in_clset = (rt == llist_first_entry(&clset->routes, struct osmo_ss7_route, list));
			const char *nonadj_str, *rtavail_str;
			/* Print route str only in first rt in combined linkset.
			 * This allows users to easily determine visually combined
			 * linksets: */
			const char *rt_str, *clsetavail_str;
			if (first_rt_in_clset) {
				rt_str = osmo_ss7_route_print(rt);
				clsetavail_str = clset_avail ? "acces" : "INACC";
			} else {
				rt_str = "";
				clsetavail_str = "";
			}
			switch (rt->status) {
			case OSMO_SS7_ROUTE_STATUS_UNAVAILABLE:
				nonadj_str = "PROHIB";
				rtavail_str = "UNAVAIL";
				break;
			case OSMO_SS7_ROUTE_STATUS_AVAILABLE:
				nonadj_str = "allowed";
				rtavail_str = dst_avail ? "avail" : "UNAVAIL";
				break;
			case OSMO_SS7_ROUTE_STATUS_RESTRICTED:
				nonadj_str = "RESTRIC";
				rtavail_str = dst_avail ? "RESTRIC" : "UNAVAIL";
				break;
			default:
				OSMO_ASSERT(0);
			}
			vty_out(vty, "%-16s %-5s %c %c %u %-19s %-7s %-7s %-7s %-3s%s",
				rt_str,
				clsetavail_str,
				' ',
				'0' + rt->cfg.qos_class,
				rt->cfg.priority,
				rt->cfg.linkset_name,
				dst_avail ? "avail" : "UNAVAIL",
				nonadj_str,
				rtavail_str,
				rt->cfg.dyn_allocated ? "dyn" : "",
				VTY_NEWLINE);
		}
	}
}

DEFUN(show_cs7_route, show_cs7_route_cmd,
	"show cs7 instance <0-15> route [POINT_CODE]",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Routing Table\n"
	"Destination Point Code\n")
{
	int id = atoi(argv[0]);
	struct osmo_ss7_instance *inst;
	uint32_t filter_pc = OSMO_SS7_PC_INVALID;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc > 1) {
		int pc = osmo_ss7_pointcode_parse(inst, argv[1]);
		if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
			vty_out(vty, "Invalid point code (%s)%s", argv[1], VTY_NEWLINE);
			return CMD_WARNING;
		}
		filter_pc = (uint32_t)pc;
	}

	vty_dump_rtable(vty, inst->rtable_system, filter_pc);
	return CMD_SUCCESS;
}

DEFUN(show_cs7_route_bindingtable, show_cs7_route_bindingtable_cmd,
	"show cs7 instance <0-15> route binding-table [POINT_CODE] [all-matches]",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Routing Table\n"
	"Display binding table\n"
	"Destination Point Code\n"
	"Display all matching Combination Links\n")
{
	int id = atoi(argv[0]);
	bool all = argc > 2;
	struct osmo_ss7_instance *inst;
	uint32_t filter_pc = OSMO_SS7_PC_INVALID;
	struct osmo_ss7_combined_linkset *clset;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (argc > 1) {
		int pc = osmo_ss7_pointcode_parse(inst, argv[1]);
		if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
			vty_out(vty, "Invalid point code (%s)%s", argv[1], VTY_NEWLINE);
			return CMD_WARNING;
		}
		filter_pc = (uint32_t)pc;
	}

	llist_for_each_entry(clset, &inst->rtable_system->combined_linksets, list) {
		if ((filter_pc != OSMO_SS7_PC_INVALID) && ((filter_pc & clset->cfg.mask) != clset->cfg.pc))
			continue; /* Skip combined linksets not matching destination */

		vty_out(vty, "%sCombined Linkset: dpc=%u=%s, mask=0x%x=%s, prio=%u%s", VTY_NEWLINE,
			(clset)->cfg.pc, osmo_ss7_pointcode_print(clset->rtable->inst, clset->cfg.pc),
			(clset)->cfg.mask, osmo_ss7_pointcode_print2(clset->rtable->inst, clset->cfg.mask),
			(clset)->cfg.priority, VTY_NEWLINE);
		vty_out(vty, "Loadshare Seed  Normal Route           Available  Alternative Route      Available%s", VTY_NEWLINE);
		vty_out(vty, "--------------  ---------------------  ---------  ---------------------  ---------%s", VTY_NEWLINE);

		for (unsigned int i = 0; i < ARRAY_SIZE(clset->esls_table); i++) {
			struct osmo_ss7_esls_entry *e = &clset->esls_table[i];
			char normal_buf[128];
			char alt_buf[128];

			#define RT_DEST_SPRINTF(buf, rt) \
				do { \
					if (rt) { \
						if ((rt)->dest.as) { \
							snprintf(buf, sizeof(buf), "%s", (rt)->dest.as->cfg.name); \
						} else if ((rt)->dest.linkset) { \
							snprintf(buf, sizeof(buf), "%s", (rt)->dest.linkset->cfg.name); \
						} else { \
							snprintf(buf, sizeof(buf), "<error>"); \
						} \
					} else { \
						snprintf(buf, sizeof(buf), "-"); \
					} \
				} while (0)

			RT_DEST_SPRINTF(normal_buf, e->normal_rt);
			RT_DEST_SPRINTF(alt_buf, e->alt_rt);

			#undef RT_DEST_SPRINTF

			vty_out(vty, "%-15u %-22s %-10s %-22s %-10s%s",
				i,
				normal_buf,
				e->normal_rt ? (ss7_route_is_available(e->normal_rt) ? "Yes" : "No") : "-",
				alt_buf,
				e->alt_rt ? (ss7_route_is_available(e->alt_rt) ? "Yes" : "No") : "-",
				VTY_NEWLINE);
		}

		if (!all)
			break;
	}
	return CMD_SUCCESS;
}

DEFUN(show_cs7_route_lookup, show_cs7_route_lookup_cmd,
      "show cs7 instance <0-15> route-lookup POINT_CODE from POINT_CODE sls <0-15> [list-asps]",
      SHOW_STR CS7_STR INST_STR INST_STR
      "Look up route\n" "Destination PC\n"
      "From\n" "Origin PC\n"
      "SLS\n" "SLS value\n"
      "List ASPs of the AS if route points to an AS")
{
	int id = atoi(argv[0]);
	bool list_asps = argc > 4;
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_route *rt;
	struct osmo_ss7_route_label rtlabel = {};
	int pc;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	pc = osmo_ss7_pointcode_parse(inst, argv[1]);
	if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
		vty_out(vty, "Invalid point code (%s)%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}
	rtlabel.dpc = pc;

	pc = osmo_ss7_pointcode_parse(inst, argv[2]);
	if (pc < 0 || !osmo_ss7_pc_is_valid((uint32_t)pc)) {
		vty_out(vty, "Invalid point code (%s)%s", argv[2], VTY_NEWLINE);
		return CMD_WARNING;
	}
	rtlabel.opc = pc;

	rtlabel.sls = atoi(argv[3]);

	rt = ss7_instance_lookup_route(inst, &rtlabel);
	if (!rt) {
		char buf[256];
		vty_out(vty, "No route found for label '%s'%s",
			ss7_route_label_to_str(buf, sizeof(buf), inst, &rtlabel), VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty_out(vty, "%s%s", osmo_ss7_route_name(rt, list_asps), VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_cs7_config, show_cs7_config_cmd,
      "show cs7 config",
      SHOW_STR CS7_STR "Currently running cs7 configuration")
{
	write_all_cs7(vty, true);
	return CMD_SUCCESS;
}

DEFUN(cs7_asp_disconnect, cs7_asp_disconnect_cmd,
      "cs7 instance <0-15> asp NAME disconnect",
      CS7_STR "Instance related commands\n" "SS7 Instance Number\n"
      "ASP related commands\n" "Name of ASP\n"
      "Disconnect the ASP (client will reconnect)\n")
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_asp *asp;

	inst = osmo_ss7_instance_find(atoi(argv[0]));
	if (!inst) {
		vty_out(vty, "unknown instance '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	asp = osmo_ss7_asp_find_by_name(inst, argv[1]);
	if (!asp) {
		vty_out(vty, "unknown ASP '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_ss7_asp_disconnect(asp);
	return CMD_SUCCESS;
}


/***********************************************************************
 * SCCP addressbook handling
 ***********************************************************************/

static struct cmd_node sccpaddr_node = {
	L_CS7_SCCPADDR_NODE,
	"%s(config-cs7-sccpaddr)# ",
	1,
};

static struct cmd_node sccpaddr_gt_node = {
	L_CS7_SCCPADDR_GT_NODE,
	"%s(config-cs7-sccpaddr-gt)# ",
	1,
};

/* Generate VTY configuration file snippet */
static void write_sccp_addressbook(struct vty *vty,
				   const struct osmo_ss7_instance *inst)
{
	struct osmo_sccp_addr_entry *entry;

	if (llist_empty(&inst->cfg.sccp_address_book))
		return;

	/* FIXME: Add code to write IP-Addresses */

	llist_for_each_entry(entry, &inst->cfg.sccp_address_book, list) {
		vty_out(vty, " sccp-address %s%s", entry->name, VTY_NEWLINE);
		switch (entry->addr.ri) {
		case OSMO_SCCP_RI_GT:
			vty_out(vty, "  routing-indicator GT%s", VTY_NEWLINE);
			break;
		case OSMO_SCCP_RI_SSN_PC:
			vty_out(vty, "  routing-indicator PC%s", VTY_NEWLINE);
			break;
		case OSMO_SCCP_RI_SSN_IP:
			vty_out(vty, "  routing-indicator IP%s", VTY_NEWLINE);
			break;
		case OSMO_SCCP_RI_NONE:
			break;
		default:
			vty_out(vty, "  ! invalid routing-indicator value: %u%s", entry->addr.ri, VTY_NEWLINE);
			break;
		}
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_PC)
			vty_out(vty, "  point-code %s%s",
				osmo_ss7_pointcode_print(entry->inst,
							 entry->addr.pc),
				VTY_NEWLINE);
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_SSN)
			vty_out(vty, "  subsystem-number %u%s", entry->addr.ssn,
				VTY_NEWLINE);
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_GT) {
			vty_out(vty, "  global-title%s", VTY_NEWLINE);
			vty_out(vty, "   global-title-indicator %u%s",
				entry->addr.gt.gti, VTY_NEWLINE);
			vty_out(vty, "   translation-type %u%s",
				entry->addr.gt.tt, VTY_NEWLINE);
			vty_out(vty, "   numbering-plan-indicator %u%s",
				entry->addr.gt.npi, VTY_NEWLINE);
			vty_out(vty, "   nature-of-address-indicator %u%s",
				entry->addr.gt.nai, VTY_NEWLINE);
			if (strlen(entry->addr.gt.digits))
				vty_out(vty, "   digits %s%s",
					entry->addr.gt.digits, VTY_NEWLINE);
		}
	}
}

/* List all addressbook entries */
DEFUN(cs7_show_sccpaddr, cs7_show_sccpaddr_cmd,
      "show cs7 instance <0-15> sccp addressbook",
      SHOW_STR CS7_STR INST_STR INST_STR SCCP_STR
      "List all SCCP addressbook entries\n")
{
	struct osmo_ss7_instance *inst;
	struct osmo_sccp_addr_entry *entry;
	int id = atoi(argv[0]);
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	char ip_addr_str[INET6_ADDRSTRLEN];
#endif

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (inst->cfg.description)
		vty_out(vty, "  description %s%s", inst->cfg.description,
			VTY_NEWLINE);

	if (llist_empty(&inst->cfg.sccp_address_book)) {
		vty_out(vty, "SCCP addressbook empty!%s", VTY_NEWLINE);
		return CMD_SUCCESS;
	}

	vty_out(vty, "%s", VTY_NEWLINE);

	vty_out(vty, "Name         ");
	vty_out(vty, "RI: ");
	vty_out(vty, "PC:       ");
	vty_out(vty, "SSN:       ");
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	vty_out(vty, "IP-Address:                            ");
#endif
	vty_out(vty, "GT:");
	vty_out(vty, "%s", VTY_NEWLINE);

	vty_out(vty, "------------ ");
	vty_out(vty, "--- ");
	vty_out(vty, "--------- ");
	vty_out(vty, "---------- ");
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	vty_out(vty, "--------------------------------------- ");
#endif
	vty_out(vty, "--------------------------------------- ");
	vty_out(vty, "%s", VTY_NEWLINE);

	llist_for_each_entry(entry, &inst->cfg.sccp_address_book, list) {
		vty_out(vty, "%-12s ", entry->name);

		/* RI */
		switch (entry->addr.ri) {
		case OSMO_SCCP_RI_GT:
			vty_out(vty, "GT  ");
			break;
		case OSMO_SCCP_RI_SSN_PC:
			vty_out(vty, "PC  ");
			break;
		case OSMO_SCCP_RI_SSN_IP:
			vty_out(vty, "IP  ");
			break;
		default:
			vty_out(vty, "ERR ");
			break;
		}

		/* PC */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_PC)
			vty_out(vty, "%-9s ",
				osmo_ss7_pointcode_print(entry->inst,
							 entry->addr.pc));
		else
			vty_out(vty, "(none)    ");

		/* SSN */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_SSN)
			vty_out(vty, "%-10u ", entry->addr.ssn);
		else
			vty_out(vty, "(none)     ");
#if 0
		/* FIXME: IP-Address based SCCP-Routing is currently not
		 * supported, so we leave the related VTY options out for now */
		/* IP-Address */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_IPv4) {
			inet_ntop(AF_INET, &entry->addr.ip.v4, ip_addr_str,
				  INET6_ADDRSTRLEN);
			vty_out(vty, "%-39s ", ip_addr_str);
		} else if (entry->addr.presence & OSMO_SCCP_ADDR_T_IPv6) {
			inet_ntop(AF_INET6, &entry->addr.ip.v6, ip_addr_str,
				  INET6_ADDRSTRLEN);
			vty_out(vty, "%-39s ", ip_addr_str);
		} else
			vty_out(vty, "(none)              ");
#endif
		/* GT */
		if (entry->addr.presence & OSMO_SCCP_ADDR_T_GT) {
			vty_out(vty, "GTI:%u ", entry->addr.gt.gti);
			vty_out(vty, "TT:%u ", entry->addr.gt.tt);
			vty_out(vty, "NPI:%u ", entry->addr.gt.npi);
			vty_out(vty, "NAI:%u ", entry->addr.gt.nai);
			if (strlen(entry->addr.gt.digits))
				vty_out(vty, "%s ", entry->addr.gt.digits);
		} else
			vty_out(vty, "(none)");
		vty_out(vty, "%s", VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

/* Create a new addressbook entry and switch nodes */
DEFUN_ATTR(cs7_sccpaddr, cs7_sccpaddr_cmd,
	   "sccp-address NAME",
	   "Create/Modify an SCCP addressbook entry\n" "Name of the SCCP Address\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = (struct osmo_ss7_instance *)vty->index;
	struct osmo_sccp_addr_entry *entry;
	const char *name = argv[0];
	int rc;

	entry = addr_entry_by_name_local(name, inst);
	if (!entry) {
		/* Create a new addressbook entry if we can not find an
		 * already existing entry */
		struct osmo_sccp_addr sccp_addr = {
			.ri = OSMO_SCCP_RI_SSN_PC,
		};
		rc = osmo_sccp_addr_create(inst, name, &sccp_addr);
		if (rc < 0) {
			if (rc == -ENOSPC)
				vty_out(vty, "Error: SCCP address name too long: '%s'%s",
					name, VTY_NEWLINE);
			if (rc == -EALREADY)
				vty_out(vty, "Error: SCCP address name already used in cs7 instance other than %u: '%s'%s",
					inst->cfg.id, name, VTY_NEWLINE);
			return CMD_ERR_INCOMPLETE;
		}
	}

	entry = addr_entry_by_name_local(name, inst);
	if (!entry) {
		vty_out(vty, "%% Error: Unable to find SCCP address '%s' just created in instance %u%s",
			name, inst->cfg.id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = L_CS7_SCCPADDR_NODE;
	vty->index = entry;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_sccpaddr_del, cs7_sccpaddr_del_cmd,
	   "no sccp-address NAME",
	   NO_STR "Delete an SCCP addressbook entry\n" "Name of the SCCP Address\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = (struct osmo_ss7_instance *)vty->index;
	struct osmo_sccp_addr_entry *entry;
	const char *name = argv[0];

	entry = addr_entry_by_name_local(name, inst);
	if (entry) {
		llist_del(&entry->list);
		llist_del(&entry->list_global);
		talloc_free(entry);
	} else {
		vty_out(vty, "Addressbook entry not found!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

/* Set routing indicator of sccp address */
DEFUN_ATTR(cs7_sccpaddr_ri, cs7_sccpaddr_ri_cmd,
	   "routing-indicator (GT|PC|IP)",
	   "Add Routing Indicator\n"
	   "by global-title\n" "by point-code\n" "by ip-address\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	switch (argv[0][0]) {
	case 'G':
		entry->addr.ri = OSMO_SCCP_RI_GT;
		break;
	case 'P':
		entry->addr.ri = OSMO_SCCP_RI_SSN_PC;
		break;
	case 'I':
		entry->addr.ri = OSMO_SCCP_RI_SSN_IP;
		break;
	}
	return CMD_SUCCESS;
}

/* Set point-code number of sccp address */
DEFUN_ATTR(cs7_sccpaddr_pc, cs7_sccpaddr_pc_cmd,
	   "point-code POINT_CODE", "Add point-code Number\n" "PC\n",
	   CMD_ATTR_IMMEDIATE)
{
	int pc;
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);

	pc = osmo_ss7_pointcode_parse(entry->inst, argv[0]);
	if (pc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	entry->addr.presence |= OSMO_SCCP_ADDR_T_PC;
	entry->addr.pc = pc;
	if (entry->addr.ri == OSMO_SCCP_RI_NONE)
		entry->addr.ri = OSMO_SCCP_RI_SSN_PC;
	return CMD_SUCCESS;
}

/* Remove point-code number from sccp address */
DEFUN_ATTR(cs7_sccpaddr_pc_del, cs7_sccpaddr_pc_del_cmd,
	   "no point-code", NO_STR "Remove point-code Number\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_PC;
	entry->addr.pc = 0;
	return CMD_SUCCESS;
}

/* Set subsystem number of sccp address */
DEFUN_ATTR(cs7_sccpaddr_ssn, cs7_sccpaddr_ssn_cmd,
	   "subsystem-number <0-4294967295>", "Add Subsystem Number\n" "SSN\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence |= OSMO_SCCP_ADDR_T_SSN;
	entry->addr.ssn = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Remove subsystem number from sccp address */
DEFUN_ATTR(cs7_sccpaddr_ssn_del, cs7_sccpaddr_ssn_del_cmd,
	   "no subsystem-number", NO_STR "Remove Subsystem Number\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_SSN;
	entry->addr.ssn = 0;
	return CMD_SUCCESS;
}

#if 0
/* FIXME: IP-Address based SCCP-Routing is currently not supported,
 * so we leave the related VTY options out for now */

/* Set IP Address (V4) of sccp address */
DEFUN_ATTR(cs7_sccpaddr_ipv4, cs7_sccpaddr_ipv4_cmd,
	   "ip-address V4 A.B.C.D",
	   "Add IP-Address\n" "Protocol version 4\n" "IP-Address digits\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	unsigned int rc;
	uint8_t ip_addr_backup[sizeof(entry->addr.ip)];
	OSMO_ASSERT(entry);

	/* Create a backup of the existing IP-Address setting */
	memcpy(ip_addr_backup, &entry->addr.ip, sizeof(entry->addr.ip));

	entry->addr.presence |= OSMO_SCCP_ADDR_T_IPv4;
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;
	rc = inet_pton(AF_INET, argv[1], &entry->addr.ip.v4);
	if (rc <= 0) {
		vty_out(vty, "Invalid IP-Address format!%s", VTY_NEWLINE);
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;

		/* In case of failure, make sure the previous IP-Address
		 * configuration is restored */
		memcpy(&entry->addr.ip, ip_addr_backup, sizeof(entry->addr.ip));
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

/* Set IP Address (V6) of sccp address */
DEFUN_ATTR(cs7_sccpaddr_ipv6, cs7_sccpaddr_ipv6_cmd,
	   "ip-address V6 A:B:C:D:E:F:G:H",
	   "Add IP-Address\n" "Protocol version 6\n" "IP-Address digits\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	unsigned int rc;
	uint8_t ip_addr_backup[sizeof(entry->addr.ip)];
	OSMO_ASSERT(entry);

	/* Create a backup of the existing IP-Address setting */
	memcpy(ip_addr_backup, &entry->addr.ip, sizeof(entry->addr.ip));

	entry->addr.presence |= OSMO_SCCP_ADDR_T_IPv6;
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
	rc = inet_pton(AF_INET6, argv[1], &entry->addr.ip.v4);
	if (rc <= 0) {
		vty_out(vty, "Invalid IP-Address format!%s", VTY_NEWLINE);
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
		entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;

		/* In case of failure, make sure the previous IP-Address
		 * configuration is restored */
		memcpy(&entry->addr.ip, ip_addr_backup, sizeof(entry->addr.ip));
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

/* Remove IP Address from sccp address */
DEFUN_ATTR(cs7_sccpaddr_ip_del, cs7_sccpaddr_ip_del_cmd,
	   "no ip-address", NO_STR "Remove IP-Address\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv4;
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_IPv6;
	memset(&entry->addr.ip, 0, sizeof(entry->addr.ip));
	return CMD_SUCCESS;
}
#endif

/* Configure global title and switch nodes */
DEFUN_ATTR(cs7_sccpaddr_gt, cs7_sccpaddr_gt_cmd,
	   "global-title", "Add/Modify Global Title\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	entry->addr.presence |= OSMO_SCCP_ADDR_T_GT;
	vty->node = L_CS7_SCCPADDR_GT_NODE;
	return CMD_SUCCESS;
}

/* Remove global title from sccp address */
DEFUN_ATTR(cs7_sccpaddr_gt_del, cs7_sccpaddr_gt_del_cmd,
	   "no global-title", NO_STR "Remove Global Title\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.presence &= ~OSMO_SCCP_ADDR_T_GT;
	entry->addr.gt = (struct osmo_sccp_gt) {};
	return CMD_SUCCESS;
}

/* Set global title inicator of the sccp address gt */
DEFUN_ATTR(cs7_sccpaddr_gt_gti, cs7_sccpaddr_gt_gti_cmd,
	   "global-title-indicator <0-15>", "Set Global Title Indicator\n" "GTI\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.gti = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title translation type of the sccp address gt */
DEFUN_ATTR(cs7_sccpaddr_gt_tt, cs7_sccpaddr_gt_tt_cmd,
	   "translation-type <0-255>", "Set Global Title Translation Type\n" "TT\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.tt = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title numbering plan indicator of the sccp address gt */
DEFUN_ATTR(cs7_sccpaddr_gt_npi, cs7_sccpaddr_gt_npi_cmd,
	   "numbering-plan-indicator <0-15>",
	   "Set Global Title Numbering Plan Indicator\n" "NPI\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.npi = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title nature of address indicator of the sccp address gt */
DEFUN_ATTR(cs7_sccpaddr_gt_nai, cs7_sccpaddr_gt_nai_cmd,
	   "nature-of-address-indicator <0-127>",
	   "Set Global Title Nature of Address Indicator\n" "NAI\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);
	entry->addr.gt.nai = atoi(argv[0]);
	return CMD_SUCCESS;
}

/* Set global title digits of the sccp address gt */
DEFUN_ATTR(cs7_sccpaddr_gt_digits, cs7_sccpaddr_gt_digits_cmd,
	   "digits DIGITS", "Set Global Title Digits\n" "Number digits\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_sccp_addr_entry *entry =
	    (struct osmo_sccp_addr_entry *)vty->index;
	OSMO_ASSERT(entry);

	if (strlen(argv[0]) > sizeof(entry->addr.gt.digits)) {
		vty_out(vty, "Number too long!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	memset(entry->addr.gt.digits, 0, sizeof(entry->addr.gt.digits));

	osmo_strlcpy(entry->addr.gt.digits, argv[0],
		     sizeof(entry->addr.gt.digits));
	return CMD_SUCCESS;
}

/***********************************************************************
 * Common
 ***********************************************************************/

static void write_cs7_timers_xua(struct vty *vty, const char *indent,
				 struct osmo_ss7_instance *inst)
{
	for (unsigned int i = 0; ss7_instance_xua_timer_names[i].str; i++) {
		const struct osmo_tdef *tdef = osmo_tdef_get_entry(inst->cfg.T_defs_xua, ss7_instance_xua_timer_names[i].value);
		if (!tdef)
			continue;
		if (tdef->val == tdef->default_val)
			continue;
		vty_out(vty, "%stimer xua %s %lu%s", indent, ss7_instance_xua_timer_names[i].str,
			tdef->val, VTY_NEWLINE);
	}
}

static void write_one_cs7(struct vty *vty, struct osmo_ss7_instance *inst, bool show_dyn_config)
{
	struct osmo_ss7_asp *asp;
	struct osmo_ss7_as *as;
	struct osmo_ss7_route_table *rtable;
	struct osmo_xua_server *oxs;

	vty_out(vty, "cs7 instance %u%s", inst->cfg.id, VTY_NEWLINE);
	if (inst->cfg.description)
		vty_out(vty, " description %s%s", inst->cfg.description, VTY_NEWLINE);
	vty_out(vty, " network-indicator %s%s",
		get_value_string(mtp_network_indicator_vals, inst->cfg.network_indicator),
		VTY_NEWLINE);

	if (inst->cfg.pc_fmt.component_len[0] != 3 ||
	    inst->cfg.pc_fmt.component_len[1] != 8 ||
	    inst->cfg.pc_fmt.component_len[2] != 3) {
		vty_out(vty, " point-code format %u",
			inst->cfg.pc_fmt.component_len[0]);
		if (inst->cfg.pc_fmt.component_len[1])
			vty_out(vty, " %u", inst->cfg.pc_fmt.component_len[1]);
		if (inst->cfg.pc_fmt.component_len[2])
			vty_out(vty, " %u", inst->cfg.pc_fmt.component_len[2]);
		vty_out(vty, "%s", VTY_NEWLINE);
	}

	if (inst->cfg.pc_fmt.delimiter != '.')
		vty_out(vty, " point-code delimiter dash%s", VTY_NEWLINE);

	if (osmo_ss7_pc_is_valid(inst->cfg.primary_pc))
		vty_out(vty, " point-code %s%s",
			osmo_ss7_pointcode_print(inst, inst->cfg.primary_pc),
			VTY_NEWLINE);

	if (osmo_ss7_pc_is_valid(inst->cfg.secondary_pc)) {
		vty_out(vty, " secondary-pc %s%s",
			osmo_ss7_pointcode_print(inst, inst->cfg.secondary_pc), VTY_NEWLINE);
	}

	if (inst->cfg.permit_dyn_rkm_alloc)
		vty_out(vty, " xua rkm routing-key-allocation dynamic-permitted%s", VTY_NEWLINE);

	if (inst->cfg.opc_shift != 0 || inst->cfg.dpc_shift != 0)
		vty_out(vty, " sls-opc-dpc opc-shift %u dpc-shift %u%s",
			inst->cfg.opc_shift, inst->cfg.dpc_shift, VTY_NEWLINE);

	if (inst->cfg.sls_shift != 0)
		vty_out(vty, " sls-shift %u%s", inst->cfg.sls_shift, VTY_NEWLINE);

	write_cs7_timers_xua(vty, " ", inst);

	/* first dump ASPs, as ASs reference them */
	llist_for_each_entry(asp, &inst->asp_list, list)
		ss7_vty_write_one_asp(vty, asp, show_dyn_config);

	/* then dump ASPs, as routes reference them */
	llist_for_each_entry(as, &inst->as_list, list)
		ss7_vty_write_one_as(vty, as, show_dyn_config);

	/* now dump everything that is relevant for the SG role */
	if (cs7_role == CS7_ROLE_SG) {

		/* dump routes, as their target ASs exist */
		llist_for_each_entry(rtable, &inst->rtable_list, list)
			write_one_rtable(vty, rtable);

		llist_for_each_entry(oxs, &inst->xua_servers, list)
			ss7_vty_write_one_oxs(vty, oxs);
	}

	/* Append SCCP Addressbook */
	write_sccp_addressbook(vty, inst);

	if (inst->sccp)
		osmo_sccp_vty_write_cs7_node(vty, " ", inst->sccp);
}

int osmo_ss7_vty_go_parent(struct vty *vty)
{
	struct osmo_ss7_route_table *rtbl;
	struct osmo_sccp_addr_entry *entry;

	switch (vty->node) {
	case L_CS7_ASP_NODE:
		return ss7_vty_node_asp_go_parent(vty);
	case L_CS7_RTABLE_NODE:
		rtbl = vty->index;
		vty->node = L_CS7_NODE;
		vty->index = rtbl->inst;
		break;
	case L_CS7_AS_NODE:
		return ss7_vty_node_as_go_parent(vty);
	case L_CS7_XUA_NODE:
		return ss7_vty_node_oxs_go_parent(vty);
	case L_CS7_SCCPADDR_NODE:
		entry = vty->index;
		vty->node = L_CS7_NODE;
		vty->index = entry->inst;
		break;
	case L_CS7_SCCPADDR_GT_NODE:
		vty->node = L_CS7_SCCPADDR_NODE;
		vty->index = NULL;
		break;
	case L_CS7_NODE:
	default:
		vty->node = CONFIG_NODE;
		vty->index = NULL;
		break;
	}
	return 0;
}

/* This is no longer used. The libosmocore callback was deprecated is not ever called since.
 * libosmocore.git 70ce871532ab21955e0955d7e230eae65438f047 (release 1.3.0). */
int osmo_ss7_is_config_node(struct vty *vty, int node)
{
	switch (node) {
	case L_CS7_NODE:
	case L_CS7_ASP_NODE:
	case L_CS7_RTABLE_NODE:
	case L_CS7_XUA_NODE:
	case L_CS7_AS_NODE:
	case L_CS7_SCCPADDR_NODE:
	case L_CS7_SCCPADDR_GT_NODE:
		return 1;
	default:
		return 0;
	}
}

/* Commands for SCCP-Addressbook */
static void vty_init_addr(void)
{
	install_node(&sccpaddr_node, NULL);
	install_lib_element_ve(&cs7_show_sccpaddr_cmd);
	install_lib_element(L_CS7_NODE, &cs7_sccpaddr_cmd);
	install_lib_element(L_CS7_NODE, &cs7_sccpaddr_del_cmd);
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_pc_del_cmd);
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ssn_del_cmd);
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ip_del_cmd);
#endif
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_gt_del_cmd);
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ri_cmd);
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_pc_cmd);
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ssn_cmd);
#if 0
	/* FIXME: IP-Address based SCCP-Routing is currently not supported,
	 * so we leave the related VTY options out for now */
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ipv4_cmd);
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_ipv6_cmd);
#endif
	install_lib_element(L_CS7_SCCPADDR_NODE, &cs7_sccpaddr_gt_cmd);
	install_node(&sccpaddr_gt_node, NULL);
	install_lib_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_gti_cmd);
	install_lib_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_tt_cmd);
	install_lib_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_npi_cmd);
	install_lib_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_nai_cmd);
	install_lib_element(L_CS7_SCCPADDR_GT_NODE, &cs7_sccpaddr_gt_digits_cmd);
}

static void vty_init_shared(void *ctx)
{
	g_ctx = ctx;

	install_lib_element_ve(&show_cs7_user_cmd);
	ss7_vty_init_show_oxs();
	install_lib_element_ve(&show_cs7_config_cmd);
	install_lib_element(ENABLE_NODE, &cs7_asp_disconnect_cmd);

	/* the mother of all VTY config nodes */
	install_lib_element(CONFIG_NODE, &cs7_instance_cmd);

	install_node(&cs7_node, config_write_cs7);
	install_lib_element(L_CS7_NODE, &cfg_description_cmd);
	install_lib_element(L_CS7_NODE, &cs7_net_ind_cmd);
	install_lib_element(L_CS7_NODE, &cs7_point_code_cmd);
	install_lib_element(L_CS7_NODE, &cs7_secondary_pc_cmd);
	install_lib_element(L_CS7_NODE, &cs7_pc_format_cmd);
	install_lib_element(L_CS7_NODE, &cs7_pc_format_def_cmd);
	install_lib_element(L_CS7_NODE, &cs7_pc_delimiter_cmd);
	install_lib_element(L_CS7_NODE, &cs7_permit_dyn_rkm_cmd);
	install_lib_element(L_CS7_NODE, &cs7_opc_dpc_shift_cmd);
	install_lib_element(L_CS7_NODE, &cs7_sls_shift_cmd);

	ss7_vty_init_node_asp();
	ss7_vty_init_node_as();

	install_lib_element_ve(&show_cs7_route_cmd);
	install_lib_element_ve(&show_cs7_route_bindingtable_cmd);
	install_lib_element_ve(&show_cs7_route_lookup_cmd);

	vty_init_addr();

	gen_cs7_timer_xua_cmd_strs(&cs7_timer_xua_cmd);
	install_lib_element(L_CS7_NODE, &cs7_timer_xua_cmd);
}

void osmo_ss7_vty_init_asp(void *ctx)
{
	cs7_role = CS7_ROLE_ASP;
	vty_init_shared(ctx);
}

void osmo_ss7_vty_init_sg(void *ctx)
{
	cs7_role = CS7_ROLE_SG;
	vty_init_shared(ctx);

#ifdef WITH_TCAP_LOADSHARING
	tcap_as_vty_init();
#endif /* WITH_TCAP_LOADSHARING */
	install_node(&rtable_node, NULL);
	install_lib_element(L_CS7_NODE, &cs7_route_table_cmd);
	install_lib_element(L_CS7_RTABLE_NODE, &cfg_description_cmd);
	install_lib_element(L_CS7_RTABLE_NODE, &cs7_rt_upd_cmd);
	install_lib_element(L_CS7_RTABLE_NODE, &cs7_rt_rem_cmd);

	ss7_vty_init_node_oxs();
}
