/* SS7 AS VTY Interface */

/* (C) 2015-2021 by Harald Welte <laforge@gnumonks.org>
 * (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/sigtran/protocol/mtp.h>

#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_route.h"
#include "ss7_route_table.h"
#include "ss7_internal.h"
#include "ss7_vty.h"

/***********************************************************************
 * Application Server
 ***********************************************************************/

static struct cmd_node as_node = {
	L_CS7_AS_NODE,
	"%s(config-cs7-as)# ",
	1,
};

DEFUN_ATTR(cs7_as, cs7_as_cmd,
	   "as NAME " XUA_VAR_STR,
	   "Configure an Application Server\n"
	   "Name of the Application Server\n"
	   XUA_VAR_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_ss7_as *as;
	const char *name = argv[0];
	enum osmo_ss7_asp_protocol protocol = parse_asp_proto(argv[1]);

	if (protocol == OSMO_SS7_ASP_PROT_NONE) {
		vty_out(vty, "invalid protocol '%s'%s", argv[1], VTY_NEWLINE);
		return CMD_WARNING;
	}

	as = osmo_ss7_as_find_or_create(inst, name, protocol);
	if (!as) {
		vty_out(vty, "cannot create AS '%s'%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}

	as->cfg.name = talloc_strdup(as, name);

	vty->node = L_CS7_AS_NODE;
	vty->index = as;
	vty->index_sub = &as->cfg.description;

	return CMD_SUCCESS;
}

DEFUN_ATTR(no_cs7_as, no_cs7_as_cmd,
	   "no as NAME",
	   NO_STR "Disable Application Server\n"
	   "Name of AS\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	const char *name = argv[0];
	struct osmo_ss7_as *as;

	as = osmo_ss7_as_find_by_name(inst, name);
	if (!as) {
		vty_out(vty, "No AS named '%s' found%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_ss7_as_destroy(as);
	return CMD_SUCCESS;
}

/* TODO: routing-key */
DEFUN_ATTR(as_asp, as_asp_cmd,
	   "asp NAME",
	   "Specify that a given ASP is part of this AS\n"
	   "Name of ASP to be added to AS\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;

	if (osmo_ss7_as_add_asp(as, argv[0])) {
		vty_out(vty, "cannot find ASP '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(as_no_asp, as_no_asp_cmd,
	   "no asp NAME",
	   NO_STR "Specify ASP to be removed from this AS\n"
	   "Name of ASP to be removed\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;

	if (osmo_ss7_as_del_asp(as, argv[0])) {
		vty_out(vty, "cannot find ASP '%s'%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN_USRATTR(as_traf_mode, as_traf_mode_cmd,
	      OSMO_SCCP_LIB_ATTR_RSTRT_ASP,
	      "traffic-mode (broadcast | roundrobin | override)",
	      "Specifies traffic mode of operation of the ASP within the AS\n"
	      "Broadcast to all ASP within AS\n"
	      "Round-Robin between all ASP within AS\n"
	      "Override\n")
{
	struct osmo_ss7_as *as = vty->index;

	as->cfg.mode = get_string_value(osmo_ss7_as_traffic_mode_vals, argv[0]);
	as->cfg.mode_set_by_vty = true;
	return CMD_SUCCESS;
}

DEFUN_USRATTR(as_traf_mode_loadshare, as_traf_mode_loadshare_cmd,
	      OSMO_SCCP_LIB_ATTR_RSTRT_ASP,
	      "traffic-mode loadshare [bindings] [sls] [opc-sls] [opc-shift] [<0-2>]",
	      "Specifies traffic mode of operation of the ASP within the AS\n"
	      "Share Load among all ASP within AS\n"
	      "Configure Loadshare parameters\n"
	      "Configure Loadshare SLS generation parameters\n"
	      "Generate extended SLS with OPC information\n"
	      "Shift OPC bits used during routing decision\n"
	      "How many bits from ITU OPC field (starting from least-significant-bit) to skip (default=0). 6 bits are always used\n"
	      )
{
	struct osmo_ss7_as *as = vty->index;

	as->cfg.mode = OSMO_SS7_AS_TMOD_LOADSHARE;
	as->cfg.mode_set_by_vty = true;
	if (argc < 3) {
		as->cfg.loadshare.opc_sls = false;
		as->cfg.loadshare.opc_shift = 0;
		return CMD_SUCCESS;
	}
	as->cfg.loadshare.opc_sls = true;
	if (argc < 5) {
		as->cfg.loadshare.opc_shift = 0;
		return CMD_SUCCESS;
	}
	as->cfg.loadshare.opc_shift = atoi(argv[4]);
	return CMD_SUCCESS;
}

DEFUN_USRATTR(as_no_traf_mode, as_no_traf_mode_cmd,
	      OSMO_SCCP_LIB_ATTR_RSTRT_ASP,
	      "no traffic-mode",
	      NO_STR "Remove explicit traffic mode of operation of this AS\n")
{
	struct osmo_ss7_as *as = vty->index;

	as->cfg.mode = 0;
	as->cfg.mode_set_by_vty = false;

	as->cfg.loadshare.sls_shift = 0;
	as->cfg.loadshare.opc_sls = false;
	as->cfg.loadshare.opc_shift = 0;
	return CMD_SUCCESS;
}

DEFUN_ATTR(as_sls_shift, as_sls_shift_cmd,
	   "sls-shift <0-3>",
	   "Shift SLS bits used during routing decision\n"
	   "How many bits from SLS field (starting from least-significant-bit) to skip\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;
	as->cfg.loadshare.sls_shift = atoi(argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(as_bindingtable_reset, as_bindingtable_reset_cmd,
	"binding-table reset",
	"AS Loadshare binding table operations\n"
	"Reset loadshare binding table\n",
	CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;
	ss7_as_loadshare_binding_table_reset(as);
	return CMD_SUCCESS;
}

DEFUN_ATTR(as_recov_tout, as_recov_tout_cmd,
	   "recovery-timeout <1-2000>",
	   "Specifies the recovery timeout value in milliseconds\n"
	   "Recovery Timeout in Milliseconds\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;
	as->cfg.recovery_timeout_msec = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(as_qos_clas, as_qos_class_cmd,
	   "qos-class " QOS_CLASS_RANGE_STR,
	   "Specity QoS Class of AS\n"
	   QOS_CLASS_RANGE_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;
	as->cfg.qos_class = atoi(argv[0]);
	return CMD_SUCCESS;
}

const struct value_string mtp_si_vals[] = {
	{ MTP_SI_SCCP,		"sccp" },
	{ MTP_SI_TUP,		"tup" },
	{ MTP_SI_ISUP,		"isup" },
	{ MTP_SI_DUP,		"dup" },
	{ MTP_SI_TESTING,	"testing" },
	{ MTP_SI_B_ISUP,	"b-isup" },
	{ MTP_SI_SAT_ISUP,	"sat-isup" },
	{ MTP_SI_AAL2_SIG,	"aal2" },
	{ MTP_SI_BICC,		"bicc" },
	{ MTP_SI_GCP,		"h248" },
	{ 0, NULL }
};

#define ROUTING_KEY_CMD "routing-key RCONTEXT DPC"
#define ROUTING_KEY_CMD_STRS \
	"Define a routing key\n" \
	"Routing context number\n" \
	"Destination Point Code\n"
#define ROUTING_KEY_SI_ARG " si (aal2|bicc|b-isup|h248|isup|sat-isup|sccp|tup)"
#define ROUTING_KEY_SI_ARG_STRS \
	"Match on Service Indicator\n" \
	"ATM Adaption Layer 2\n" \
	"Bearer Independent Call Control\n" \
	"Broadband ISDN User Part\n" \
	"H.248\n" \
	"ISDN User Part\n" \
	"Sattelite ISDN User Part\n" \
	"Signalling Connection Control Part\n" \
	"Telephony User Part\n"
#define ROUTING_KEY_SSN_ARG " ssn SSN"
#define ROUTING_KEY_SSN_ARG_STRS \
	"Match on Sub-System Number\n" \
	"Sub-System Number to match on\n"

static int _rout_key(struct vty *vty,
		     const char *rcontext, const char *dpc,
		     const char *si, const char *ssn)
{
	struct osmo_ss7_as *as = vty->index;
	struct osmo_ss7_routing_key *rkey = &as->cfg.routing_key;
	struct osmo_ss7_route *rt;
	int pc;

	if (as->cfg.proto == OSMO_SS7_ASP_PROT_IPA && atoi(rcontext) != 0) {
		vty_out(vty, "IPA doesn't support routing contexts; only permitted routing context "
			"is 0\n");
		return CMD_WARNING;
	}

	pc = osmo_ss7_pointcode_parse(as->inst, dpc);
	if (pc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", dpc, VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* When libosmo-sigtran is used in ASP role, the VTY routing table node
	 * (config-cs7-rt) is not available. However, when we add a routing key
	 * to an AS we still have to put a matching route into the routing
	 * table. This is done automatically by first removing the old route
	 * (users may change the routing key via VTY during runtime) and then
	 * putting a new route (see below). */
	if (cs7_role == CS7_ROLE_ASP) {
		rt = ss7_route_table_find_route_by_dpc_mask(as->inst->rtable_system, rkey->pc, 0xffffff);
		if (rt)
			ss7_route_destroy(rt);
	}

	rkey->pc = pc;

	rkey->context = atoi(rcontext);				/* FIXME: input validation */
	rkey->si = si ? get_string_value(mtp_si_vals, si) : 0;	/* FIXME: input validation */
	rkey->ssn = ssn ? atoi(ssn) : 0;			/* FIXME: input validation */

	/* automatically add new route (see also comment above) */
	if (cs7_role == CS7_ROLE_ASP) {
		if (!ss7_route_create(as->inst->rtable_system, rkey->pc, 0xffffff, as->cfg.name)) {
			vty_out(vty, "Cannot create route (pc=%s, linkset=%s) to AS %s", dpc, as->cfg.name, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	return CMD_SUCCESS;
}

DEFUN_ATTR(as_rout_key, as_rout_key_cmd,
	   ROUTING_KEY_CMD,
	   ROUTING_KEY_CMD_STRS,
	   CMD_ATTR_IMMEDIATE)
{
	return _rout_key(vty, argv[0], argv[1], NULL, NULL);
}

DEFUN_ATTR(as_rout_key_si, as_rout_key_si_cmd,
	   ROUTING_KEY_CMD      ROUTING_KEY_SI_ARG,
	   ROUTING_KEY_CMD_STRS ROUTING_KEY_SI_ARG_STRS,
	   CMD_ATTR_IMMEDIATE)
{
	return _rout_key(vty, argv[0], argv[1], argv[2], NULL);
}

DEFUN_ATTR(as_rout_key_ssn, as_rout_key_ssn_cmd,
	   ROUTING_KEY_CMD      ROUTING_KEY_SSN_ARG,
	   ROUTING_KEY_CMD_STRS ROUTING_KEY_SSN_ARG_STRS,
	   CMD_ATTR_IMMEDIATE)
{
	return _rout_key(vty, argv[0], argv[1], NULL, argv[2]);
}

DEFUN_ATTR(as_rout_key_si_ssn, as_rout_key_si_ssn_cmd,
	   ROUTING_KEY_CMD      ROUTING_KEY_SI_ARG      ROUTING_KEY_SSN_ARG,
	   ROUTING_KEY_CMD_STRS ROUTING_KEY_SI_ARG_STRS ROUTING_KEY_SSN_ARG_STRS,
	   CMD_ATTR_IMMEDIATE)
{
	return _rout_key(vty, argv[0], argv[1], argv[2], argv[3]);
}

DEFUN_ATTR(as_pc_override, as_pc_override_cmd,
	   "point-code override dpc PC",
	   "Point Code Specific Features\n"
	   "Override (force) a point-code to hard-coded value\n"
	   "Override Source Point Code\n"
	   "Override Destination Point Code\n"
	   "New Point Code\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;
	int pc = osmo_ss7_pointcode_parse(as->inst, argv[0]);
	if (pc < 0) {
		vty_out(vty, "Invalid point code (%s)%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (as->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		vty_out(vty, "Only IPA type AS support point-code override. "
			"Be happy that you don't need it!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	as->cfg.pc_override.dpc = pc;

	return CMD_SUCCESS;
}

DEFUN_ATTR(as_pc_patch_sccp, as_pc_patch_sccp_cmd,
	   "point-code override patch-sccp (disabled|both)",
	   "Point Code Specific Features\n"
	   "Override (force) a point-code to hard-coded value\n"
	   "Patch point code values into SCCP called/calling address\n"
	   "Don't patch any point codes into SCCP called/calling address\n"
	   "Patch both origin and destination point codes into SCCP called/calling address\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_as *as = vty->index;

	if (as->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
		vty_out(vty, "Only IPA type AS support point-code patch-into-sccp. "
			"Be happy that you don't need it!%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "disabled"))
		as->cfg.pc_override.sccp_mode = OSMO_SS7_PATCH_NONE;
	else
		as->cfg.pc_override.sccp_mode = OSMO_SS7_PATCH_BOTH;

	return CMD_SUCCESS;
}

void ss7_vty_write_one_as(struct vty *vty, struct osmo_ss7_as *as, bool show_dyn_config)
{
	struct osmo_ss7_routing_key *rkey;
	unsigned int i;

	/* skip any dynamically allocated AS definitions */
	if ((as->rkm_dyn_allocated || as->simple_client_allocated)
	    && !show_dyn_config)
		return;

	vty_out(vty, " as %s %s%s", as->cfg.name,
		osmo_ss7_asp_protocol_name(as->cfg.proto), VTY_NEWLINE);
	if (as->cfg.description)
		vty_out(vty, "  description %s%s", as->cfg.description, VTY_NEWLINE);
	for (i = 0; i < ARRAY_SIZE(as->cfg.asps); i++) {
		struct osmo_ss7_asp *asp = as->cfg.asps[i];
		if (!asp)
			continue;
		/* skip any dynamically created ASPs (e.g. auto-created at connect time) */
		if ((asp->dyn_allocated || asp->simple_client_allocated)
		    && !show_dyn_config)
			continue;
		vty_out(vty, "  asp %s%s", asp->cfg.name, VTY_NEWLINE);
	}
	if (as->cfg.mode_set_by_vty) {
		vty_out(vty, "  traffic-mode %s%s", osmo_ss7_as_traffic_mode_name(as->cfg.mode), VTY_NEWLINE);
		if (as->cfg.mode == OSMO_SS7_AS_TMOD_LOADSHARE) {
			if (as->cfg.loadshare.opc_sls) {
				vty_out(vty, " bindings sls opc-sls");
				if (as->cfg.loadshare.opc_shift != 0)
					vty_out(vty, " opc-shift %u", as->cfg.loadshare.opc_shift);
			}
			vty_out(vty, "%s", VTY_NEWLINE);
		}

		if (as->cfg.loadshare.sls_shift != 0)
			vty_out(vty, "  sls-shift %u%s", as->cfg.loadshare.sls_shift, VTY_NEWLINE);
	}

	if (as->cfg.recovery_timeout_msec != 2000) {
		vty_out(vty, "  recovery-timeout %u%s",
			as->cfg.recovery_timeout_msec, VTY_NEWLINE);
	}
	if (as->cfg.qos_class)
		vty_out(vty, "  qos-class %u%s", as->cfg.qos_class, VTY_NEWLINE);
	rkey = &as->cfg.routing_key;
	vty_out(vty, "  routing-key %u %s", rkey->context,
		osmo_ss7_pointcode_print(as->inst, rkey->pc));
	if (rkey->si)
		vty_out(vty, " si %s",
			get_value_string(mtp_si_vals, rkey->si));
	if (rkey->ssn)
		vty_out(vty, " ssn %u", rkey->ssn);
	vty_out(vty, "%s", VTY_NEWLINE);

	if (as->cfg.pc_override.dpc)
		vty_out(vty, "  point-code override dpc %s%s",
			osmo_ss7_pointcode_print(as->inst, as->cfg.pc_override.dpc), VTY_NEWLINE);

	if (as->cfg.pc_override.sccp_mode)
		vty_out(vty, "  point-code override patch-sccp both%s", VTY_NEWLINE);
}

static void show_one_as(struct vty *vty, struct osmo_ss7_as *as)
{
	vty_out(vty, "%-12s %-12s %-10u %-13s %4s %13s %3s %5s %4s %10s%s",
		as->cfg.name, osmo_fsm_inst_state_name(as->fi), as->cfg.routing_key.context,
		osmo_ss7_pointcode_print(as->inst, as->cfg.routing_key.pc),
		"", "", "", "", "", osmo_ss7_as_traffic_mode_name(as->cfg.mode),
		VTY_NEWLINE);
}

static int show_as(struct vty *vty, int id, const char *as_name, const char *filter)
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_as *as = NULL;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "%% No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (as_name) {
		as = osmo_ss7_as_find_by_name(inst, as_name);
		if (!as) {
			vty_out(vty, "%% No AS '%s' found%s", as_name, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	vty_out(vty, "                          Routing    Routing Key                          Cic   Cic   Traffic%s", VTY_NEWLINE);
	vty_out(vty, "AS Name      State        Context    Dpc           Si   Opc           Ssn Min   Max   Mode%s", VTY_NEWLINE);
	vty_out(vty, "------------ ------------ ---------- ------------- ---- ------------- --- ----- ----- -------%s", VTY_NEWLINE);

	if (as) {
		show_one_as(vty, as);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(as, &inst->as_list, list) {
		if (filter && !strcmp(filter, "m3ua") && as->cfg.proto != OSMO_SS7_ASP_PROT_M3UA)
			continue;
		if (filter && !strcmp(filter, "sua") && as->cfg.proto != OSMO_SS7_ASP_PROT_SUA)
			continue;
		if (filter && !strcmp(filter, "active") && !osmo_ss7_as_active(as))
			continue;
		show_one_as(vty, as);
	}
	return CMD_SUCCESS;
}

DEFUN(show_cs7_as, show_cs7_as_cmd,
	"show cs7 instance <0-15> as (active|all|m3ua|sua)",
	SHOW_STR CS7_STR INST_STR INST_STR "Application Server (AS)\n"
	"Display all active ASs\n"
	"Display all ASs (default)\n"
	"Display all m3ua ASs\n"
	"Display all SUA ASs\n")
{
	const char *filter = argv[1];
	int id = atoi(argv[0]);

	return show_as(vty, id, NULL, filter);
}

DEFUN(show_cs7_as_name, show_cs7_as_name_cmd,
	"show cs7 instance <0-15> as name AS_NAME",
	SHOW_STR CS7_STR INST_STR INST_STR "Application Server (AS)\n"
	"Look up AS with a given name\n"
	"Name of the Application Server (AS)\n")
{
	int id = atoi(argv[0]);
	const char *as_name = argv[1];

	return show_as(vty, id, as_name, NULL);
}

DEFUN(show_cs7_as_bindingtable_name, show_cs7_as_bindingtable_name_cmd,
	"show cs7 instance <0-15> as binding-table name AS_NAME",
	SHOW_STR CS7_STR INST_STR INST_STR "Application Server (AS)\n"
	"Display binding table\n"
	"Look up AS with a given name\n"
	"Name of the Application Server (AS)\n")
{
	int id = atoi(argv[0]);
	const char *as_name = argv[1];
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_as *as = NULL;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (as_name) {
		as = osmo_ss7_as_find_by_name(inst, as_name);
		if (!as) {
			vty_out(vty, "No AS %s found%s", as_name, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	vty_out(vty, "Loadshare Seed  Normal ASP       Active  Alternative ASP  Active%s", VTY_NEWLINE);
	vty_out(vty, "--------------  ---------------  ------  ---------------  ------%s", VTY_NEWLINE);

	for (unsigned int i = 0; i < ARRAY_SIZE(as->aesls_table); i++) {
		struct osmo_ss7_as_esls_entry *e = &as->aesls_table[i];
		vty_out(vty, "%-15u %-16s %-7s %-16s %-7s%s",
			i,
			e->normal_asp ? e->normal_asp->cfg.name : "-",
			e->normal_asp ? (osmo_ss7_asp_active(e->normal_asp) ? "Yes" : "No") : "-",
			e->alt_asp ? e->alt_asp->cfg.name : "-",
			e->alt_asp ? (osmo_ss7_asp_active(e->alt_asp) ? "Yes" : "No") : "-",
			VTY_NEWLINE);
	}

	return CMD_SUCCESS;
}

int ss7_vty_node_as_go_parent(struct vty *vty)
{
	struct osmo_ss7_as *as = vty->index;
	vty->node = L_CS7_NODE;
	vty->index = as->inst;
	return 0;
}

void ss7_vty_init_node_as(void)
{
	install_node(&as_node, NULL);
	install_lib_element_ve(&show_cs7_as_cmd);
	install_lib_element_ve(&show_cs7_as_name_cmd);
	install_lib_element_ve(&show_cs7_as_bindingtable_name_cmd);
	install_lib_element(L_CS7_NODE, &cs7_as_cmd);
	install_lib_element(L_CS7_NODE, &no_cs7_as_cmd);
	install_lib_element(L_CS7_AS_NODE, &cfg_description_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_asp_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_no_asp_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_traf_mode_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_traf_mode_loadshare_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_no_traf_mode_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_sls_shift_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_bindingtable_reset_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_recov_tout_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_qos_class_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_rout_key_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_rout_key_si_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_rout_key_ssn_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_rout_key_si_ssn_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_pc_override_cmd);
	install_lib_element(L_CS7_AS_NODE, &as_pc_patch_sccp_cmd);
}
