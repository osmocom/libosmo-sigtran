/* SS7 TCAP Loadsharing VTY Interface */

/* (C) 2025 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
 * Author: Alexander Couzens <lynxis@fe80.eu>
 * Author: Daniel Willmann <dwillmann@sysmocom.de>
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

#include <osmocom/core/hashtable.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_vty.h"
#include "tcap_as_loadshare.h"

static int show_one_tcap_range(struct vty *vty, const struct osmo_ss7_as *as, const struct tcap_range *tcrng)
{
	vty_out(vty, "%-7u %-7u %3u %-13s %-12s%s", tcrng->tid_start, tcrng->tid_end, tcrng->ssn, osmo_ss7_pointcode_print(as->inst, tcrng->pc), tcrng->asp->cfg.name, VTY_NEWLINE);
	return CMD_SUCCESS;
}

DEFUN(show_cs7_as_tcapranges_name, show_cs7_as_name_tcapranges_cmd,
	"show cs7 instance <0-15> as name AS_NAME tcap-ranges",
	SHOW_STR CS7_STR INST_STR INST_STR "Application Server (AS)\n"
	"Look up AS with a given name\n"
	"Name of the Application Server (AS)\n"
	"Display tcap ranges\n")
{
	int id = atoi(argv[0]);
	const char *as_name = argv[1];
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_as *as = NULL;
	int i;
	struct tcap_range *tcrng;

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

	vty_out(vty, "Tid Min Tid Max SSN PC            ASP Name    %s", VTY_NEWLINE);
	vty_out(vty, "------- ------- --- ------------- ------------%s", VTY_NEWLINE);

	hash_for_each(as->tcap.tid_ranges, i, tcrng, list) {
		show_one_tcap_range(vty, as, tcrng);
	}


	return CMD_SUCCESS;
}

DEFUN(show_cs7_as_tcaproute_name, show_cs7_as_name_tcapranges_tid_cmd,
	"show cs7 instance <0-15> as name AS_NAME tcap-ranges tid TID",
	SHOW_STR CS7_STR INST_STR INST_STR "Application Server (AS)\n"
	"Display tcap range\n"
	"Look up AS with a given name\n"
	"Name of the Application Server (AS)\n"
	"Show tcap range for a given TID\n"
	"TID\n")
{
	int id = atoi(argv[0]);
	const char *as_name = argv[1];
	int tid = atoi(argv[2]);
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_as *as = NULL;
	int i;
	struct tcap_range *tcrng;

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

	vty_out(vty, "Tid Min Tid Max SSN PC            ASP Name    %s", VTY_NEWLINE);
	vty_out(vty, "------- ------- --- ------------- ------------%s", VTY_NEWLINE);

	hash_for_each(as->tcap.tid_ranges, i, tcrng, list) {
		if (tid < tcrng->tid_start || tid > tcrng->tid_end)
			continue;
		show_one_tcap_range(vty, as, tcrng);
	}


	return CMD_SUCCESS;
}

void tcap_as_vty_init(void)
{
	install_lib_element_ve(&show_cs7_as_name_tcapranges_cmd);
	install_lib_element_ve(&show_cs7_as_name_tcapranges_tid_cmd);
}
