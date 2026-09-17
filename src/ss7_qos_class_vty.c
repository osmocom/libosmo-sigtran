/* SS7 QoS Class VTY Interface */

/* (C) 2026 by sysmocom s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>

#include "ss7_vty.h"
#include "ss7_qos_class.h"

/***********************************************************************
 * QoS Class Definition
 ***********************************************************************/

static struct cmd_node qos_class_node = {
	L_CS7_QOS_CLASS_NODE,
	"%s(config-cs7-qos-class)# ",
	1,
};

DEFUN_ATTR(cs7_qos_class, cs7_qos_class_cmd,
	   "qos class " SS7_QOS_CLASS_RANGE_STR,
	   "QoS definition\n"
	   "QoS class definition\n"
	   SS7_QOS_CLASS_RANGE_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	struct ss7_qos_class *qos;

	qos = ss7_qos_class_find_or_create(inst, atoi(argv[0]), 0);
	if (!qos) {
		vty_out(vty, "Failed to add new QoS class %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	vty->node = L_CS7_QOS_CLASS_NODE;
	vty->index = qos;

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_no_qos_class, cs7_no_qos_class_cmd,
	   "no qos class " SS7_QOS_CLASS_RANGE_STR,
	   NO_STR
	   "QoS definition\n"
	   "QoS class definition\n"
	   SS7_QOS_CLASS_RANGE_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	struct ss7_qos_class *qos;

	qos = ss7_qos_class_find(inst, atoi(argv[0]));
	if (!qos) {
		vty_out(vty, "QoS class %s does not exists%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	ss7_qos_class_destroy(qos);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_qos_ip_dscp, cs7_qos_ip_dscp_cmd,
	   "qos-ip-dscp " IP_DSCP_RANGE_STR,
	   "Specify IP DSCP of QoS class\n"
	   IP_DSCP_RANGE_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct ss7_qos_class *qos = vty->index;

	qos->ip_dscp = atoi(argv[0]);
	ss7_qos_class_update(qos);

	return CMD_SUCCESS;
}

DEFUN_ATTR(cs7_no_qos_ip_dscp, cs7_no_qos_ip_dscp_cmd,
	   "no qos-ip-dscp",
	   NO_STR "Reset IP DSCP of QoS class to default\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct ss7_qos_class *qos = vty->index;

	qos->ip_dscp = 0;
	ss7_qos_class_update(qos);

	return CMD_SUCCESS;
}

void ss7_vty_write_one_qos_class(struct vty *vty, struct ss7_qos_class *qos)
{
	/* Only show class, if it has ip-dscp set. */
	vty_out(vty, " qos class %u%s", qos->qos_class, VTY_NEWLINE);
	if (qos->ip_dscp)
		vty_out(vty, "  qos-ip-dscp %u%s", qos->ip_dscp, VTY_NEWLINE);
	else
		vty_out(vty, "  no qos-ip-dscp%s", VTY_NEWLINE);
}

void ss7_vty_init_node_qos_class(void)
{
	install_node(&qos_class_node, NULL);
	install_lib_element(L_CS7_NODE, &cs7_qos_class_cmd);
	install_lib_element(L_CS7_NODE, &cs7_no_qos_class_cmd);
	install_lib_element(L_CS7_QOS_CLASS_NODE, &cs7_qos_ip_dscp_cmd);
	install_lib_element(L_CS7_QOS_CLASS_NODE, &cs7_no_qos_ip_dscp_cmd);
}
