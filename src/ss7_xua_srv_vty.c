/* SS7 xua_srv VTY Interface */

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

#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include "xua_internal.h"
#include "ss7_asp.h"
#include "ss7_internal.h"
#include "ss7_vty.h"
#include "ss7_xua_srv.h"

/***********************************************************************
 * xUA Listener Configuration (SG)
 ***********************************************************************/

static struct cmd_node xua_node = {
	L_CS7_XUA_NODE,
	"%s(config-cs7-listen)# ",
	1,
};

DEFUN_ATTR(cs7_xua, cs7_xua_cmd,
	   "listen " XUA_VAR_STR " <0-65534> [" IPPROTO_VAR_STR "]",
	   "Configure/Enable xUA Listener\n"
	   XUA_VAR_HELP_STR
	   "Port number\n"
	   IPPROTO_VAR_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[0]);
	uint16_t port = atoi(argv[1]);
	int trans_proto;

	if (argc > 2)
		trans_proto = parse_trans_proto(argv[2]);
	else /* default transport protocol */
		trans_proto = ss7_default_trans_proto_for_asp_proto(proto);
	if (trans_proto < 0)
		return CMD_WARNING;

	xs = ss7_xua_server_find2(inst, trans_proto, proto, port);
	if (!xs) {
		xs = ss7_xua_server_create2(inst, trans_proto, proto, port, NULL);
		if (!xs)
			return CMD_WARNING;
		/* Drop first dummy address created automatically by _create(): */
		ss7_xua_server_set_local_hosts(xs, NULL, 0);
	}

	vty->node = L_CS7_XUA_NODE;
	vty->index = xs;
	return CMD_SUCCESS;
}

DEFUN_ATTR(no_cs7_xua, no_cs7_xua_cmd,
	   "no listen " XUA_VAR_STR " <0-65534> [" IPPROTO_VAR_STR "]",
	   NO_STR "Disable xUA Listener on given port\n"
	   XUA_VAR_HELP_STR
	   "Port number\n"
	   IPPROTO_VAR_HELP_STR,
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	struct osmo_xua_server *xs;
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[0]);
	uint16_t port = atoi(argv[1]);
	int trans_proto;

	if (argc > 2)
		trans_proto = parse_trans_proto(argv[2]);
	else /* default transport protocol */
		trans_proto = ss7_default_trans_proto_for_asp_proto(proto);
	if (trans_proto < 0)
		return CMD_WARNING;

	xs = ss7_xua_server_find2(inst, trans_proto, proto, port);
	if (!xs) {
		vty_out(vty, "No xUA server for port %u found%s", port, VTY_NEWLINE);
		return CMD_WARNING;
	}
	ss7_xua_server_destroy(xs);
	return CMD_SUCCESS;
}

DEFUN_ATTR(xua_local_ip, xua_local_ip_cmd,
	   "local-ip " VTY_IPV46_CMD,
	   "Configure the Local IP Address for xUA\n"
	   "IPv4 Address to use for XUA\n"
	   "IPv6 Address to use for XUA\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_xua_server *xs = vty->index;

	ss7_xua_server_add_local_host(xs, argv[0]);

	return CMD_SUCCESS;
}

DEFUN_ATTR(xua_no_local_ip, xua_no_local_ip_cmd,
	   "no local-ip " VTY_IPV46_CMD,
	   NO_STR "Configure the Local IP Address for xUA\n"
	   "IPv4 Address to use for XUA\n"
	   "IPv6 Address to use for XUA\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_xua_server *xs = vty->index;

	if (ss7_xua_server_del_local_host(xs, argv[0]) != 0) {
		vty_out(vty, "%% Failed deleting local address '%s' from set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(xua_accept_dyn_asp, xua_accept_dyn_asp_cmd,
	   "accept-asp-connections (pre-configured|dynamic-permitted)",
	   "Define what kind of ASP connections to accept\n"
	   "Accept only pre-configured ASPs (source IP/port)\n"
	   "Accept any connection and dynamically create an ASP definition\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_xua_server *xs = vty->index;

	if (!strcmp(argv[0], "dynamic-permitted"))
		xs->cfg.accept_dyn_reg = true;
	else
		xs->cfg.accept_dyn_reg = false;

	return CMD_SUCCESS;
}

#define XUA_SRV_SCTP_PARAM_INIT_DESC \
	"Configure SCTP parameters\n" \
	"Configure INIT related parameters\n" \
	"Configure INIT Number of Outbound Streams\n" \
	"Configure INIT Maximum Inboud Streams\n"
#define XUA_SRV_SCTP_PARAM_INIT_FIELDS "(num-ostreams|max-instreams)"

DEFUN_ATTR(xua_sctp_param_init, xua_sctp_param_init_cmd,
	   "sctp-param init " XUA_SRV_SCTP_PARAM_INIT_FIELDS " <0-65535>",
	   XUA_SRV_SCTP_PARAM_INIT_DESC
	   "Value of the parameter\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_xua_server *xs = vty->index;

	uint16_t val = atoi(argv[1]);

	if (strcmp(argv[0], "num-ostreams") == 0) {
		xs->cfg.sctp_init.num_ostreams_present = true;
		xs->cfg.sctp_init.num_ostreams_value = val;
	} else if (strcmp(argv[0], "max-instreams") == 0) {
		xs->cfg.sctp_init.max_instreams_present = true;
		xs->cfg.sctp_init.max_instreams_value = val;
	} else {
		OSMO_ASSERT(0);
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(xua_no_sctp_param_init, xua_no_sctp_param_init_cmd,
	   "no sctp-param init " XUA_SRV_SCTP_PARAM_INIT_FIELDS,
	   NO_STR XUA_SRV_SCTP_PARAM_INIT_DESC,
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_xua_server *xs = vty->index;

	if (strcmp(argv[0], "num-ostreams") == 0)
		xs->cfg.sctp_init.num_ostreams_present = false;
	else if (strcmp(argv[0], "max-instreams") == 0)
		xs->cfg.sctp_init.max_instreams_present = false;
	else
		OSMO_ASSERT(0);
	return CMD_SUCCESS;
}

void ss7_vty_write_one_oxs(struct vty *vty, struct osmo_xua_server *xs)
{
	int i;

	vty_out(vty, " listen %s %u",
		get_value_string(osmo_ss7_asp_protocol_vals, xs->cfg.proto),
		xs->cfg.local.port);
	if (xs->cfg.trans_proto != ss7_default_trans_proto_for_asp_proto(xs->cfg.proto))
		vty_out(vty, " %s", get_value_string(ipproto_vals, xs->cfg.trans_proto));
	vty_out(vty, "%s", VTY_NEWLINE);

	for (i = 0; i < xs->cfg.local.host_cnt; i++) {
		if (xs->cfg.local.host[i])
			vty_out(vty, "  local-ip %s%s", xs->cfg.local.host[i], VTY_NEWLINE);
	}
	if (xs->cfg.accept_dyn_reg)
		vty_out(vty, "  accept-asp-connections dynamic-permitted%s", VTY_NEWLINE);
	if (xs->cfg.sctp_init.num_ostreams_present)
		vty_out(vty, "  sctp-param init num-ostreams %u%s", xs->cfg.sctp_init.num_ostreams_value, VTY_NEWLINE);
	if (xs->cfg.sctp_init.max_instreams_present)
		vty_out(vty, "  sctp-param init max-instreams %u%s", xs->cfg.sctp_init.max_instreams_value, VTY_NEWLINE);
}

static void vty_dump_xua_server(struct vty *vty, struct osmo_xua_server *xs)
{
	char buf[OSMO_SOCK_MULTIADDR_PEER_STR_MAXLEN];
	const char *proto = get_value_string(osmo_ss7_asp_protocol_vals, xs->cfg.proto);
	int fd = xs->server ? osmo_stream_srv_link_get_fd(xs->server) : -1;

	if (fd < 0) {
		if (ss7_asp_peer_snprintf(buf, sizeof(buf), &xs->cfg.local) < 0)
			snprintf(buf, sizeof(buf), "<error>");
	} else {
		char hostbuf[OSMO_SOCK_MAX_ADDRS][INET6_ADDRSTRLEN];
		size_t num_hostbuf = ARRAY_SIZE(hostbuf);
		char portbuf[6];
		int rc;
		rc = osmo_sock_multiaddr_get_ip_and_port(fd, xs->cfg.trans_proto,
							 &hostbuf[0][0], &num_hostbuf, sizeof(hostbuf[0]),
							 portbuf, sizeof(portbuf), true);
		if (rc < 0) {
			snprintf(buf, sizeof(buf), "<error>");
		} else {
			if (num_hostbuf > ARRAY_SIZE(hostbuf))
				num_hostbuf = ARRAY_SIZE(hostbuf);
			osmo_multiaddr_ip_and_port_snprintf(buf, sizeof(buf),
							    &hostbuf[0][0], num_hostbuf, sizeof(hostbuf[0]),
							    portbuf);
		}
	}
	vty_out(vty, "xUA server for %s/%s on %s is %s%s",
		proto, get_value_string(ipproto_vals, xs->cfg.trans_proto),
		buf, fd >= 0 ? "listening" : "inactive", VTY_NEWLINE);
}

static int _show_cs7_xua(struct vty *vty,
			 enum osmo_ss7_asp_protocol proto,
			 int trans_proto, int local_port)
{
	const struct osmo_ss7_instance *inst;

	llist_for_each_entry(inst, &osmo_ss7_instances, list) {
		struct osmo_xua_server *xs;

		llist_for_each_entry(xs, &inst->xua_servers, list) {
			if (xs->cfg.proto != proto)
				continue;
			if (local_port >= 0 && xs->cfg.local.port != local_port) /* optional */
				continue;
			if (trans_proto >= 0 && xs->cfg.trans_proto != trans_proto) /* optional */
				continue;
			vty_dump_xua_server(vty, xs);
		}
	}

	return CMD_SUCCESS;
}

#define SHOW_CS7_XUA_CMD \
	"show cs7 " XUA_VAR_STR
#define SHOW_CS7_XUA_CMD_HELP \
	SHOW_STR CS7_STR XUA_VAR_HELP_STR

DEFUN(show_cs7_xua, show_cs7_xua_cmd,
      SHOW_CS7_XUA_CMD " [<0-65534>]",
      SHOW_CS7_XUA_CMD_HELP "Local Port Number\n")
{
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[0]);
	int local_port = (argc > 1) ? atoi(argv[1]) : -1;

	return _show_cs7_xua(vty, proto, -1, local_port);
}

DEFUN(show_cs7_xua_trans_proto, show_cs7_xua_trans_proto_cmd,
      SHOW_CS7_XUA_CMD " " IPPROTO_VAR_STR " [<0-65534>]",
      SHOW_CS7_XUA_CMD_HELP IPPROTO_VAR_HELP_STR "Local Port Number\n")
{
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[0]);
	int trans_proto = parse_trans_proto(argv[1]);
	int local_port = (argc > 2) ? atoi(argv[2]) : -1;

	return _show_cs7_xua(vty, proto, trans_proto, local_port);
}

int ss7_vty_node_oxs_go_parent(struct vty *vty)
{
	struct osmo_xua_server *oxs = vty->index;

	/* If no local addr was set, or erased after _create(): */
	ss7_xua_server_set_default_local_hosts(oxs);
	if (ss7_xua_server_bind(oxs) < 0)
		vty_out(vty, "%% Unable to bind xUA server to IP(s)%s", VTY_NEWLINE);
	vty->node = L_CS7_NODE;
	vty->index = oxs->inst;

	return 0;
}

void ss7_vty_init_show_oxs(void)
{
	install_lib_element_ve(&show_cs7_xua_cmd);
	install_lib_element_ve(&show_cs7_xua_trans_proto_cmd);
}

void ss7_vty_init_node_oxs(void)
{
	install_node(&xua_node, NULL);
	install_lib_element(L_CS7_NODE, &cs7_xua_cmd);
	install_lib_element(L_CS7_NODE, &no_cs7_xua_cmd);
	install_lib_element(L_CS7_XUA_NODE, &xua_local_ip_cmd);
	install_lib_element(L_CS7_XUA_NODE, &xua_no_local_ip_cmd);
	install_lib_element(L_CS7_XUA_NODE, &xua_accept_dyn_asp_cmd);
	install_lib_element(L_CS7_XUA_NODE, &xua_sctp_param_init_cmd);
	install_lib_element(L_CS7_XUA_NODE, &xua_no_sctp_param_init_cmd);
}
