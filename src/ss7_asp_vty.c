/* SS7 ASP VTY Interface */

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

#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>

#include <osmocom/core/sockaddr_str.h>

#include <osmocom/vty/vty.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/misc.h>

#include <osmocom/netif/stream.h>

#include <osmocom/sigtran/osmo_ss7.h>

#include "xua_internal.h"
#include "ss7_as.h"
#include "ss7_asp.h"
#include "ss7_combined_linkset.h"
#include <ss7_linkset.h>
#include "ss7_internal.h"
#include "ss7_vty.h"

#include <netinet/tcp.h>

#ifdef HAVE_LIBSCTP
#include <netinet/sctp.h>
#include <osmocom/netif/sctp.h>
#endif

/***********************************************************************
 * Application Server Process
 ***********************************************************************/

static struct cmd_node asp_node = {
	L_CS7_ASP_NODE,
	"%s(config-cs7-asp)# ",
	1,
};

/* netinet/tcp.h */
static const struct value_string tcp_info_state_values[] = {
	{ TCP_ESTABLISHED,	"ESTABLISHED" },
	{ TCP_SYN_SENT,		"SYN_SENT" },
	{ TCP_SYN_RECV,		"SYN_RECV" },
	{ TCP_FIN_WAIT1,	"FIN_WAIT1" },
	{ TCP_FIN_WAIT2,	"FIN_WAIT2" },
	{ TCP_TIME_WAIT,	"TIME_WAIT" },
	{ TCP_CLOSE,		"CLOSE" },
	{ TCP_CLOSE_WAIT,	"CLOSE_WAIT" },
	{ TCP_LAST_ACK,		"LAST_ACK" },
	{ TCP_LISTEN,		"LISTEN" },
	{ TCP_CLOSING,		"CLOSING" },
	{}
};


static const struct value_string asp_quirk_names[] = {
	{ OSMO_SS7_ASP_QUIRK_NO_NOTIFY,		"no_notify" },
	{ OSMO_SS7_ASP_QUIRK_DAUD_IN_ASP,	"daud_in_asp" },
	{ OSMO_SS7_ASP_QUIRK_SNM_INACTIVE,	"snm_inactive" },
	{ 0, NULL }
};

static const struct value_string asp_quirk_descs[] = {
	{ OSMO_SS7_ASP_QUIRK_NO_NOTIFY, "Peer SG doesn't send NTFY(AS-INACTIVE) after ASP-UP" },
	{ OSMO_SS7_ASP_QUIRK_DAUD_IN_ASP, "Allow Rx of DAUD in ASP role" },
	{ OSMO_SS7_ASP_QUIRK_SNM_INACTIVE, "Allow Rx of [S]SNM in AS-INACTIVE state" },
	{ 0, NULL }
};

DEFUN_ATTR(cs7_asp, cs7_asp_cmd,
	   "asp NAME <0-65535> <0-65535> " XUA_VAR_STR,
	   "Configure Application Server Process\n"
	   "Name of ASP\n"
	   "Remote port number\n"
	   "Local port number\n"
	   XUA_VAR_HELP_STR,
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_instance *inst = vty->index;
	const char *name = argv[0];
	uint16_t remote_port = atoi(argv[1]);
	uint16_t local_port = atoi(argv[2]);
	enum osmo_ss7_asp_protocol proto = parse_asp_proto(argv[3]);
	struct osmo_ss7_asp *asp;
	int trans_proto;

	if (proto == OSMO_SS7_ASP_PROT_NONE) {
		vty_out(vty, "invalid protocol '%s'%s", argv[3], VTY_NEWLINE);
		return CMD_WARNING;
	}

	/* argv[4] can be supplied by an alias (see below) */
	if (argc > 4)
		trans_proto = parse_trans_proto(argv[4]);
	else /* default transport protocol */
		trans_proto = ss7_default_trans_proto_for_asp_proto(proto);
	if (trans_proto < 0)
		return CMD_WARNING;

	asp = osmo_ss7_asp_find2(inst, name,
				 remote_port, local_port,
				 trans_proto, proto);
	if (!asp) {
		asp = osmo_ss7_asp_find_or_create2(inst, name,
						   remote_port, local_port,
						   trans_proto, proto);
		if (!asp) {
			vty_out(vty, "cannot create ASP '%s'%s", name, VTY_NEWLINE);
			return CMD_WARNING;
		}
		asp->cfg.is_server = true;
		asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
	}

	/* Reset value, will be checked at osmo_ss7_vty_go_parent() */
	asp->cfg.explicit_shutdown_state_by_vty_since_node_enter = false;

	vty->node = L_CS7_ASP_NODE;
	vty->index = asp;
	vty->index_sub = &asp->cfg.description;
	return CMD_SUCCESS;
}

/* XXX: workaround for https://osmocom.org/issues/6360, can be removed once it's fixed.
 * Currently we hit an assert if we make the IPPROTO_VAR_STR optional in cs7_asp_cmd. */
ALIAS_ATTR(cs7_asp, cs7_asp_trans_proto_cmd,
	   "asp NAME <0-65535> <0-65535> " XUA_VAR_STR " " IPPROTO_VAR_STR,
	   "Configure Application Server Process\n"
	   "Name of ASP\n"
	   "Remote port number\n"
	   "Local port number\n"
	   XUA_VAR_HELP_STR
	   IPPROTO_VAR_HELP_STR,
	   CMD_ATTR_NODE_EXIT);

DEFUN_ATTR(no_cs7_asp, no_cs7_asp_cmd,
	   "no asp NAME",
	   NO_STR "Disable Application Server Process\n"
	   "Name of ASP\n",
	   CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_instance *inst = vty->index;
	const char *name = argv[0];
	struct osmo_ss7_asp *asp;

	asp = osmo_ss7_asp_find_by_name(inst, name);
	if (!asp) {
		vty_out(vty, "No ASP named '%s' found%s", name, VTY_NEWLINE);
		return CMD_WARNING;
	}
	osmo_ss7_asp_destroy(asp);
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_local_ip, asp_local_ip_cmd,
	   "local-ip " VTY_IPV46_CMD " [primary]",
	   "Specify Local IP Address from which to contact ASP\n"
	   "Local IPv4 Address from which to contact of ASP\n"
	   "Local IPv6 Address from which to contact of ASP\n"
	   "Signal the SCTP peer to use this address as Primary Address\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;
	bool is_primary = argc > 1;
	int old_idx_primary = asp->cfg.local.idx_primary;
	int old_host_count = asp->cfg.local.host_cnt;
	int rc;

	if (ss7_asp_peer_add_host2(&asp->cfg.local, asp, argv[0], is_primary) != 0) {
		vty_out(vty, "%% Failed adding host '%s' to set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!ss7_asp_is_started(asp))
		return CMD_SUCCESS;
	if (asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
		return CMD_SUCCESS;
	/* The SCTP socket is already created. */

	/* dynamically apply the new address if it was added to the set: */
	if (asp->cfg.local.host_cnt > old_host_count) {
		if ((rc = ss7_asp_apply_new_local_address(asp, asp->cfg.local.host_cnt - 1)) < 0) {
			/* Failed, rollback changes: */
			TALLOC_FREE(asp->cfg.local.host[asp->cfg.local.host_cnt - 1]);
			asp->cfg.local.host_cnt--;
			vty_out(vty, "%% Failed adding new local address '%s'%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
		vty_out(vty, "%% Local address '%s' added to the active socket bind set%s", argv[0], VTY_NEWLINE);
	}

	/* dynamically apply the new primary if it changed: */
	if (is_primary && asp->cfg.local.idx_primary != old_idx_primary) {
		if ((rc = ss7_asp_apply_peer_primary_address(asp)) < 0) {
			/* Failed, rollback changes: */
			asp->cfg.local.idx_primary = old_idx_primary;
			vty_out(vty, "%% Failed announcing primary '%s' to peer%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
		vty_out(vty, "%% Local address '%s' announced as primary to the peer on the active socket%s", argv[0], VTY_NEWLINE);
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_no_local_ip, asp_no_local_ip_cmd,
	   "no local-ip " VTY_IPV46_CMD,
	   NO_STR "Specify Local IP Address from which to contact ASP\n"
	   "Local IPv4 Address from which to contact of ASP\n"
	   "Local IPv6 Address from which to contact of ASP\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;
	int idx = ss7_asp_peer_find_host(&asp->cfg.local, argv[0]);
	int rc;

	if (idx < 0) {
		vty_out(vty, "%% Local address '%s' not found in set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ss7_asp_is_started(asp)) {
		if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA) {
			if ((rc = ss7_asp_apply_drop_local_address(asp, idx)) < 0) {
				vty_out(vty, "%% Failed removing local address '%s' from existing socket%s", argv[0], VTY_NEWLINE);
				return CMD_WARNING;
			}
			vty_out(vty, "%% Local address '%s' removed from active socket connection%s", argv[0], VTY_NEWLINE);
		}
	}

	if (ss7_asp_peer_del_host(&asp->cfg.local, argv[0]) != 0) {
		vty_out(vty, "%% Failed deleting local address '%s' from set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_remote_ip, asp_remote_ip_cmd,
	   "remote-ip " VTY_IPV46_CMD " [primary]",
	   "Specify Remote IP Address of ASP\n"
	   "Remote IPv4 Address of ASP\n"
	   "Remote IPv6 Address of ASP\n"
	   "Set remote address as SCTP Primary Address\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;
	bool is_primary = argc > 1;
	int old_idx_primary = asp->cfg.remote.idx_primary;
	int rc;

	if (ss7_asp_peer_add_host2(&asp->cfg.remote, asp, argv[0], is_primary) != 0) {
		vty_out(vty, "%% Failed adding host '%s' to set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!ss7_asp_is_started(asp))
		return CMD_SUCCESS;
	if (asp->cfg.proto == OSMO_SS7_ASP_PROT_IPA)
		return CMD_SUCCESS;

	/* The SCTP socket is already created, dynamically apply the new primary if it changed: */
	if (asp->cfg.proto != OSMO_SS7_ASP_PROT_IPA && ss7_asp_is_started(asp)) {
		if ((rc = ss7_asp_apply_primary_address(asp)) < 0) {
			/* Failed, rollback changes: */
			asp->cfg.remote.idx_primary = old_idx_primary;
			vty_out(vty, "%% Failed applying primary on host '%s'%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_no_remote_ip, asp_no_remote_ip_cmd,
	   "no remote-ip " VTY_IPV46_CMD,
	   NO_STR  "Specify Remote IP Address of ASP\n"
	   "Remote IPv4 Address of ASP\n"
	   "Remote IPv6 Address of ASP\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;
	int idx = ss7_asp_peer_find_host(&asp->cfg.remote, argv[0]);

	if (idx < 0) {
		vty_out(vty, "%% Remote address '%s' not found in set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (ss7_asp_peer_del_host(&asp->cfg.remote, argv[0]) != 0) {
		vty_out(vty, "%% Failed deleting remote address '%s' from set%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_qos_clas, asp_qos_class_cmd,
	   "qos-class " QOS_CLASS_RANGE_STR,
	   "Specify QoS Class of ASP\n"
	   QOS_CLASS_RANGE_HELP_STR,
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;
	asp->cfg.qos_class = atoi(argv[0]);
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_role, asp_role_cmd,
	   "role (sg|asp|ipsp)",
	   "Specify the xUA role for this ASP\n"
	   "SG (Signaling Gateway)\n"
	   "ASP (Application Server Process)\n"
	   "IPSP (IP Signalling Point)\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;

	if (!strcmp(argv[0], "ipsp")) {
		vty_out(vty, "IPSP role isn't supported yet%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (!strcmp(argv[0], "sg"))
		asp->cfg.role = OSMO_SS7_ASP_ROLE_SG;
	else if (!strcmp(argv[0], "asp"))
		asp->cfg.role = OSMO_SS7_ASP_ROLE_ASP;
	else
		OSMO_ASSERT(0);

	asp->cfg.role_set_by_vty = true;
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_transport_role, asp_transport_role_cmd,
	   "transport-role (client|server)",
	   "Specify the transport layer role for this ASP\n"
	   "Operate as a client; connect to a server\n"
	   "Operate as a server; wait for client connections\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;

	if (!strcmp(argv[0], "client"))
		asp->cfg.is_server = false;
	else if (!strcmp(argv[0], "server"))
		asp->cfg.is_server = true;
	else
		OSMO_ASSERT(0);

	asp->cfg.trans_role_set_by_vty = true;
	return CMD_SUCCESS;
}

ALIAS_ATTR(asp_transport_role, asp_sctp_role_cmd,
	   "sctp-role (client|server)",
	   "Specify the SCTP role for this ASP\n"
	   "Operate as SCTP client; connect to a server\n"
	   "Operate as SCTP server; wait for client connections\n",
	   CMD_ATTR_HIDDEN | CMD_ATTR_NODE_EXIT);

#define ASP_SCTP_PARAM_INIT_DESC \
	"Configure SCTP parameters\n" \
	"Configure INIT related parameters\n" \
	"Configure INIT Number of Outbound Streams\n" \
	"Configure INIT Maximum Inboud Streams\n" \
	"Configure INIT Maximum Attempts\n" \
	"Configure INIT Timeout (milliseconds)\n"
#define ASP_SCTP_PARAM_INIT_FIELDS "(num-ostreams|max-instreams|max-attempts|timeout)"

DEFUN_ATTR(asp_sctp_param_init, asp_sctp_param_init_cmd,
	   "sctp-param init " ASP_SCTP_PARAM_INIT_FIELDS " <0-65535>",
	   ASP_SCTP_PARAM_INIT_DESC
	   "Value of the parameter\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;

	uint16_t val = atoi(argv[1]);

	if (strcmp(argv[0], "num-ostreams") == 0) {
		asp->cfg.sctp_init.num_ostreams_present = true;
		asp->cfg.sctp_init.num_ostreams_value = val;
	} else if (strcmp(argv[0], "max-instreams") == 0) {
		asp->cfg.sctp_init.max_instreams_present = true;
		asp->cfg.sctp_init.max_instreams_value = val;
	} else if (strcmp(argv[0], "max-attempts") == 0) {
		asp->cfg.sctp_init.max_attempts_present = true;
		asp->cfg.sctp_init.max_attempts_value = val;
	} else if (strcmp(argv[0], "timeout") == 0) {
		asp->cfg.sctp_init.max_init_timeo_present = true;
		asp->cfg.sctp_init.max_init_timeo_value = val;
	} else {
		OSMO_ASSERT(0);
	}
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_no_sctp_param_init, asp_no_sctp_param_init_cmd,
	   "no sctp-param init " ASP_SCTP_PARAM_INIT_FIELDS,
	   NO_STR ASP_SCTP_PARAM_INIT_DESC,
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;

	if (strcmp(argv[0], "num-ostreams") == 0)
		asp->cfg.sctp_init.num_ostreams_present = false;
	else if (strcmp(argv[0], "max-instreams") == 0)
		asp->cfg.sctp_init.max_instreams_present = false;
	else if (strcmp(argv[0], "max-attempts") == 0)
		asp->cfg.sctp_init.max_attempts_present = false;
	else if (strcmp(argv[0], "timeout") == 0)
		asp->cfg.sctp_init.max_init_timeo_present = false;
	else
		OSMO_ASSERT(0);
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_block, asp_block_cmd,
	   "block",
	   "Allows a SCTP Association with ASP, but doesn't let it become active\n",
	   CMD_ATTR_NODE_EXIT)
{
	/* TODO */
	vty_out(vty, "Not supported yet%s", VTY_NEWLINE);
	return CMD_WARNING;
}

DEFUN_ATTR(asp_shutdown, asp_shutdown_cmd,
	   "shutdown",
	   "Terminates SCTP association; New associations will be rejected\n",
	   CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;

	LOGPASP(asp, DLSS7, LOGL_NOTICE, "Applying Adm State change: %s -> %s\n",
		get_value_string(osmo_ss7_asp_admin_state_names, asp->cfg.adm_state),
		get_value_string(osmo_ss7_asp_admin_state_names, OSMO_SS7_ASP_ADM_S_SHUTDOWN));

	asp->cfg.explicit_shutdown_state_by_vty_since_node_enter = true;
	asp->cfg.adm_state = OSMO_SS7_ASP_ADM_S_SHUTDOWN;
	ss7_asp_restart_after_reconfigure(asp);
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_no_shutdown, asp_no_shutdown_cmd,
	"no shutdown",
	NO_STR "Terminates SCTP association; New associations will be rejected\n",
	CMD_ATTR_NODE_EXIT)
{
	struct osmo_ss7_asp *asp = vty->index;

	LOGPASP(asp, DLSS7, LOGL_NOTICE, "Applying Adm State change: %s -> %s\n",
		get_value_string(osmo_ss7_asp_admin_state_names, asp->cfg.adm_state),
		get_value_string(osmo_ss7_asp_admin_state_names, OSMO_SS7_ASP_ADM_S_ENABLED));

	asp->cfg.explicit_shutdown_state_by_vty_since_node_enter = true;
	asp->cfg.adm_state = OSMO_SS7_ASP_ADM_S_ENABLED;
	ss7_asp_restart_after_reconfigure(asp);
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_quirk, asp_quirk_cmd,
	"OVERWRITTEN",
	"OVERWRITTEN\n",
	CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_asp *asp = vty->index;
	int quirk = get_string_value(asp_quirk_names, argv[0]);

	if (quirk < 0)
		return CMD_WARNING;

	asp->cfg.quirks |= quirk;
	return CMD_SUCCESS;
}

DEFUN_ATTR(asp_no_quirk, asp_no_quirk_cmd,
	"OVERWRITTEN",
	"OVERWRITTEN\n",
	CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_asp *asp = vty->index;
	int quirk = get_string_value(asp_quirk_names, argv[0]);

	if (quirk < 0)
		return CMD_WARNING;

	asp->cfg.quirks &= ~quirk;
	return CMD_SUCCESS;
}

/* timer lm <name> <1-999999>
 * (cmdstr and doc are dynamically generated from ss7_asp_lm_timer_names.) */
DEFUN_ATTR(asp_timer, asp_timer_cmd,
	   NULL, NULL, CMD_ATTR_IMMEDIATE)
{
	struct osmo_ss7_asp *asp = vty->index;
	enum ss7_asp_lm_timer timer = get_string_value(ss7_asp_lm_timer_names, argv[0]);

	if (timer <= 0 || timer >= SS7_ASP_LM_TIMERS_LEN) {
		vty_out(vty, "%% Invalid timer: %s%s", argv[0], VTY_NEWLINE);
		return CMD_WARNING;
	}

	osmo_tdef_set(asp->cfg.T_defs_lm, timer, atoi(argv[1]), OSMO_TDEF_S);
	return CMD_SUCCESS;
}

static void gen_asp_timer_cmd_strs(struct cmd_element *cmd)
{
	int i;
	char *cmd_str = NULL;
	char *doc_str = NULL;

	OSMO_ASSERT(cmd->string == NULL);
	OSMO_ASSERT(cmd->doc == NULL);

	osmo_talloc_asprintf(tall_vty_ctx, cmd_str, "timer lm (");
	osmo_talloc_asprintf(tall_vty_ctx, doc_str,
			     "Configure ASP default timer values\n"
			     "Configure ASP default lm timer values\n");

	for (i = 0; ss7_asp_lm_timer_names[i].str; i++) {
		const struct osmo_tdef *def;
		enum ss7_asp_lm_timer timer;

		timer = ss7_asp_lm_timer_names[i].value;
		def = osmo_tdef_get_entry((struct osmo_tdef *)&ss7_asp_lm_timer_defaults, timer);
		OSMO_ASSERT(def);

		osmo_talloc_asprintf(tall_vty_ctx, cmd_str, "%s%s",
				     i ? "|" : "",
				     ss7_asp_lm_timer_names[i].str);
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

static void write_asp_timers(struct vty *vty, const char *indent,
				struct osmo_ss7_asp *asp)
{
	int i;

	for (i = 0; ss7_asp_lm_timer_names[i].str; i++) {
		const struct osmo_tdef *tdef = osmo_tdef_get_entry(asp->cfg.T_defs_lm, ss7_asp_lm_timer_names[i].value);
		if (!tdef)
			continue;
		if (tdef->val == tdef->default_val)
			continue;
		vty_out(vty, "%stimer lm %s %lu%s", indent, ss7_asp_lm_timer_names[i].str,
			tdef->val, VTY_NEWLINE);
	}
}

static char *as_list_for_asp(const struct osmo_ss7_asp *asp, char *buf, size_t buf_len)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buf_len };
	const struct osmo_ss7_as *as;
	unsigned int count = 0;
	llist_for_each_entry(as, &asp->inst->as_list, list) {
		if (!osmo_ss7_as_has_asp(as, asp))
			continue;
		OSMO_STRBUF_PRINTF(sb, "%s%s", count != 0 ? "," : "", as->cfg.name);
		count++;
		break;
	}

	if (count == 0)
		OSMO_STRBUF_PRINTF(sb, "?");
	return buf;
}

/* Similar to osmo_sock_multiaddr_get_name_buf(), but aimed at listening sockets (only local part): */
static char *get_sockname_buf(char *buf, size_t buf_len, int fd, int proto, bool local)
{
	char hostbuf[OSMO_SOCK_MAX_ADDRS][INET6_ADDRSTRLEN];
	size_t num_hostbuf = ARRAY_SIZE(hostbuf);
	char portbuf[6];
	struct osmo_strbuf sb = { .buf = buf, .len = buf_len };
	bool need_more_bufs;
	int rc;

	rc = osmo_sock_multiaddr_get_ip_and_port(fd, proto, &hostbuf[0][0],
						 &num_hostbuf, sizeof(hostbuf[0]),
						 portbuf, sizeof(portbuf), local);
	if (rc < 0)
		return NULL;

	need_more_bufs = num_hostbuf > ARRAY_SIZE(hostbuf);
	if (need_more_bufs)
		num_hostbuf = ARRAY_SIZE(hostbuf);
	OSMO_STRBUF_APPEND(sb, osmo_multiaddr_ip_and_port_snprintf,
			   &hostbuf[0][0], num_hostbuf, sizeof(hostbuf[0]), portbuf);
	if (need_more_bufs)
		OSMO_STRBUF_PRINTF(sb, "<need-more-bufs!>");

	return buf;
}

static void show_one_asp(struct vty *vty, struct osmo_ss7_asp *asp)
{
	char as_buf[64];
	char buf_loc[OSMO_SOCK_MULTIADDR_PEER_STR_MAXLEN];
	char buf_rem[sizeof(buf_loc)];

	int fd = ss7_asp_get_fd(asp);
	if (fd > 0) {
		const int trans_proto = asp->cfg.trans_proto;
		if (!get_sockname_buf(buf_loc, sizeof(buf_loc), fd, trans_proto, true))
			OSMO_STRLCPY_ARRAY(buf_loc, "<sockname-error>");
		if (!get_sockname_buf(buf_rem, sizeof(buf_rem), fd, trans_proto, false))
			OSMO_STRLCPY_ARRAY(buf_rem, "<sockname-error>");
	} else {
		ss7_asp_peer_snprintf(buf_loc, sizeof(buf_loc), &asp->cfg.local);
		ss7_asp_peer_snprintf(buf_rem, sizeof(buf_rem), &asp->cfg.remote);
	}

	vty_out(vty, "%-12s  %-12s  %-13s  %-4s  %-4s  %-9s  %-23s  %-23s%s",
		asp->cfg.name,
		as_list_for_asp(asp, as_buf, sizeof(as_buf)),
		asp->fi ? osmo_fsm_inst_state_name(asp->fi) : "uninitialized",
		get_value_string(osmo_ss7_asp_protocol_vals, asp->cfg.proto),
		osmo_str_tolower(get_value_string(osmo_ss7_asp_role_names, asp->cfg.role)),
		asp->cfg.is_server ? "server" : "client",
		buf_loc, buf_rem,
		VTY_NEWLINE);
}

static int show_asp(struct vty *vty, int id, const char *asp_name)
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_asp *asp = NULL;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (asp_name) {
		asp = osmo_ss7_asp_find_by_name(inst, asp_name);
		if (!asp) {
			vty_out(vty, "No ASP %s found%s", asp_name, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	vty_out(vty, "ASP Name      AS Name       State          Type  Role  SCTP Role  Local Addresses          Remote Addresses%s", VTY_NEWLINE);
	vty_out(vty, "------------  ------------  -------------  ----  ----  ---------  -----------------------  -----------------------%s", VTY_NEWLINE);

	if (asp) {
		show_one_asp(vty, asp);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(asp, &inst->asp_list, list)
		show_one_asp(vty, asp);
	return CMD_SUCCESS;
}

DEFUN(show_cs7_asp, show_cs7_asp_cmd,
	"show cs7 instance <0-15> asp",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Application Server Process (ASP)\n")
{
	int id = atoi(argv[0]);

	return show_asp(vty, id, NULL);
}

DEFUN(show_cs7_asp_name, show_cs7_asp_name_cmd,
	"show cs7 instance <0-15> asp name ASP_NAME",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Application Server Process (ASP)\n"
	"Lookup ASP with a given name\n"
	"Name of the Application Server Process (ASP)\n")
{
	int id = atoi(argv[0]);
	const char *asp_name = argv[1];

	return show_asp(vty, id, asp_name);
}

static void show_one_asp_remaddr_tcp(struct vty *vty, struct osmo_ss7_asp *asp)
{
	struct osmo_sockaddr osa = {};
	struct tcp_info tcpi = {};
	socklen_t len;
	int fd, rc;

	fd = ss7_asp_get_fd(asp);
	if (fd < 0) {
		vty_out(vty, "%-12s  %-46s  uninitialized%s", asp->cfg.name, "", VTY_NEWLINE);
		return;
	}

	len = sizeof(osa.u.sas);
	rc = getpeername(fd, &osa.u.sa, &len);

	len = sizeof(tcpi);
	rc = getsockopt(fd, SOL_TCP, TCP_INFO, &tcpi, &len);
	if (rc < 0) {
		char buf_err[128];
		strerror_r(errno, buf_err, sizeof(buf_err));
		vty_out(vty, "%-12s  %-46s  getsockopt(TCP_INFO) failed: %s%s",
			asp->cfg.name, osmo_sockaddr_to_str(&osa), buf_err, VTY_NEWLINE);
		return;
	}

	vty_out(vty, "%-12s  %-46s  TCP_%-19s  %-8u  %-8u  %-8u  %-8u%s",
		asp->cfg.name,
		osmo_sockaddr_to_str(&osa),
		get_value_string(tcp_info_state_values, tcpi.tcpi_state),
		tcpi.tcpi_snd_cwnd, tcpi.tcpi_rtt,
		tcpi.tcpi_rto, tcpi.tcpi_pmtu,
		VTY_NEWLINE);
}

#ifdef HAVE_LIBSCTP
static void show_one_asp_remaddr_sctp(struct vty *vty, struct osmo_ss7_asp *asp)
{
	struct sctp_paddrinfo pinfo[OSMO_SOCK_MAX_ADDRS];
	struct osmo_sockaddr osa = {};
	size_t pinfo_cnt = ARRAY_SIZE(pinfo);
	bool more_needed;
	int fd, rc;
	unsigned int i;

	fd = ss7_asp_get_fd(asp);
	if (fd < 0) {
		vty_out(vty, "%-12s  %-46s  uninitialized%s", asp->cfg.name, "", VTY_NEWLINE);
		return;
	}

	rc = osmo_sock_sctp_get_peer_addr_info(fd, &pinfo[0], &pinfo_cnt);
	if (rc < 0) {
		char buf_err[128];
		strerror_r(errno, buf_err, sizeof(buf_err));
		vty_out(vty, "%-12s  %-46s  getsockopt(SCTP_GET_PEER_ADDR_INFO) failed: %s%s", asp->cfg.name, "", buf_err, VTY_NEWLINE);
		return;
	}

	more_needed = pinfo_cnt > ARRAY_SIZE(pinfo);
	if (pinfo_cnt > ARRAY_SIZE(pinfo))
		pinfo_cnt = ARRAY_SIZE(pinfo);

	for (i = 0; i < pinfo_cnt; i++) {
		osa.u.sas = pinfo[i].spinfo_address;
		vty_out(vty, "%-12s  %-46s  SCTP_%-18s  %-8u  %-8u  %-8u  %-8u%s",
			asp->cfg.name,
			osmo_sockaddr_to_str(&osa),
			osmo_sctp_spinfo_state_str(pinfo[i].spinfo_state),
			pinfo[i].spinfo_cwnd, pinfo[i].spinfo_srtt,
			pinfo[i].spinfo_rto, pinfo[i].spinfo_mtu,
			VTY_NEWLINE);
	}

	if (more_needed)
		vty_out(vty, "%-12s  more address buffers needed!%s", asp->cfg.name, VTY_NEWLINE);
}
#endif

static void show_one_asp_remaddr(struct vty *vty, struct osmo_ss7_asp *asp)
{
	switch (asp->cfg.trans_proto) {
	case IPPROTO_TCP:
		show_one_asp_remaddr_tcp(vty, asp);
		break;
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		show_one_asp_remaddr_sctp(vty, asp);
		break;
#endif
	default:
		vty_out(vty, "%-12s  %-46s  unknown proto %d%s",
			asp->cfg.name, "", asp->cfg.trans_proto, VTY_NEWLINE);
		break;
	}
}

static int show_asp_remaddr(struct vty *vty, int id, const char *asp_name)
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_asp *asp = NULL;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (asp_name) {
		asp = osmo_ss7_asp_find_by_name(inst, asp_name);
		if (!asp) {
			vty_out(vty, "No ASP %s found%s", asp_name, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	vty_out(vty, "ASP Name      Remote IP Address & Port                        State                    CWND      SRTT      RTO       MTU%s", VTY_NEWLINE);
	vty_out(vty, "------------  ----------------------------------------------  -----------------------  --------  --------  --------  --------%s", VTY_NEWLINE);

	if (asp) {
		show_one_asp_remaddr(vty, asp);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(asp, &inst->asp_list, list) {
		show_one_asp_remaddr(vty, asp);
	}
	return CMD_SUCCESS;
}

DEFUN(show_cs7_asp_remaddr, show_cs7_asp_remaddr_cmd,
	"show cs7 instance <0-15> asp-remaddr",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Application Server Process (ASP) remote addresses information\n")
{
	int id = atoi(argv[0]);

	return show_asp_remaddr(vty, id, NULL);
}


DEFUN(show_cs7_asp_remaddr_name, show_cs7_asp_remaddr_name_cmd,
	"show cs7 instance <0-15> asp-remaddr name ASP_NAME",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Application Server Process (ASP) remote addresses information\n"
	"Lookup ASP with a given name\n"
	"Name of the Application Server Process (ASP)\n")
{
	int id = atoi(argv[0]);
	const char *asp_name = argv[1];

	return show_asp_remaddr(vty, id, asp_name);
}

static void show_one_asp_assoc_status_tcp(struct vty *vty, struct osmo_ss7_asp *asp)
{
	struct osmo_sockaddr osa = {};
	struct tcp_info tcpi = {};
	socklen_t len;
	int fd, rc;
	int rx_pend_bytes = 0;

	fd = ss7_asp_get_fd(asp);
	if (fd < 0) {
		vty_out(vty, "%-12s  uninitialized%s", asp->cfg.name, VTY_NEWLINE);
		return;
	}

	len = sizeof(osa.u.sas);
	rc = getpeername(fd, &osa.u.sa, &len);

	len = sizeof(tcpi);
	rc = getsockopt(fd, SOL_TCP, TCP_INFO, &tcpi, &len);
	if (rc < 0) {
		char buf_err[128];
		strerror_r(errno, buf_err, sizeof(buf_err));
		vty_out(vty, "%-12s  getsockopt(TCP_INFO) failed: %s%s",
			asp->cfg.name, buf_err, VTY_NEWLINE);
		return;
	}

	rc = ioctl(fd, FIONREAD, &rx_pend_bytes);

	/* FIXME: RWND: struct tcp_info from linux/tcp.h contains more fields
	 * than the one from netinet/tcp.h we currently use, including
	 * "tcpi_rcv_wnd" which we could use to print RWND here. However,
	 * linux/tcp.h seems to be missing the state defines used in
	 * "tcp_info_state_values", so we cannot use that one instead.
	 */

	vty_out(vty, "%-12s  TCP_%-19s  %-9s  %-10s  %-8s  %-9u  %-7u  %-9u  %-46s%s",
		asp->cfg.name,
		get_value_string(tcp_info_state_values, tcpi.tcpi_state),
		"-", "-", "-", tcpi.tcpi_unacked, rx_pend_bytes,
		tcpi.tcpi_pmtu, osmo_sockaddr_to_str(&osa),
		VTY_NEWLINE);
}

#ifdef HAVE_LIBSCTP
static void show_one_asp_assoc_status_sctp(struct vty *vty, struct osmo_ss7_asp *asp)
{
	struct osmo_sockaddr osa = {};
	struct sctp_status st;
	socklen_t len;
	int fd, rc;

	fd = ss7_asp_get_fd(asp);
	if (fd < 0) {
		vty_out(vty, "%-12s  uninitialized%s", asp->cfg.name, VTY_NEWLINE);
		return;
	}

	memset(&st, 0, sizeof(st));
	len = sizeof(st);
	rc = getsockopt(fd, IPPROTO_SCTP, SCTP_STATUS, &st, &len);
	if (rc < 0) {
		char buf_err[128];
		strerror_r(errno, buf_err, sizeof(buf_err));
		vty_out(vty, "%-12s  getsockopt(SCTP_STATUS) failed: %s%s", asp->cfg.name, buf_err, VTY_NEWLINE);
		return;
	}

	osa.u.sas = st.sstat_primary.spinfo_address;
	vty_out(vty, "%-12s  SCTP_%-18s  %-9u  %-10u  %-8u  %-9u  %-7u  %-9u  %-46s%s",
		asp->cfg.name,
		osmo_sctp_sstat_state_str(st.sstat_state),
		st.sstat_instrms, st.sstat_outstrms,
		st.sstat_rwnd, st.sstat_unackdata, st.sstat_penddata,
		st.sstat_fragmentation_point,
		osmo_sockaddr_to_str(&osa),
		VTY_NEWLINE);
}
#endif

static void show_one_asp_assoc_status(struct vty *vty, struct osmo_ss7_asp *asp)
{
	switch (asp->cfg.trans_proto) {
	case IPPROTO_TCP:
		show_one_asp_assoc_status_tcp(vty, asp);
		break;
#ifdef HAVE_LIBSCTP
	case IPPROTO_SCTP:
		show_one_asp_assoc_status_sctp(vty, asp);
		break;
#endif
	default:
		vty_out(vty, "%-12s  unknown proto %d%s",
			asp->cfg.name, asp->cfg.trans_proto, VTY_NEWLINE);
		break;
	}
}

static int show_asp_assoc_status(struct vty *vty, int id, const char *asp_name)
{
	struct osmo_ss7_instance *inst;
	struct osmo_ss7_asp *asp = NULL;

	inst = osmo_ss7_instance_find(id);
	if (!inst) {
		vty_out(vty, "No SS7 instance %d found%s", id, VTY_NEWLINE);
		return CMD_WARNING;
	}

	if (asp_name) {
		asp = osmo_ss7_asp_find_by_name(inst, asp_name);
		if (!asp) {
			vty_out(vty, "No ASP %s found%s", asp_name, VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	vty_out(vty, "ASP Name      State                    InStreams  OutStreams  RWND      UnackData  PenData  FragPoint  Current Primary Remote IP Address & Port%s", VTY_NEWLINE);
	vty_out(vty, "------------  -----------------------  ---------  ----------  --------  ---------  -------  ---------  ----------------------------------------------%s", VTY_NEWLINE);

	if (asp) {
		show_one_asp_assoc_status(vty, asp);
		return CMD_SUCCESS;
	}

	llist_for_each_entry(asp, &inst->asp_list, list)
		show_one_asp_assoc_status(vty, asp);
	return CMD_SUCCESS;
}

DEFUN(show_cs7_asp_assoc_status, show_cs7_asp_assoc_status_cmd,
	"show cs7 instance <0-15> asp-assoc-status",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Application Server Process (ASP) SCTP association status\n")
{
	int id = atoi(argv[0]);

	return show_asp_assoc_status(vty, id, NULL);
}


DEFUN(show_cs7_asp_assoc_status_name, show_cs7_asp_assoc_status_name_cmd,
	"show cs7 instance <0-15> asp-assoc-status name ASP_NAME",
	SHOW_STR CS7_STR INST_STR INST_STR
	"Application Server Process (ASP) SCTP association information\n"
	"Lookup ASP with a given name\n"
	"Name of the Application Server Process (ASP)\n")
{
	int id = atoi(argv[0]);
	const char *asp_name = argv[1];

	return show_asp_assoc_status(vty, id, asp_name);
}

void ss7_vty_write_one_asp(struct vty *vty, struct osmo_ss7_asp *asp, bool show_dyn_config)
{
	int i;
	/* skip any dynamically created ASPs (e.g. auto-created at connect time) */
	if ((asp->dyn_allocated || asp->simple_client_allocated)
	    && !show_dyn_config)
		return;

	vty_out(vty, " asp %s %u %u %s",
		asp->cfg.name, asp->cfg.remote.port, asp->cfg.local.port,
		osmo_ss7_asp_protocol_name(asp->cfg.proto));
	if (asp->cfg.trans_proto != ss7_default_trans_proto_for_asp_proto(asp->cfg.proto))
		vty_out(vty, " %s", get_value_string(ipproto_vals, asp->cfg.trans_proto));
	vty_out(vty, "%s", VTY_NEWLINE);
	if (asp->cfg.description)
		vty_out(vty, "  description %s%s", asp->cfg.description, VTY_NEWLINE);
	for (i = 0; i < asp->cfg.local.host_cnt; i++) {
		if (asp->cfg.local.host[i])
			vty_out(vty, "  local-ip %s%s%s", asp->cfg.local.host[i],
				asp->cfg.local.idx_primary == i ? " primary" : "", VTY_NEWLINE);
	}
	for (i = 0; i < asp->cfg.remote.host_cnt; i++) {
		if (asp->cfg.remote.host[i])
			vty_out(vty, "  remote-ip %s%s%s", asp->cfg.remote.host[i],
				asp->cfg.remote.idx_primary == i ? " primary" : "", VTY_NEWLINE);
	}
	if (asp->cfg.qos_class)
		vty_out(vty, "  qos-class %u%s", asp->cfg.qos_class, VTY_NEWLINE);
	vty_out(vty, "  role %s%s", osmo_str_tolower(get_value_string(osmo_ss7_asp_role_names, asp->cfg.role)),
		VTY_NEWLINE);
	if (asp->cfg.trans_proto == IPPROTO_SCTP)
		vty_out(vty, "  sctp-role %s%s", asp->cfg.is_server ? "server" : "client", VTY_NEWLINE);
	else
		vty_out(vty, "  transport-role %s%s", asp->cfg.is_server ? "server" : "client", VTY_NEWLINE);
	if (asp->cfg.sctp_init.num_ostreams_present)
		vty_out(vty, "  sctp-param init num-ostreams %u%s", asp->cfg.sctp_init.num_ostreams_value, VTY_NEWLINE);
	if (asp->cfg.sctp_init.max_instreams_present)
		vty_out(vty, "  sctp-param init max-instreams %u%s", asp->cfg.sctp_init.max_instreams_value, VTY_NEWLINE);
	if (asp->cfg.sctp_init.max_attempts_present)
		vty_out(vty, "  sctp-param init max-attempts %u%s", asp->cfg.sctp_init.max_attempts_value, VTY_NEWLINE);
	if (asp->cfg.sctp_init.max_init_timeo_present)
		vty_out(vty, "  sctp-param init timeout %u%s", asp->cfg.sctp_init.max_init_timeo_value, VTY_NEWLINE);
	for (i = 0; i < sizeof(uint32_t) * 8; i++) {
		if (!(asp->cfg.quirks & ((uint32_t) 1 << i)))
			continue;
		vty_out(vty, "  quirk %s%s", get_value_string(asp_quirk_names, (1 << i)), VTY_NEWLINE);
	}
	write_asp_timers(vty, "  ", asp);

	switch (asp->cfg.adm_state) {
	case OSMO_SS7_ASP_ADM_S_SHUTDOWN:
		vty_out(vty, "  shutdown%s", VTY_NEWLINE);
		break;
	case OSMO_SS7_ASP_ADM_S_BLOCKED:
		vty_out(vty, "  blocked%s", VTY_NEWLINE);
		break;
	case OSMO_SS7_ASP_ADM_S_ENABLED:
		/* Default, no need to print: */
		vty_out(vty, "  no shutdown%s", VTY_NEWLINE);
		break;
	}
}

int ss7_vty_node_asp_go_parent(struct vty *vty)
{
	struct osmo_ss7_asp *asp = vty->index;

	if (asp->cfg.explicit_shutdown_state_by_vty_since_node_enter) {
		/* Interactive VTY, inform of new behavior upon use of new '[no] shutdown' commands: */
		if (vty->type != VTY_FILE)
			vty_out(vty, "%% NOTE: Skipping automatic restart of ASP since an explicit '[no] shutdown' command was entered%s", VTY_NEWLINE);
		asp->cfg.explicit_shutdown_state_by_vty_since_node_enter = false;
	} else if (vty->type == VTY_FILE) {
		/* Make sure config reading is backward compatible by starting the ASP if no explicit 'no shutdown' is read: */
		vty_out(vty,
			"%% VTY node 'asp' without a '[no] shutdown' command at the end is deprecated, "
			"please make sure you update your cfg file for future compatibility.%s",
			VTY_NEWLINE);
		ss7_asp_restart_after_reconfigure(asp);
	} else {
		/* Interactive VTY without '[no] shutdown' explicit cmd, remind the user that we are no
			* longer automatically restarting the ASP when going out of the "asp" node: */
		vty_out(vty,
			"%% NOTE: Make sure to use '[no] shutdown' command in 'asp' node "
			"in order to restart the ASP for new configs to be applied.%s",
			VTY_NEWLINE);
	}
	vty->node = L_CS7_NODE;
	vty->index = asp->inst;
	return 0;
}

void ss7_vty_init_node_asp(void)
{
	asp_quirk_cmd.string = vty_cmd_string_from_valstr(g_ctx, asp_quirk_names,
							  "quirk (", "|", ")", VTY_DO_LOWER);
	asp_quirk_cmd.doc = vty_cmd_string_from_valstr(g_ctx, asp_quirk_descs,
							"Enable quirk to work around interop issues\n",
							"\n", "\n", 0);
	asp_no_quirk_cmd.string = vty_cmd_string_from_valstr(g_ctx, asp_quirk_names,
							  "no quirk (", "|", ")", VTY_DO_LOWER);
	asp_no_quirk_cmd.doc = vty_cmd_string_from_valstr(g_ctx, asp_quirk_descs,
							NO_STR "Disable quirk to work around interop issues\n",
							"\n", "\n", 0);

	install_node(&asp_node, NULL);
	install_lib_element_ve(&show_cs7_asp_cmd);
	install_lib_element_ve(&show_cs7_asp_name_cmd);
	install_lib_element_ve(&show_cs7_asp_remaddr_cmd);
	install_lib_element_ve(&show_cs7_asp_remaddr_name_cmd);
	install_lib_element_ve(&show_cs7_asp_assoc_status_cmd);
	install_lib_element_ve(&show_cs7_asp_assoc_status_name_cmd);
	install_lib_element(L_CS7_NODE, &cs7_asp_cmd);
	install_lib_element(L_CS7_NODE, &cs7_asp_trans_proto_cmd);
	install_lib_element(L_CS7_NODE, &no_cs7_asp_cmd);
	install_lib_element(L_CS7_ASP_NODE, &cfg_description_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_remote_ip_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_no_remote_ip_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_local_ip_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_no_local_ip_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_qos_class_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_role_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_transport_role_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_sctp_role_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_sctp_param_init_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_no_sctp_param_init_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_quirk_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_no_quirk_cmd);
	gen_asp_timer_cmd_strs(&asp_timer_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_timer_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_block_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_shutdown_cmd);
	install_lib_element(L_CS7_ASP_NODE, &asp_no_shutdown_cmd);
}
