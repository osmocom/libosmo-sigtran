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

#include "ss7_asp.h"
#include "ss7_xua_srv.h"
#include "ss7_qos_class.h"

/***********************************************************************
 * SS7 QoS Class
 ***********************************************************************/

/*! \brief Find QoS Class
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] qos_class Id of QoS class
 *  \returns pointer to a QoS class instance on success; NULL otherwise */
struct ss7_qos_class *
ss7_qos_class_find(struct osmo_ss7_instance *inst, uint8_t qos_class)
{
	struct ss7_qos_class *qos;

	llist_for_each_entry(qos, &inst->qos_class_list, list) {
		if (qos->qos_class == qos_class)
			return qos;
	}

	return NULL;
}

/*! \brief Create QoS Class
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] qos_class Id of QoS class
 *  \param[in] ip_dscp IP DSCP
 *  \returns pointer to a QoS class instance on success; NULL otherwise */
struct ss7_qos_class *
ss7_qos_class_create(struct osmo_ss7_instance *inst, uint8_t qos_class, uint8_t ip_dscp)
{
	struct ss7_qos_class *qos;

	qos = talloc_zero(inst, struct ss7_qos_class);
	if (!qos)
		return NULL;
	qos->inst = inst;
	qos->qos_class = qos_class;
	qos->ip_dscp = ip_dscp;
	llist_add_tail(&qos->list, &inst->qos_class_list);

	return qos;
}

/*! \brief Delete QoS Class
 *  \param[in] QoS class instance to delete */
void ss7_qos_class_destroy(struct ss7_qos_class *qos)
{
	struct osmo_ss7_instance *inst = qos->inst;
	struct osmo_ss7_asp *asp;
	struct osmo_xua_server *xua;

	/* Remove bindings, if any. */
	llist_for_each_entry(asp, &inst->asp_list, list) {
		if (asp->cfg.qos == qos) {
			asp->cfg.qos = NULL;
			ss7_asp_apply_qos_class(asp);
		}
	}
	llist_for_each_entry(xua, &inst->xua_servers, list) {
		if (xua->cfg.qos == qos) {
			xua->cfg.qos = NULL;
			ss7_xua_server_set_ip_dscp(xua);
		}
	}
	llist_del(&qos->list);
	talloc_free(qos);
}

/*! \brief Find or Create QoS Class
 *  \param[in] inst SS7 Instance on which we operate
 *  \param[in] qos_class Id of QoS class
 *  \param[in] ip_dscp IP DSCP
 *  \returns pointer to a QoS class instance on success; NULL otherwise */
struct ss7_qos_class *
ss7_qos_class_find_or_create(struct osmo_ss7_instance *inst, uint8_t qos_class, uint8_t ip_dscp)
{
	struct ss7_qos_class *qos;

	qos = ss7_qos_class_find(inst, qos_class);
	if (!qos)
		qos = ss7_qos_class_create(inst, qos_class, ip_dscp);

	return qos;
}

/*! \brief Update sockets of all ASPs and xUA Servers that use this QoS class
 *  \param[in] QoS class instance to update */
void ss7_qos_class_update(struct ss7_qos_class *qos)
{
	struct osmo_ss7_instance *inst = qos->inst;
	struct osmo_ss7_asp *asp;
	struct osmo_xua_server *xua;

	llist_for_each_entry(asp, &inst->asp_list, list) {
		if (asp->cfg.qos == qos)
			ss7_asp_apply_qos_class(asp);
	}
	llist_for_each_entry(xua, &inst->xua_servers, list) {
		if (xua->cfg.qos == qos)
			ss7_xua_server_set_ip_dscp(xua);
	}
}

