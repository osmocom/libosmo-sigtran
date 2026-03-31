/* M3UA/SUA <-> XUA Layer Manager SAP, RFC466 1.6.3 & RFC3868 1.6.3 */
#pragma once

#include <unistd.h>
#include <stdint.h>

#include <osmocom/core/tdef.h>
#include <osmocom/sigtran/osmo_ss7.h>
#include <osmocom/sigtran/sigtran_sap.h>

struct osmo_xlm_prim *xua_xlm_prim_alloc(enum osmo_xlm_prim_type prim_type,
					 enum osmo_prim_operation op);
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_rk_reg_req(const struct osmo_ss7_routing_key *rkey,
						      enum osmo_ss7_as_traffic_mode mode);
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_rk_reg_cfm(const struct osmo_ss7_routing_key *rkey,
						      uint32_t status);
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_rk_dereg_cfm(uint32_t route_ctx, uint32_t status);
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_error_ind(uint32_t err_code);
struct osmo_xlm_prim *xua_xlm_prim_alloc_m_notify_ind(const struct osmo_xlm_prim_notify *ntfy);

void xua_asp_send_xlm_prim(struct osmo_ss7_asp *asp, struct osmo_xlm_prim *prim);
void xua_asp_send_xlm_prim_simple(struct osmo_ss7_asp *asp,
				  enum osmo_xlm_prim_type prim_type,
				  enum osmo_prim_operation op);

int xlm_sap_down_simple(struct osmo_ss7_asp *asp,
			enum osmo_xlm_prim_type prim_type,
			enum osmo_prim_operation op);
