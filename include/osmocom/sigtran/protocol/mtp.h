#pragma once

#include <osmocom/core/utils.h>

/* Chapter 15.17.4 of Q.704 + RFC4666 3.4.5. */
/* Section 5.1 of ETSI EG 201 693: MTP SI code allocations (for NI= 00) */
enum mtp_si_ni00 {
	MTP_SI_SNM	= 0,
	MTP_SI_STM	= 1,
	MTP_SI_SCCP	= 3,
	MTP_SI_TUP	= 4,
	MTP_SI_ISUP	= 5,
	MTP_SI_DUP	= 6, /* call related */
	MTP_SI_DUP_FAC	= 7, /* facility related */
	MTP_SI_TESTING	= 8,
	MTP_SI_B_ISUP	= 9,
	MTP_SI_SAT_ISUP = 10,
	MTP_SI_SPEECH	= 11, /* speech processing element */
	MTP_SI_AAL2_SIG	= 12,
	MTP_SI_BICC	= 13,
	MTP_SI_GCP	= 14,
};

extern const struct value_string mtp_si_vals[];


/* Chapter 15.17.5 of Q.704 */
enum mtp_unavail_cause {
	MTP_UNAVAIL_C_UNKNOWN		= 0x0,
	MTP_UNAVAIL_C_UNEQUIP_REM_USER	= 0x1,
	MTP_UNAVAIL_C_INACC_REM_USER	= 0x2,
	/* This field is not explicitly listed in Q.704 15.17.5, but it is
	 * expicitly described as one of four options in:
	 * Q.701 "TABLE 1" and 8.4
	 * Q.704 2.4.2
	 * Q.711 "Table 18" and 7.2.4
	 * Q.714 "Figure D.4"
	 */
	MTP_UNAVAIL_C_CONGESTED		= 0x3,
	/* reserved */
};

extern const struct value_string mtp_unavail_cause_vals[];

static inline const char *mtp_unavail_cause_str(enum mtp_unavail_cause cs) {
	return get_value_string(mtp_unavail_cause_vals, cs);
}
