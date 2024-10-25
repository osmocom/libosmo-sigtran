#include <osmocom/sccp/sccp_types.h>

/* Table 1/Q.713 - SCCP message types */
const struct value_string osmo_sccp_msg_type_names[] = {
	{ SCCP_MSG_TYPE_CR, "Connection request" },
	{ SCCP_MSG_TYPE_CC, "Connection confirm" },
	{ SCCP_MSG_TYPE_CREF, "Connection refused" },
	{ SCCP_MSG_TYPE_RLSD, "Released" },
	{ SCCP_MSG_TYPE_RLC, "Release complete" },
	{ SCCP_MSG_TYPE_DT1, "Data form 1" },
	{ SCCP_MSG_TYPE_DT2, "Data form 2" },
	{ SCCP_MSG_TYPE_AK, "Data acknowledgement" },
	{ SCCP_MSG_TYPE_UDT, "Unitdata" },
	{ SCCP_MSG_TYPE_UDTS, "Unitdata service" },
	{ SCCP_MSG_TYPE_ED, "Expedited data" },
	{ SCCP_MSG_TYPE_EA, "Expedited data acknowledgement" },
	{ SCCP_MSG_TYPE_RSR, "Reset request" },
	{ SCCP_MSG_TYPE_RSC, "Reset confirmation" },
	{ SCCP_MSG_TYPE_ERR, "Protocol data unit error" },
	{ SCCP_MSG_TYPE_IT, "Inactivity test" },
	{ SCCP_MSG_TYPE_XUDT, "Extended unitdata" },
	{ SCCP_MSG_TYPE_XUDTS, "Extended unitdata service" },
	{ SCCP_MSG_TYPE_LUDT, "Long unitdata" },
	{ SCCP_MSG_TYPE_LUDTS, "Long unitdata service" },
	{}
};

/* Table 2/Q.713 - SCCP parameter name codes */
const struct value_string osmo_sccp_pnc_names[] = {
	{ SCCP_PNC_END_OF_OPTIONAL, "End of optional parameters" },
	{ SCCP_PNC_DESTINATION_LOCAL_REFERENCE, "Destination local reference" },
	{ SCCP_PNC_SOURCE_LOCAL_REFERENCE, "Source local reference" },
	{ SCCP_PNC_CALLED_PARTY_ADDRESS, "Called party address" },
	{ SCCP_PNC_CALLING_PARTY_ADDRESS, "Calling party address" },
	{ SCCP_PNC_PROTOCOL_CLASS, "Protocol class" },
	{ SCCP_PNC_SEGMENTING, "Segmenting/reassembling" },
	{ SCCP_PNC_RECEIVE_SEQ_NUMBER, "Receive sequence number" },
	{ SCCP_PNC_SEQUENCING, "Sequencing/segmenting" },
	{ SCCP_PNC_CREDIT, "Credit" },
	{ SCCP_PNC_RELEASE_CAUSE, "Release cause" },
	{ SCCP_PNC_RETURN_CAUSE, "Return cause" },
	{ SCCP_PNC_RESET_CAUSE, "Reset cause" },
	{ SCCP_PNC_ERROR_CAUSE, "Error cause" },
	{ SCCP_PNC_REFUSAL_CAUSE, "Refusal cause" },
	{ SCCP_PNC_DATA, "Data" },
	{ SCCP_PNC_SEGMENTATION, "Segmentation" },
	{ SCCP_PNC_HOP_COUNTER, "Hop counter" },
	{ SCCP_PNC_IMPORTANCE, "Importance" },
	{ SCCP_PNC_LONG_DATA, "Long data" },
	{}
};

/* ITU-T Q.713, Section 3.11 Release cause */
const struct value_string osmo_sccp_release_cause_names[] = {
	{ SCCP_RELEASE_CAUSE_END_USER_ORIGINATED, "end user originated" },
	{ SCCP_RELEASE_CAUSE_END_USER_CONGESTION, "end user congestion" },
	{ SCCP_RELEASE_CAUSE_END_USER_FAILURE, "end user failure" },
	{ SCCP_RELEASE_CAUSE_SCCP_USER_ORIGINATED, "SCCP user originated" },
	{ SCCP_RELEASE_CAUSE_REMOTE_PROCEDURE_ERROR, "remote procedure error" },
	{ SCCP_RELEASE_CAUSE_INCONSISTENT_CONN_DATA, "inconsistent connection data" },
	{ SCCP_RELEASE_CAUSE_ACCESS_FAILURE, "access failure" },
	{ SCCP_RELEASE_CAUSE_ACCESS_CONGESTION, "access congestion" },
	{ SCCP_RELEASE_CAUSE_SUBSYSTEM_FAILURE, "subsystem failure" },
	{ SCCP_RELEASE_CAUSE_SUBSYSTEM_CONGESTION, "subsystem congestion" },
	{ SCCP_RELEASE_CAUSE_MTP_FAILURE, "MTP failure" },
	{ SCCP_RELEASE_CAUSE_NETWORK_CONGESTION, "network congestion" },
	{ SCCP_RELEASE_CAUSE_EXPIRATION_RESET, "expiration of reset timer" },
	{ SCCP_RELEASE_CAUSE_EXPIRATION_INACTIVE, "expiration of receive inactivity timer" },
	{ SCCP_RELEASE_CAUSE_RESERVED, "reserved" },
	{ SCCP_RELEASE_CAUSE_UNQUALIFIED, "unqualified" },
	{ SCCP_RELEASE_CAUSE_SCCP_FAILURE, "SCCP failure" },
	{}
};

/* ITU-T Q.713, Section 3.12 Return cause */
const struct value_string osmo_sccp_return_cause_names[] = {
	{ SCCP_RETURN_CAUSE_NO_TRANSLATION_NATURE, "no translation for an address of such nature" },
	{ SCCP_RETURN_CAUSE_NO_TRANSLATION, "no translation for this specific address" },
	{ SCCP_RETURN_CAUSE_SUBSYSTEM_CONGESTION, "subsystem congestion" },
	{ SCCP_RETURN_CAUSE_SUBSYSTEM_FAILURE, "subsystem failure" },
	{ SCCP_RETURN_CAUSE_UNEQUIPPED_USER, "unequipped user" },
	{ SCCP_RETURN_CAUSE_MTP_FAILURE, "MTP failure" },
	{ SCCP_RETURN_CAUSE_NETWORK_CONGESTION, "network congestion" },
	{ SCCP_RETURN_CAUSE_UNQUALIFIED, "unqualified" },
	{ SCCP_RETURN_CAUSE_ERROR_IN_MSG_TRANSPORT, "error in message transport" },
	{ SCCP_RETURN_CAUSE_ERROR_IN_LOCAL_PROCESSING, "error in local processing" },
	{ SCCP_RETURN_CAUSE_DEST_CANNOT_PERFORM_REASSEMBLY, "destination cannot perform reassembly" },
	{ SCCP_RETURN_CAUSE_SCCP_FAILURE, "SCCP failure" },
	{ SCCP_RETURN_CAUSE_HOP_COUNTER_VIOLATION, "hop counter violation" },
	{ SCCP_RETURN_CAUSE_SEGMENTATION_NOT_SUPPORTED, "segmentation not supported" },
	{ SCCP_RETURN_CAUSE_SEGMENTATION_FAILURE, "segmentation failure" },
	{}
};

/* ITU-T Q.713, Section 3.13 Reset cause */
const struct value_string osmo_sccp_reset_cause_names[] = {
	{ SCCP_RESET_CAUSE_END_USER_ORIGINATED, "end user originated" },
	{ SCCP_RESET_CAUSE_SCCP_USER_ORIGINATED, "SCCP user originated" },
	{ SCCP_RESET_CAUSE_MSG_OUT_OF_ORDER_PS, "message out of order - incorrect P(S)" },
	{ SCCP_RESET_CAUSE_MSG_OUT_OF_ORDER_PR, "message out of order - incorrect P(R)" },
	{ SCCP_RESET_CAUSE_RPC_OUT_OF_WINDOW, "remote procedure error - message out of window" },
	{ SCCP_RESET_CAUSE_RPC_INCORRECT_PS, "remote procedure error - incorrect P(S) after (re)initialization" },
	{ SCCP_RESET_CAUSE_RPC_GENERAL, "remote procedure error - general" },
	{ SCCP_RESET_CAUSE_REMOTE_END_USER_OPERATIONAL, "remote end user operational" },
	{ SCCP_RESET_CAUSE_NETWORK_OPERATIONAL, "network operational" },
	{ SCCP_RESET_CAUSE_ACCESS_OPERATIONAL, "access operational" },
	{ SCCP_RESET_CAUSE_NETWORK_CONGESTION, "network congestion" },
	{ SCCP_RESET_CAUSE_RESERVED, "reserved" },
	{ SCCP_RESET_CAUSE_UNQUALIFIED, "unqualified"},
	{}
};

/* ITU-T Q.713, Section 3.14 Error cause */
const struct value_string osmo_sccp_error_cause_names[] = {
	{ SCCP_ERROR_LRN_MISMATCH_UNASSIGNED, "local reference number (LRN) mismatch - unassigned destination LRN" },
	{ SCCP_ERROR_LRN_MISMATCH_INCONSISTENT, "local reference number (LRN) mismatch - inconsistent source LRN" },
	{ SCCP_ERROR_POINT_CODE_MISMATCH, "point code mismatch" },
	{ SCCP_ERROR_SERVICE_CLASS_MISMATCH, "service class mismatch" },
	{ SCCP_ERROR_UNQUALIFIED, "unqualified" },
	{}
};

/* ITU-T Q.713 Section 3.15 Refusal cause */
const struct value_string osmo_sccp_refusal_cause_names[] = {
	{ SCCP_REFUSAL_END_USER_ORIGINATED, "end user originated" },
	{ SCCP_REFUSAL_END_USER_CONGESTION, "end user congestion" },
	{ SCCP_REFUSAL_END_USER_FAILURE, "end user failure" },
	{ SCCP_REFUSAL_SCCP_USER_ORIGINATED, "SCCP user originated" },
	{ SCCP_REFUSAL_DESTINATION_ADDRESS_UKNOWN, "destination address unknown" },
	{ SCCP_REFUSAL_DESTINATION_INACCESSIBLE, "destination inaccessible" },
	{ SCCP_REFUSAL_NET_QOS_NON_TRANSIENT, "network resource - QoS not available/non-transient" },
	{ SCCP_REFUSAL_NET_QOS_TRANSIENT, "network resource - QoS not available/transient" },
	{ SCCP_REFUSAL_ACCESS_FAILURE, "access failure" },
	{ SCCP_REFUSAL_ACCESS_CONGESTION, "access congestion" },
	{ SCCP_REFUSAL_SUBSYSTEM_FAILURE, "subsystem failure" },
	{ SCCP_REFUSAL_SUBSYTEM_CONGESTION, "subsystem congestion" },
	{ SCCP_REFUSAL_EXPIRATION, "expiration of the connection establishment timer" },
	{ SCCP_REFUSAL_INCOMPATIBLE_USER_DATA, "incompatible user data" },
	{ SCCP_REFUSAL_RESERVED, "reserved" },
	{ SCCP_REFUSAL_UNQUALIFIED, "unqualified" },
	{ SCCP_REFUSAL_HOP_COUNTER_VIOLATION, "hop counter violation" },
	{ SCCP_REFUSAL_SCCP_FAILURE, "SCCP failure" },
	{ SCCP_REFUSAL_NO_TRANS_FOR_ADDRESS_NATURE, "no translation for an address of such nature" },
	{ SCCP_REFUSAL_UNEQUIPPED_USER, "unequipped user" },
	{}
};
