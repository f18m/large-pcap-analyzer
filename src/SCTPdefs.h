//---------------------------------------------------------------------------
// SCTPDefs.h : Declares basic SCTP protocol structures
// (C) Copyright 2014 Empirix Inc.
//
//  Created on: Nov, 2014
//      Author: fmontorsi
//
// Description:
//  linux/sctp.h header is not always available, so we roll our own with the
//  basic SCTP protocol definitions
//
//  Reference: https://en.wikipedia.org/wiki/SCTP_packet_structure
//             https://tools.ietf.org/html/rfc3309
//
//---------------------------------------------------------------------------

#ifndef SCTP_DEFS_H_
#define SCTP_DEFS_H_

#include <stdint.h>

#define SCTP_CRC_OFFSET 8
#define SCTP_CRC_FIELD_LENGTH 4
#define SCTP_CHUNK_OFFSET 12

#define SCTP_ERROR_CHUNK_MIN_PARAM_SIZE 4

/*
 * Header repeated only once just after IP frame
 */
typedef struct sctphdr {
    uint16_t source;
    uint16_t dest;
    uint32_t vtag;
    uint32_t checksum;
} __attribute__((packed)) sctp_sctphdr_t; // 12B

/*
 * Header preceding every single SCTP chunks
 */
typedef struct sctp_chunkhdr {
    uint8_t type; // one of sctp_cid_t
    uint8_t flags;
    uint16_t length; // IMPORTANT: specifies total length of the chunk in bytes (excludes any padding): chunk type, flags, length, and value fields.
} __attribute__((packed)) sctp_chunkhdr_t; // 4B

/* Section 3.2.  Chunk Type Values.
 * [Chunk Type] identifies the type of information contained in the Chunk
 * Value field. It takes a value from 0 to 254. The value of 255 is
 * reserved for future use as an extension field.
 */
typedef enum {
    SCTP_CID_DATA = 0,
    SCTP_CID_INIT = 1,
    SCTP_CID_INIT_ACK = 2,
    SCTP_CID_SACK = 3,
    SCTP_CID_HEARTBEAT = 4,
    SCTP_CID_HEARTBEAT_ACK = 5,
    SCTP_CID_ABORT = 6,
    SCTP_CID_SHUTDOWN = 7,
    SCTP_CID_SHUTDOWN_ACK = 8,
    SCTP_CID_ERROR = 9,
    SCTP_CID_COOKIE_ECHO = 10,
    SCTP_CID_COOKIE_ACK = 11,
    SCTP_CID_ECN_ECNE = 12,
    SCTP_CID_ECN_CWR = 13,
    SCTP_CID_SHUTDOWN_COMPLETE = 14,

    /* recent addition, see https://tools.ietf.org/html/rfc8260 */
    SCTP_CID_IDATA = 64,

    /* PR-SCTP Sec 3.2 */
    SCTP_CID_FWD_TSN = 0xC0,

    /* Use hex, as defined in ADDIP sec. 3.1 */
    SCTP_CID_ASCONF = 0xC1,
    SCTP_CID_ASCONF_ACK = 0x80,
} sctp_cid_t; /* enum */

typedef enum {
    SCTP_ERRID_INVALID_STREAM_IDENTIFIER = 1,
    SCTP_ERRID_MISSING_MANDATORY_PARAMETER = 2,
    SCTP_ERRID_STALE_COOKIE_ERROR = 3,
    SCTP_ERRID_OUT_OF_RESOURCES = 4,
    SCTP_ERRID_UNRESOLVABLE_ADDRESS = 5,
    SCTP_ERRID_UNRECOGNIZED_CHUNK_TYPE = 6,
    SCTP_ERRID_INVALID_MANDATORY_PARAMETER = 7,
    SCTP_ERRID_UNRECOGNIZED_PARAMETERS = 8,
    SCTP_ERRID_NO_USER_DATA = 9,
    SCTP_ERRID_COOKIE_RECEIVED_SHUTTING_DOWN = 10,
    SCTP_ERRID_RESTART_ASSOCIATION_NEW_ADDRESSES = 11,
    SCTP_ERRID_USER_INITIATED_ABORT = 12,
    SCTP_ERRID_PROTOCOL_VIOLATION = 13,

    SCTP_ERRID_MAX
} sctp_errorid_t; /* enum */

// if sctp_chunkhdr_t.type == SCTP_CID_DATA, this header follows:
typedef struct sctp_datahdr {
    uint32_t tsn;
    uint16_t stream;
    uint16_t ssn;
    uint32_t ppid; // one of sctp_ppid_t
    uint8_t payload[0];
} __attribute__((packed)) sctp_datahdr_t; // 12B

/* Section 3.3.1 Payload Data
 * Payload Protocol Identifier: 32 bits (unsigned integer):
 * This value represents an application (or upper layer) specified protocol
 * identifier.  This value is passed to SCTP by its upper layer and sent to its
 * peer.  This identifier is not used by SCTP but can be used by certain
 * network entities, as well as by the peer application, to identify the type
 * of information being carried in this DATA chunk.
 *
 * Updated list at:
 *    https://www.iana.org/assignments/sctp-parameters/sctp-parameters.xhtml#sctp-parameters-25
 * we only list what we actually care about:
 */

typedef enum {
    SCTP_PPID_IUA = 1,
    SCTP_PPID_M2UA = 2,
    SCTP_PPID_M3UA = 3,
    SCTP_PPID_SUA = 4,
    SCTP_PPID_M2PA = 5,
    SCTP_PPID_H248 = 7,
    SCTP_PPID_BICC = 8,
    SCTP_PPID_S1AP = 18,
    SCTP_PPID_SBCAP = 24,
    SCTP_PPID_NBAP = 25,
    SCTP_PPID_X2AP = 27,
    SCTP_PPID_DIAMETER = 46,
    SCTP_PPID_NGAP = 60,

    SCTP_PPID_MAX
} sctp_ppid_t; /* enum */

#endif /* SCTP_DEFS_H_ */
