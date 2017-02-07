#ifndef LPA_H_
#define LPA_H_

/*
 * large-pcap-analyzer
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 * Created: Nov 2014
 * Last Modified: Jan 2017
 *
 * History:
 *
 * v3.1 = first version released in Github
 * v3.2 = reworked command-line arguments to match those of "tshark" command line utility;
 *        added support for GTPu-filtering (-G option)
 * v3.3 = added filtering for valid GTPu-encapsulated TCP connections (-T option)
 *
 *
 * LICENSE:
	 This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
	MA 02110-1301, USA.

 */


//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#ifndef _GNU_SOURCE
#define _GNU_SOURCE         // to have memmem
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdarg.h>
#include <linux/types.h>

// libpcap dependency:
// NOTE: in version 1.7.x there is no pcap/pcap.h, just a pcap.h apparently:
//#include <pcap/pcap.h>
#include <pcap.h>

#include "config.h"
#include <map>


//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

#define MAX_PACKET_LEN      4096
#define KB                  1024
#define MB                  (1024*1024)
#define GB                  (1024*1024*1024)
#define MILLION             (1000000)
#define SMALL_NUM           (0.000001)           // 1us
#define MAX_SNAPLEN         (65535)

#define ETHERTYPE_IS_VLAN(x)			((x) == ETH_P_8021Q || (x) == 0x9100/*qinq*/ || (x) == 0x88A8 /*802.1 ad*/)
#define VLAN_VID_MASK					(0x0FFF)


#if !defined(PCAP_NETMASK_UNKNOWN)
    /*
     * Value to pass to pcap_compile() as the netmask if you don't know what
     * the netmask is.
     */
    #define PCAP_NETMASK_UNKNOWN    0xffffffff
#endif

#ifndef MIN
    #define MIN(x,y) ((x)>(y)?(y):(x))
#endif  /*MIN*/


// stuff coming from http://lxr.free-electrons.com/source/include/net/gtp.h

/* General GTP protocol related definitions. */
#define GTP1U_PORT      2152
#define GTP_TPDU        255
#define GTP1_F_NPDU     0x01
#define GTP1_F_SEQ      0x02
#define GTP1_F_EXTHDR   0x04
#define GTP1_F_MASK     0x07


//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

typedef int        boolean;
typedef uint64_t   flow_hash_t;

#ifndef TRUE
    #define TRUE        1
#endif

#ifndef FALSE
    #define FALSE       0
#endif

typedef enum
{
	GPRC_VALID_PKT = 0,

	GPRC_NOT_GTPU_PKT = -1,
	GPRC_TOO_SHORT_PKT = -2,
	GPRC_INVALID_PKT = -3,
} ParserRetCode_t;

typedef enum
{
	FLOW_FOUND_SYN,
	FLOW_FOUND_SYN_AND_SYNACK,
} FlowStatus_t;

typedef std::map<flow_hash_t /* key */, FlowStatus_t /* value */>     flow_map_t;

typedef struct
{
	uint16_t vlanId;			// in NETWORK order
	uint16_t protoType;
} __attribute__((packed)) ether80211q_t;

class filter_criteria_t
{
public:
	filter_criteria_t()
	{
	    memset(&capture_filter, 0, sizeof(capture_filter));
	    memset(&gtpu_filter, 0, sizeof(gtpu_filter));
	    capture_filter_set = FALSE;
	    gtpu_filter_set = FALSE;
	    valid_tcp_filter = FALSE;
	    string_filter = NULL;
	}


	struct bpf_program 			capture_filter;
	boolean 					capture_filter_set;

	struct bpf_program 			gtpu_filter;
	boolean 					gtpu_filter_set;

	const char* 				string_filter;

	boolean 					valid_tcp_filter;
	flow_map_t 					valid_tcp_firstpass_flows;			// contains the result of the 1st pass

} ;


// stuff coming from http://lxr.free-electrons.com/source/include/net/gtp.h

struct gtp1_header {    /* According to 3GPP TS 29.060. */
	__u8    flags;
	__u8    type;
	__be16  length;
	__be32  tid;
} __attribute__ ((packed));



//------------------------------------------------------------------------------
// Globals
//------------------------------------------------------------------------------

extern u_char g_buffer[MAX_SNAPLEN];
extern boolean g_verbose;


//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

extern void printf_verbose(const char *fmtstr, ...);

// filter routines:
extern boolean must_be_saved(struct pcap_pkthdr* pcap_header, const u_char* pcap_packet,
							const filter_criteria_t* filter, boolean* is_gtpu);

// parse routines:
extern ParserRetCode_t get_gtpu_inner_ip_offset(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetIpInner, int* ipver);
extern ParserRetCode_t get_gtpu_inner_transport_offset(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetTransportInner, int* ipprotInner);

extern flow_hash_t compute_flow_hash(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, bool is_gtpu);

#endif
