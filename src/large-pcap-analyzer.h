/*
 * large-pcap-analyzer.h
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
 * v3.4 = added modes (syn|3way|3way-data) to the -T option
 * v3.4.2 = added -C option
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

#ifndef LPA_H_
#define LPA_H_

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

#define KB								(1024)
#define MB								(1024*1024)
#define GB								(1024*1024*1024)
#define MILLION							(1000000)
#define SMALL_NUM						(0.000001)           // 1us
#define MAX_SNAPLEN						(65535)
#define VLAN_VID_MASK					(0x0FFF)
#define ETHERTYPE_IS_VLAN(x)			((x) == ETH_P_8021Q || (x) == 0x9100/*qinq*/ || (x) == 0x88A8 /*802.1 ad*/)
#define INVALID_FLOW_HASH				(0)

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

#define LIKELY(x)   __builtin_expect((x),1)
#define UNLIKELY(x) __builtin_expect((x),0)


// stuff coming from http://lxr.free-electrons.com/source/include/net/gtp.h

/* General GTP protocol related definitions. */
#define GTP1U_PORT      2152
#define GTP_TPDU        255
#define GTP1_F_NPDU     0x01
#define GTP1_F_SEQ      0x02
#define GTP1_F_EXTHDR   0x04
#define GTP1_F_MASK     0x07


//------------------------------------------------------------------------------
// Time macros
//------------------------------------------------------------------------------

#define SEC_TO_NSEC(x)			(x*(1E9))
#define SEC_TO_USEC(x)			(x*(1E6))

#define NSEC_TO_SEC(x)			(x/(1E9))
#define NSEC_TO_USEC(x)			(x/(1E6))

#define USEC_TO_SEC(x)			(x/(1E6))


//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------


// VLAN frame definition:

typedef struct
{
	uint16_t vlanId;			// in NETWORK order
	uint16_t protoType;
} __attribute__((packed)) ether80211q_t;


// GTPv1 frame definition:
// stuff coming from http://lxr.free-electrons.com/source/include/net/gtp.h

struct gtp1_header {    /* According to 3GPP TS 29.060. */
	__u8    flags;
	__u8    type;
	__be16  length;
	__be32  tid;
} __attribute__ ((packed));

class Packet
{
public:
	Packet(struct pcap_pkthdr* hdr = NULL, const u_char* data = NULL)
		{ m_pcap_header=hdr; m_pcap_packet=data; m_pcaplib_owns_data=true; }

	~Packet() { destroy(); }

	void destroy()
	{
		if (m_pcaplib_owns_data)
		{
			// libpcap owns this packet, just reset pointers and leave
			// memory deallocation to libpcap
			m_pcap_header = NULL;
			m_pcap_packet = NULL;
		}
		else
		{
			if (m_pcap_header)
				free(m_pcap_header);

			if (m_pcap_packet)
				free(const_cast<u_char*>(m_pcap_packet));

			m_pcap_header = NULL;
			m_pcap_packet = NULL;
		}
	}

	void copy(const struct pcap_pkthdr* hdr, const u_char* data)
	{
		destroy();		// just in case

		m_pcaplib_owns_data = false;
		m_pcap_header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr)+1);
		m_pcap_packet = (u_char*)malloc(hdr->caplen+1);

		memcpy(m_pcap_header, hdr, sizeof(struct pcap_pkthdr));
		memcpy(const_cast<u_char*>(m_pcap_packet), data, hdr->caplen);
	}

	size_t len() const				{ if (m_pcap_header) return m_pcap_header->caplen; else return 0; }

	const struct pcap_pkthdr* header() const		{ return m_pcap_header; }
	const u_char* data() const						{ return m_pcap_packet; }

	static double pcap_timestamp_to_seconds(struct timeval* ts)
	{
		return (double)ts->tv_sec +
							USEC_TO_SEC((double)ts->tv_usec);
	}
	static double pcap_timestamp_to_seconds(struct pcap_pkthdr* pcap_header)
	{
		return pcap_timestamp_to_seconds(&pcap_header->ts);
	}
	double pcap_timestamp_to_seconds() const
	{
		return pcap_timestamp_to_seconds(&m_pcap_header->ts);
	}

	void set_timestamp_from_seconds(double ts)
	{
		m_pcap_header->ts.tv_sec = (time_t)ts;
		m_pcap_header->ts.tv_usec = SEC_TO_USEC(ts) - SEC_TO_USEC(m_pcap_header->ts.tv_sec);

	}

private:
	struct pcap_pkthdr*			m_pcap_header;
	const u_char*				m_pcap_packet;
	bool						m_pcaplib_owns_data;
};


//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

extern void printf_verbose(const char *fmtstr, ...);
extern void printf_error(const char *fmtstr, ...);

#endif
