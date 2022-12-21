/*
 * packet.h
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
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

#ifndef LPA_PACKET_H_
#define LPA_PACKET_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#ifndef _GNU_SOURCE
#define _GNU_SOURCE // to have memmem
#endif

#include <linux/types.h>
#include <stdlib.h>
#include <string.h>

// libpcap dependency:
// NOTE: in version 1.7.x there is no pcap/pcap.h, just a pcap.h apparently:
//#include <pcap/pcap.h>
#include <pcap.h>

#include "config.h"

//------------------------------------------------------------------------------
// Protocol Constants
//------------------------------------------------------------------------------

#define VLAN_VID_MASK (0x0FFF)
#define ETHERTYPE_IS_VLAN(x) \
    ((x) == ETH_P_8021Q || (x) == 0x9100 /*qinq*/ || (x) == 0x88A8 /*802.1 ad*/)

// stuff coming from http://lxr.free-electrons.com/source/include/net/gtp.h

/* General GTP protocol related definitions. */
#define GTP1U_PORT 2152
#define GTP_TPDU 255
#define GTP1_F_NPDU 0x01
#define GTP1_F_SEQ 0x02
#define GTP1_F_EXTHDR 0x04
#define GTP1_F_MASK 0x07

// VLAN frame definition:

typedef struct {
    uint16_t vlanId; // in NETWORK order
    uint16_t protoType;
} __attribute__((packed)) ether80211q_t;

// GTPv1 frame definition:
// stuff coming from http://lxr.free-electrons.com/source/include/net/gtp.h

struct gtp1_header { /* According to 3GPP TS 29.060. */
    __u8 flags;
    __u8 type;
    __be16 length;
    __be32 tid;
} __attribute__((packed));

//------------------------------------------------------------------------------
// Packet
//------------------------------------------------------------------------------

class Packet {
public:
    Packet(struct pcap_pkthdr* hdr = NULL, const u_char* data = NULL)
    {
        m_pcap_header = hdr;
        m_pcap_packet = data;
        m_pcaplib_owns_data = true;
    }

    ~Packet() { destroy(); }

    void destroy()
    {
        if (m_pcaplib_owns_data) {
            // libpcap owns this packet, just reset pointers and leave
            // memory deallocation to libpcap
            m_pcap_header = NULL;
            m_pcap_packet = NULL;
        } else {
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
        destroy(); // just in case

        m_pcaplib_owns_data = false;
        m_pcap_header = (struct pcap_pkthdr*)malloc(sizeof(struct pcap_pkthdr) + 1);
        m_pcap_packet = (u_char*)malloc(hdr->caplen + 1);

        memcpy(m_pcap_header, hdr, sizeof(struct pcap_pkthdr));
        memcpy(const_cast<u_char*>(m_pcap_packet), data, hdr->caplen);
    }

    size_t len() const
    {
        if (m_pcap_header)
            return m_pcap_header->caplen;
        else
            return 0;
    }

    const struct pcap_pkthdr* header() const { return m_pcap_header; }
    const u_char* data() const { return m_pcap_packet; }

    static double pcap_timestamp_to_seconds(struct timeval* ts)
    {
        // for some reason the 'struct timeval' is using SIGNED integers, at least on Linux x86_64:
        if (ts->tv_sec < 0 || ts->tv_usec < 0)
            return 0;

        return (double)ts->tv_sec + USEC_TO_SEC((double)ts->tv_usec);
    }
    static double pcap_timestamp_to_seconds(struct pcap_pkthdr* pcap_header)
    {
        return pcap_timestamp_to_seconds(&pcap_header->ts);
    }
    static bool pcap_timestamp_is_valid(struct pcap_pkthdr* pcap_header)
    {
        return pcap_header->ts.tv_sec + pcap_header->ts.tv_usec > 0;
    }

    double pcap_timestamp_to_seconds() const
    {
        return pcap_timestamp_to_seconds(&m_pcap_header->ts);
    }

    void set_timestamp_from_seconds(double ts)
    {
        m_pcap_header->ts.tv_sec = (time_t)ts;
        m_pcap_header->ts.tv_usec = SEC_TO_USEC(ts) - SEC_TO_USEC(m_pcap_header->ts.tv_sec);

        /*
        Beware: ts_usec value shouldn't reach 1 second (in regular pcap files 1 000 000; in nanosecond-resolution files, 1 000 000 000); 
                in this case ts_sec must be increased instead!
        See https://wiki.wireshark.org/Development/LibpcapFileFormat

        Also note that large_pcap_analyzer is using libpcap to write PCAP files and libpcap provides no way to produce
        a nanosecond-resolution file... so we always store MICROSECONDs inside the timeval "ts":
        */
        while (m_pcap_header->ts.tv_usec > 1000000) {
            m_pcap_header->ts.tv_sec++;
            m_pcap_header->ts.tv_usec -= 1000000;
        }
    }

private:
    struct pcap_pkthdr* m_pcap_header;
    const u_char* m_pcap_packet;
    bool m_pcaplib_owns_data;
};

#endif // LPA_PACKET_H_
