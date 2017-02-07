/*
 * filter.c
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 * Created: Nov 2014
 * Last Modified: Jan 2017
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

#include "large-pcap-analyzer.h"



//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

GtpuParserRetCode get_gtpu_inner_frame_offset(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetOut)
{
	unsigned int offset = 0;
#ifdef DEBUG
	unsigned int offset_ethernet=0, offset_ipv4=0, offset_udp=0;
#endif


	// parse Ethernet layer

	if(pcap_header->len < sizeof(struct ether_header))
		return GPRC_TOO_SHORT_PKT; // Packet too short

	const struct ether_header* ehdr = (const struct ether_header*)pcap_packet;
	uint16_t eth_type = ntohs(ehdr->ether_type);
	offset = sizeof(struct ether_header);
#ifdef DEBUG
	offset_ethernet=offset;
#endif

	// parse VLAN tags

	while (ETHERTYPE_IS_VLAN(eth_type) && offset < pcap_header->len)
	{
		const Ether80211q* qType = (const Ether80211q*) (pcap_packet + offset);
		eth_type = ntohs(qType->protoType);
		offset += sizeof(Ether80211q);
	}

	if (eth_type != ETH_P_IP)
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet


	// parse IPv4 layer
	// NOTE: for the encapsulation, only IPv4 is supported; IPv6 is never used for encapsulation anyway!

	if (pcap_header->len < (offset + sizeof(struct ip)) )
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	const struct ip* ip = (const struct ip*) (pcap_packet + offset);
	if ( ip->ip_v != 4 )
		return GPRC_INVALID_PKT;		// wrong packet

	if(ip->ip_p != IPPROTO_UDP)
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet

	size_t hlen = (u_int) ip->ip_hl * 4;
	offset += hlen;
#ifdef DEBUG
	offset_ipv4=offset;
#endif


	// parse UDP layer

	if (pcap_header->len < (offset + sizeof(struct udphdr)) )
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	const struct udphdr* udp = (const struct udphdr*)(pcap_packet + offset);
	if (udp->source != htons(GTP1U_PORT) &&
			udp->dest != htons(GTP1U_PORT))
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet

	offset += sizeof(struct udphdr);
#ifdef DEBUG
	offset_udp=offset;
#endif


	// parse GTPu layer

	if (pcap_header->len < (offset + sizeof(struct gtp1_header)) )
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	const struct gtp1_header* gtpu = (const struct gtp1_header*)(pcap_packet + offset);

	//check for gtp-u message (type = 0xff) and is a gtp release 1
	if ((gtpu->flags & 0xf0) != 0x30)
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet
	if (gtpu->type != GTP_TPDU)
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet

	offset += sizeof(struct gtp1_header);
	const u_char* gtp_start = pcap_packet + offset;
	const u_char* gtp_payload = pcap_packet + offset;

	// check for sequence number field and NPDU field
	if ((gtpu->flags & (GTP1_F_NPDU | GTP1_F_SEQ)) != 0)
		offset += 4;

	// parse the extension bit
	if ((gtpu->flags & GTP1_F_EXTHDR) != 0)
	{
		// skip all extensions present
		uint16_t ext_type;
		do
		{
			uint16_t word = *((uint16_t*)gtp_payload);
			gtp_payload+=2;

			uint16_t ext_size = (word & 0xff00) >> 8;
			if (ext_size != 0)
			{
				uint16_t i;

				ext_size = (ext_size << 1) - 2;
				for (i = 0; i < ext_size; i++)
				{
					gtp_payload+=2;
				}

				uint16_t word = *((uint16_t*)gtp_payload);
				gtp_payload+=2;

				ext_type = (word & 0x00ff);
			}
			else
			{
				ext_type = 0;
			}
		} while (ext_type != 0);
	}

	offset += (gtp_payload - gtp_start);

	// check that a valid IPv4 layer is following

	if (pcap_header->len < (offset + sizeof(struct ip)) )
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	const struct ip* ipinner = (const struct ip*) (pcap_packet + offset);
	if ( ipinner->ip_v != 4 && ipinner->ip_v != 6 )
		return GPRC_INVALID_PKT;		// wrong packet or above GTPu there is no IP layer (it could be e.g., PPP or other)


	// ok, found the offset for a valid GTPu packet

	if (offsetOut)
		*offsetOut = offset;

	return GPRC_VALID_GTPU_PKT;
}

boolean apply_filter_on_inner_ipv4_frame(struct pcap_pkthdr* pcap_header, const u_char* pcap_packet,
		  	  	  	  	  	  	  	  unsigned int inner_ipv4_offset, unsigned int inner_ipv4_len, struct bpf_program* gtpu_filter)
{
	boolean tosave = FALSE;
	//memset(g_buffer, 0, sizeof(g_buffer));   // not actually needed

	// rebuild the ethernet frame, copying the original one possibly
	const struct ether_header* orig_ehdr = (struct ether_header*)pcap_packet;
	struct ether_header* fake_ehdr = (struct ether_header*)g_buffer;
	memcpy(fake_ehdr, orig_ehdr, sizeof(*orig_ehdr));
	fake_ehdr->ether_type = htons(ETH_P_IP);			// erase any layer (like VLAN) possibly present in orig packet

	// copy from IPv4 onward:
	const u_char* orig_inner = pcap_packet + inner_ipv4_offset;
	u_char* fake_ipv4 = g_buffer + sizeof(struct ether_header);
	memcpy(fake_ipv4, orig_inner, inner_ipv4_len);

	// create also a fake
	struct pcap_pkthdr fakehdr;
	memcpy(&fakehdr.ts, &pcap_header->ts, sizeof(pcap_header->ts));
	fakehdr.caplen = fakehdr.len = sizeof(struct ether_header) + inner_ipv4_len;

	// pcap_offline_filter returns
	// zero if the packet doesn't match the filter and non-zero
	// if the packet matches the filter.
	int ret = pcap_offline_filter(gtpu_filter, &fakehdr, g_buffer);
	if (ret != 0)
	{
		tosave = TRUE;
	}

	return tosave;
}


//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

boolean must_be_saved(struct pcap_pkthdr* pcap_header, const u_char* pcap_packet,
					  const char *search, struct bpf_program* gtpu_filter, boolean* is_gtpu)
{
	boolean tosave = FALSE;

	// string-search filter:

	if (search)
	{
		unsigned int len = MIN(pcap_header->len, MAX_PACKET_LEN);

		memcpy(g_buffer, pcap_packet, len);
		g_buffer[len] = '\0';

		if (!memmem(g_buffer, len, search, strlen(search)))
			tosave |= TRUE;
	}


	// GTPu filter:

	if (gtpu_filter)
	{
		// is this a GTPu packet?
		int offset;
		GtpuParserRetCode errcode = get_gtpu_inner_frame_offset(pcap_header, pcap_packet, &offset);
		if (is_gtpu && errcode == GPRC_VALID_GTPU_PKT)
			*is_gtpu = TRUE;

		int len = pcap_header->len - offset;
		if (offset > 0 && len > 0)
		{
			tosave |= apply_filter_on_inner_ipv4_frame(pcap_header, pcap_packet, offset, len, gtpu_filter);
		}
	}


	return tosave;
}
