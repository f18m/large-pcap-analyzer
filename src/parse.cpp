/*
 * parse.cpp
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

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* superset of previous */
#include <linux/udp.h>
#include <linux/tcp.h>

#define IPV6_LEN			(16)


//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

#if !defined (hw_get16bits)
#define hw_get16bits(d) ((((uint32_t)(((const u_int8_t *)(d))[1])) << 8)\
                       +(uint32_t)(((const u_int8_t *)(d))[0]) )
#endif

static uint32_t hw_fasthash(const void *buf, size_t len, uint64_t offset)
{
	const char* data = (const char*)buf;
	uint32_t hash = len, tmp;
	int rem;

	rem = len & 3;
	len >>= 2;

	/* Main loop */
	for (;len > 0; len--) {
		hash  += hw_get16bits (data);
		tmp    = (hw_get16bits (data+2) << 11) ^ hash;
		hash   = (hash << 16) ^ tmp;
		data  += 2*sizeof (u_int16_t);
		hash  += hash >> 11;
	}

	/* Handle end cases */
	switch (rem) {
		case 3: hash += hw_get16bits (data);
				hash ^= hash << 16;
				hash ^= data[sizeof (u_int16_t)] << 18;
				hash += hash >> 11;
				break;
		case 2: hash += hw_get16bits (data);
				hash ^= hash << 11;
				hash += hash >> 17;
				break;
		case 1: hash += *data;
				hash ^= hash << 10;
				hash += hash >> 1;
				break;
	}

	/* Force "avalanching" of final 127 bits */
	hash ^= hash << 3;
	hash += hash >> 5;
	hash ^= hash << 4;
	hash += hash >> 17;
	hash ^= hash << 25;
	hash += hash >> 6;

	return hash+offset;
}

//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

ParserRetCode_t get_ip_offset(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetOut, int* ipver)
{
	unsigned int offset = 0;

	// parse Ethernet layer

	if(pcap_header->len < sizeof(struct ether_header))
		return GPRC_TOO_SHORT_PKT; // Packet too short

	const struct ether_header* ehdr = (const struct ether_header*)pcap_packet;
	uint16_t eth_type = ntohs(ehdr->ether_type);
	offset = sizeof(struct ether_header);

	// parse VLAN tags

	while (ETHERTYPE_IS_VLAN(eth_type) && offset < pcap_header->len)
	{
		const ether80211q_t* qType = (const ether80211q_t*) (pcap_packet + offset);
		eth_type = ntohs(qType->protoType);
		offset += sizeof(ether80211q_t);
	}

	if (eth_type != ETH_P_IP)
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet


	// parse IPv4/v6layer

	if (pcap_header->len < (offset + sizeof(struct ip)) )
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	const struct ip* ip = (const struct ip*) (pcap_packet + offset);
	if ( ip->ip_v != 4 && ip->ip_v != 6 )
		return GPRC_INVALID_PKT;		// wrong packet


	// ok, found the offset of IPv4/IPv6 layer

	if (offsetOut)
		*offsetOut = offset;
	if (ipver)
		*ipver = ip->ip_v;

	return GPRC_VALID_PKT;
}

ParserRetCode_t get_transport_offset(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetTransportOut, int* ipprotOut)
{
	int offset = 0, ipver = 0;
	ParserRetCode_t ret = get_ip_offset(pcap_header, pcap_packet, &offset, &ipver);
	if (ret != GPRC_VALID_PKT)
		return ret;

	const struct ip* ip = NULL;
	struct ip6_hdr* ipv6 = NULL;

	if (ipver == 4)
	{
		ip = (const struct ip*) (pcap_packet + offset);
		if (ipprotOut)
			*ipprotOut = ip->ip_p;

		size_t hlen = (u_int) ip->ip_hl * 4;
		offset += hlen;
	}
	else
	{
		ipv6 = (struct ip6_hdr*) (pcap_packet + offset);
		if (ipprotOut)
			*ipprotOut = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

		offset += sizeof(struct ip6_hdr);		// fixed size
	}


	// check there are enough bytes remaining

	if (pcap_header->len < (offset + sizeof(struct tcphdr)) &&
			pcap_header->len < (offset + sizeof(struct udphdr)))
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	// ok, found the offset for a valid UDP/TCP layer

	if (offsetTransportOut)
		*offsetTransportOut = offset;

	return GPRC_VALID_PKT;
}

//------------------------------------------------------------------------------
// Global Functions - GTPu parsing
//------------------------------------------------------------------------------

ParserRetCode_t get_gtpu_inner_ip_offset(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetIpInner, int* ipver)
{
	int offset = 0, ip_prot = 0;
	ParserRetCode_t ret = get_transport_offset(pcap_header, pcap_packet, &offset, &ip_prot);
	if (ret != GPRC_VALID_PKT)
		return ret;
	if (ip_prot != IPPROTO_UDP)
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet, all GTPu packets go over UDP


	// parse UDP layer

	if (pcap_header->len < (offset + sizeof(struct udphdr)) )
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	const struct udphdr* udp = (const struct udphdr*)(pcap_packet + offset);
	if (udp->source != htons(GTP1U_PORT) &&
			udp->dest != htons(GTP1U_PORT))
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet

	offset += sizeof(struct udphdr);


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

	if (offsetIpInner)
		*offsetIpInner = offset;
	if (ipver)
		*ipver = ipinner->ip_v;

	return GPRC_VALID_PKT;
}

ParserRetCode_t get_gtpu_inner_transport_offset(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetTransportInner, int* ipprotInner)
{
	int offset = 0, ipver = 0;
	ParserRetCode_t ret = get_gtpu_inner_ip_offset(pcap_header, pcap_packet, &offset, &ipver);
	if (ret != GPRC_VALID_PKT)
		return ret;


	const struct ip* ip = NULL;
	struct ip6_hdr* ipv6 = NULL;

	if (ipver == 4)
	{
		ip = (const struct ip*) (pcap_packet + offset);
		if (ipprotInner)
			*ipprotInner = ip->ip_p;

		size_t hlen = (u_int) ip->ip_hl * 4;
		offset += hlen;
	}
	else
	{
		ipv6 = (struct ip6_hdr*) (pcap_packet + offset);
		if (ipprotInner)
			*ipprotInner = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

		offset += sizeof(struct ip6_hdr);		// fixed size
	}


	// ok, found the offset for a valid GTPu packet

	if (offsetTransportInner)
		*offsetTransportInner = offset;

	return GPRC_VALID_PKT;
}


//------------------------------------------------------------------------------
// Global Functions - flow hashing
//------------------------------------------------------------------------------

flow_hash_t compute_flow_hash(struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet)
{
	flow_hash_t flow_hash = INVALID_FLOW_HASH;
	int offsetIp = 0, offsetTransport = 0, ip_prot = 0, ipver = 0;

	// detect if this is an encapsulated packet or nto
	ParserRetCode_t ret = get_gtpu_inner_ip_offset(pcap_header, pcap_packet, &offsetIp, &ipver);
	if (ret == GPRC_VALID_PKT)
	{
		ret = get_gtpu_inner_transport_offset(pcap_header, pcap_packet, &offsetTransport, &ip_prot);
		if (ret != GPRC_VALID_PKT)
			return INVALID_FLOW_HASH;
		if (ip_prot != IPPROTO_TCP)
			return INVALID_FLOW_HASH;		// we only compute hashes for TCP
	}
	else		// not a GTPu packet
	{
		ParserRetCode_t ret = get_ip_offset(pcap_header, pcap_packet, &offsetIp, &ipver);
		if (ret != GPRC_VALID_PKT)
			return INVALID_FLOW_HASH;

		ret = get_transport_offset(pcap_header, pcap_packet, &offsetTransport, &ip_prot);
		if (ret != GPRC_VALID_PKT)
			return INVALID_FLOW_HASH;
		if (ip_prot != IPPROTO_TCP)
			return INVALID_FLOW_HASH;		// we only compute hashes for TCP
	}


	// hash IP addresses

	if (ipver == 4)
	{
		const struct ip* ip = (const struct ip*) (pcap_packet + offsetIp);

		flow_hash = hw_fasthash((unsigned char*)&ip->ip_src,sizeof(ip->ip_src),0);
		flow_hash += hw_fasthash((unsigned char*)&ip->ip_dst,sizeof(ip->ip_dst),0);
	}
	else
	{
		struct ip6_hdr* ipv6 = (struct ip6_hdr*) (pcap_packet + offsetIp);

		flow_hash = hw_fasthash(&ipv6->ip6_src, IPV6_LEN, 0);
		flow_hash += hw_fasthash(&ipv6->ip6_dst, IPV6_LEN, 0);
	}


	// hash ports

	if (pcap_header->len < (offsetTransport + sizeof(struct tcphdr)) )
		return INVALID_FLOW_HASH;		// Packet too short

	const struct tcphdr* tcp = (const struct tcphdr*)(pcap_packet + offsetTransport);

	flow_hash += hw_fasthash(&tcp->source, sizeof(tcp->source), 0);
	flow_hash += hw_fasthash(&tcp->dest, sizeof(tcp->dest), 0);

	return flow_hash;
}
