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

#include "parse.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* superset of previous */

#include <arpa/inet.h>

#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/sctp.h>

//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

#define IPV6_LEN			(16)

#if defined( __GNUC__ ) && __GNUC__ >= 7
#define GCC_ALLOW_FALLTHROUGH			__attribute__ ((fallthrough))
#else
#define GCC_ALLOW_FALLTHROUGH			/* empty macro */
#endif

//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

// Compression function for Merkle-Damgard construction.
#define fasthash64_mix(h) ({				\
			(h) ^= (h) >> 23;				\
			(h) *= 0x2127599bf4325c37ULL;	\
			(h) ^= (h) >> 47; })

static
uint64_t FastHash64(const char* buf, uint32_t len, uint64_t seed)
{
	const uint64_t    m = 0x880355f21e6d1965ULL;
	const uint64_t *pos = (const uint64_t *)buf;
	const uint64_t *end = pos + (len / 8);
	const unsigned char *pos2;
	uint64_t h = seed ^ (len * m);
	uint64_t v;

	while (pos != end) {
		v  = *pos++;
		h ^= fasthash64_mix(v);
		h *= m;
	}

	pos2 = (const unsigned char*)pos;
	v = 0;

	switch (len & 7) {
	case 7:
		v ^= (uint64_t)pos2[6] << 48;
		GCC_ALLOW_FALLTHROUGH;
	case 6:
		v ^= (uint64_t)pos2[5] << 40;
		GCC_ALLOW_FALLTHROUGH;
	case 5:
		v ^= (uint64_t)pos2[4] << 32;
		GCC_ALLOW_FALLTHROUGH;
	case 4:
		v ^= (uint64_t)pos2[3] << 24;
		GCC_ALLOW_FALLTHROUGH;
	case 3:
		v ^= (uint64_t)pos2[2] << 16;
		GCC_ALLOW_FALLTHROUGH;
	case 2:
		v ^= (uint64_t)pos2[1] << 8;
		GCC_ALLOW_FALLTHROUGH;
	case 1:
		v ^= (uint64_t)pos2[0];
		h ^= fasthash64_mix(v);
		h *= m;
		break;
	}

	return fasthash64_mix(h);
}

static
ParserRetCode_t do_ip_layer_parse(const Packet& pkt,
									int offset,
									int* offsetOut, int* ipver, int* len_after_ip_start, flow_hash_t* hashIP)
{
	// parse IPv4/v6 layer

	const struct ip* ip = (const struct ip*) (pkt.data() + offset);
	const struct ip6_hdr* ip6 = (const struct ip6_hdr*)(pkt.data() + offset);

	uint16_t ip_total_len = 0;
	uint16_t ip_hdr_len = 0;
	switch(ip->ip_v)
	{
	case 4:
		if (UNLIKELY( pkt.len() < (offset + sizeof(struct ip)) ))
			return GPRC_TOO_SHORT_PKT;		// Packet too short

		ip_total_len = ntohs(ip->ip_len);							// IMPORTANT: in IPv4 the "ip_len" does include the size of the IPv4 header!
		ip_hdr_len = (uint16_t)(ip->ip_hl) * 4;
		if (UNLIKELY(hashIP != NULL))
		{
			uint64_t flow_hash = FastHash64((const char*)&ip->ip_src,sizeof(ip->ip_src),0) +
									FastHash64((const char*)&ip->ip_dst,sizeof(ip->ip_dst),0);
			*hashIP += flow_hash;
		}
		break;

	case 6:
		if (UNLIKELY( pkt.len() < (offset + sizeof(struct ip6_hdr)) ))
			return GPRC_TOO_SHORT_PKT;		// Packet too short

		ip_total_len = sizeof(struct ip6_hdr) + ntohs(ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);   // IMPORTANT: in IPv6 the "ip6_un1_plen" field does not include the size of the IPv6 header!
		ip_hdr_len = sizeof(struct ip6_hdr);
		if (UNLIKELY(hashIP != NULL))
		{
			uint64_t flow_hash = FastHash64((const char*)&ip6->ip6_src, IPV6_LEN, 0) +
									FastHash64((const char*)&ip6->ip6_dst, IPV6_LEN, 0);
			*hashIP += flow_hash;
		}
		break;

	default:
		return GPRC_INVALID_PKT;		// wrong packet
	}

	if (UNLIKELY( ip_hdr_len >= ip_total_len ))
		return GPRC_INVALID_PKT;		// wrong packet


	// ok, found the offset of IPv4/IPv6 layer

	if (offsetOut)
		*offsetOut = offset;
	if (ipver)
		*ipver = ip->ip_v;
	if (len_after_ip_start)
		*len_after_ip_start = ip_total_len;

	return GPRC_VALID_PKT;
}

static
ParserRetCode_t do_transport_layer_parse(const Packet& pkt,
										int ipStartOffset, int ipver, int len_after_ip_start,
										int* offsetTransportOut, int* ipprotOut, int* len_after_transport_start, flow_hash_t* hashPorts)
{
	const struct ip* ip = NULL;
	struct ip6_hdr* ipv6 = NULL;
	int ip_proto = 0;
	uint16_t ip_hdr_len = 0;

	if (ipver == 4)
	{
		ip = (const struct ip*) (pkt.data() + ipStartOffset);
		ip_proto = ip->ip_p;
		ip_hdr_len = (uint16_t)(ip->ip_hl) * 4;
	}
	else
	{
		ipv6 = (struct ip6_hdr*) (pkt.data() + ipStartOffset);
		ip_proto = ipv6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		ip_hdr_len = sizeof(struct ip6_hdr);		// fixed size
	}
	unsigned int transportStartOffset = ipStartOffset + ip_hdr_len;


	// check there are enough bytes remaining
	switch(ip_proto)
	{
	case IPPROTO_TCP:
		if (UNLIKELY( pkt.len() < (transportStartOffset + sizeof(struct tcphdr))))
			return GPRC_TOO_SHORT_PKT;		// Packet too short
		if (UNLIKELY(hashPorts != NULL))
		{
			const struct tcphdr* tcp = (const struct tcphdr*)(pkt.data() + transportStartOffset);
			uint64_t flow_hash = FastHash64((const char*)&tcp->source, sizeof(tcp->source), 0) +
									FastHash64((const char*)&tcp->dest, sizeof(tcp->dest), 0);
			*hashPorts += flow_hash;
		}
		break;
	case IPPROTO_UDP:
		if (UNLIKELY( pkt.len() < (transportStartOffset + sizeof(struct udphdr))))
			return GPRC_TOO_SHORT_PKT;		// Packet too short
		break;
#if 0
	case IPPROTO_SCTP:
		if (UNLIKELY( pkt.len() < (transportStartOffset + sizeof(struct sctphdr))))
			return GPRC_TOO_SHORT_PKT;		// Packet too short
		break;
#endif
	default:
		break;
	}


	// ok, found the ipStartOffset for a valid UDP/TCP layer

	if (offsetTransportOut)
		*offsetTransportOut = transportStartOffset;
	if (ipprotOut)
		*ipprotOut = ip_proto;
	if (len_after_transport_start)
		*len_after_transport_start = len_after_ip_start - ip_hdr_len;

	return GPRC_VALID_PKT;
}


//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

ParserRetCode_t get_ip_start_offset(const Packet& pkt, int* offsetOut, int* ipver, int* len_after_ip_start, flow_hash_t* hashIP)
{
	unsigned int offset = 0;

	// parse Ethernet layer

	if(UNLIKELY(pkt.len() < sizeof(struct ether_header)))
		return GPRC_TOO_SHORT_PKT; // Packet too short

	const struct ether_header* ehdr = (const struct ether_header*)pkt.data();
	uint16_t eth_type = ntohs(ehdr->ether_type);
	offset = sizeof(struct ether_header);

	// parse VLAN tags

	while (ETHERTYPE_IS_VLAN(eth_type) && offset < pkt.len())
	{
		const ether80211q_t* qType = (const ether80211q_t*) (pkt.data() + offset);
		eth_type = ntohs(qType->protoType);
		offset += sizeof(ether80211q_t);
	}

	if (UNLIKELY(eth_type != ETH_P_IP))
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet


	// parse IPv4/v6 layer

	return do_ip_layer_parse(pkt, offset, offsetOut, ipver, len_after_ip_start, hashIP);
}

ParserRetCode_t get_transport_start_offset(const Packet& pkt, int* offsetTransportOut, int* ipprotOut, int* len_after_transport_start, flow_hash_t* hash)
{
	int ipStartOffset = 0, ipver = 0, len_after_ip_start = 0;
	ParserRetCode_t ret = get_ip_start_offset(pkt, &ipStartOffset, &ipver, &len_after_ip_start, hash);
	if (UNLIKELY(ret != GPRC_VALID_PKT))
		return ret;

	return do_transport_layer_parse(pkt, ipStartOffset, ipver, len_after_ip_start,
									offsetTransportOut, ipprotOut, len_after_transport_start, hash);
}

//------------------------------------------------------------------------------
// Global Functions - GTPu parsing
//------------------------------------------------------------------------------

ParserRetCode_t get_gtpu_inner_ip_start_offset(const Packet& pkt, int* offsetIpInner, int* ipver, int* remainingLen, flow_hash_t* hash)
{
	int offset = 0, ip_prot = 0;
	ParserRetCode_t ret = get_transport_start_offset(pkt, &offset, &ip_prot, NULL, hash);
	if (UNLIKELY(ret != GPRC_VALID_PKT))
		return ret;
	if (UNLIKELY(ip_prot != IPPROTO_UDP))
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet, all GTPu packets go over UDP


	// parse UDP layer

	const struct udphdr* udp = (const struct udphdr*)(pkt.data() + offset);
	if (udp->source != htons(GTP1U_PORT) && udp->dest != htons(GTP1U_PORT))
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet

	offset += sizeof(struct udphdr);


	// parse GTPu layer

	if (UNLIKELY( pkt.len() < (offset + sizeof(struct gtp1_header)) ))
		return GPRC_TOO_SHORT_PKT;		// Packet too short

	const struct gtp1_header* gtpu = (const struct gtp1_header*)(pkt.data() + offset);

	//check for gtp-u message (type = 0xff) and is a gtp release 1
	if (UNLIKELY((gtpu->flags & 0xf0) != 0x30))
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet
	if (UNLIKELY(gtpu->type != GTP_TPDU))
		return GPRC_NOT_GTPU_PKT;		// not a GTPu packet

	offset += sizeof(struct gtp1_header);
	const u_char* gtp_start = pkt.data() + offset;
	const u_char* gtp_payload = pkt.data() + offset;

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

	return do_ip_layer_parse(pkt, offset, offsetIpInner, ipver, remainingLen, hash);
}

ParserRetCode_t get_gtpu_inner_transport_start_offset(const Packet& pkt, int* offsetTransportInner, int* ipprotInner, int* remainingLen, flow_hash_t* hash)
{
	int ipStartOffset = 0, ipver = 0, len_after_ip_start = 0;
	ParserRetCode_t ret = get_gtpu_inner_ip_start_offset(pkt, &ipStartOffset, &ipver, &len_after_ip_start, hash);
	if (UNLIKELY(ret != GPRC_VALID_PKT))
		return ret;

	return do_transport_layer_parse(pkt, ipStartOffset, ipver, len_after_ip_start,
									offsetTransportInner, ipprotInner, remainingLen, hash);
}


//------------------------------------------------------------------------------
// Global Functions - parsing stats
//------------------------------------------------------------------------------

void update_parsing_stats(const Packet& pkt, ParsingStats& outstats)
{
	ParserRetCode_t ret;

	// increment the total: it will be used to compute percentages later
	outstats.pkts_total++;

	// TODO: this way to do the stats is pretty much non-efficient:

	ret = get_gtpu_inner_transport_start_offset(pkt, NULL, NULL, NULL, NULL);
	if (ret == GPRC_VALID_PKT)
	{
		outstats.pkts_valid_gtpu_transport++;
		return;
	}
	//else: try to parse inner layers

	ret = get_gtpu_inner_ip_start_offset(pkt, NULL, NULL, NULL, NULL);
	if (ret == GPRC_VALID_PKT)
	{
		outstats.pkts_valid_gtpu_ip++;
		return;
	}
	//else: try to parse inner layers

	ret = get_transport_start_offset(pkt, NULL, NULL, NULL, NULL);
	if (ret == GPRC_VALID_PKT)
	{
		outstats.pkts_valid_tranport++;
		return;
	}
	//else: try to parse inner layers

	ret = get_ip_start_offset(pkt, NULL, NULL, NULL, NULL);
	if (ret == GPRC_VALID_PKT)
	{
		outstats.pkts_valid_ip++;
		return;
	}
	//else: try to parse inner layers


	outstats.pkts_invalid++;
}

//------------------------------------------------------------------------------
// Global Functions - flow hashing
//------------------------------------------------------------------------------

flow_hash_t compute_flow_hash(const Packet& pkt)
{
	flow_hash_t flow_hash = INVALID_FLOW_HASH;
	int/* offsetIp = 0,*/ offsetTransport = 0, ip_prot = 0/*, ipver = 0*/;

	// detect if this is an encapsulated packet or not
	ParserRetCode_t ret = get_gtpu_inner_transport_start_offset(pkt, &offsetTransport, &ip_prot, NULL, &flow_hash);
	if (ret == GPRC_VALID_PKT)
	{
#if 0
		ret = get_gtpu_inner_transport_start_offset(pkt, &offsetTransport, &ip_prot, NULL);
		if (UNLIKELY( ret != GPRC_VALID_PKT ))
			return INVALID_FLOW_HASH;
		if (UNLIKELY( ip_prot != IPPROTO_TCP ))
			return INVALID_FLOW_HASH;		// we only compute hashes for TCP
#else
		if (UNLIKELY( ip_prot != IPPROTO_TCP ))
			return INVALID_FLOW_HASH;		// we only compute hashes for TCP
#endif

	}
	else		// not a GTPu packet... try parsing it as a non-encapsulated packet:
	{
#if 0
		ParserRetCode_t ret = get_ip_start_offset(pkt, &offsetIp, &ipver, NULL);
		if (UNLIKELY( ret != GPRC_VALID_PKT ))
			return INVALID_FLOW_HASH;

		ret = get_transport_start_offset(pkt, &offsetTransport, &ip_prot, NULL);
		if (UNLIKELY( ret != GPRC_VALID_PKT ))
			return INVALID_FLOW_HASH;
		if (UNLIKELY( ip_prot != IPPROTO_TCP ))
			return INVALID_FLOW_HASH;		// we only compute hashes for TCP
#else
		ret = get_transport_start_offset(pkt, &offsetTransport, &ip_prot, NULL, &flow_hash);
		if (UNLIKELY( ret != GPRC_VALID_PKT ))
			return INVALID_FLOW_HASH;
		if (UNLIKELY( ip_prot != IPPROTO_TCP ))
			return INVALID_FLOW_HASH;		// we only compute hashes for TCP
#endif

	}

#if 0
	// hash IP addresses

	if (ipver == 4)
	{
		const struct ip* ip = (const struct ip*) (pkt.data() + offsetIp);

		flow_hash = hw_fasthash((unsigned char*)&ip->ip_src,sizeof(ip->ip_src),0);
		flow_hash += hw_fasthash((unsigned char*)&ip->ip_dst,sizeof(ip->ip_dst),0);
	}
	else
	{
		struct ip6_hdr* ipv6 = (struct ip6_hdr*) (pkt.data() + offsetIp);

		flow_hash = hw_fasthash(&ipv6->ip6_src, IPV6_LEN, 0);
		flow_hash += hw_fasthash(&ipv6->ip6_dst, IPV6_LEN, 0);
	}


	// hash ports

	if (UNLIKELY( pkt.len() < (offsetTransport + sizeof(struct tcphdr)) ))
		return INVALID_FLOW_HASH;		// Packet too short

	const struct tcphdr* tcp = (const struct tcphdr*)(pkt.data() + offsetTransport);

	flow_hash += hw_fasthash(&tcp->source, sizeof(tcp->source), 0);
	flow_hash += hw_fasthash(&tcp->dest, sizeof(tcp->dest), 0);
#endif
	return flow_hash;
}
