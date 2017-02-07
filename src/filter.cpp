/*
 * filter.cpp
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
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* superset of previous */
#include <linux/udp.h>
#include <linux/tcp.h>


//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

static bool apply_filter_on_inner_ipv4_frame(struct pcap_pkthdr* pcap_header, const u_char* pcap_packet,
												unsigned int inner_ipv4_offset, unsigned int inner_ipv4_len,
												const struct bpf_program* gtpu_filter)
{
	bool tosave = FALSE;
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

bool must_be_saved(struct pcap_pkthdr* pcap_header, const u_char* pcap_packet,
					const FilterCriteria* filter, bool* is_gtpu)
{
	// string-search filter:

	if (filter->string_filter)
	{
		unsigned int len = MIN(pcap_header->len, MAX_SNAPLEN);

		memcpy(g_buffer, pcap_packet, len);
		g_buffer[len] = '\0';

		void* result = memmem(g_buffer, len, filter->string_filter, strlen(filter->string_filter));
		if (result != NULL)
			// string was found inside the packet!
			return TRUE;   // useless to proceed!
	}


	// PCAP capture filter:

	if (filter->capture_filter_set)
	{
		int ret = pcap_offline_filter(&filter->capture_filter, pcap_header, pcap_packet);
		if (ret != 0)
		{
			// pcap_offline_filter returns
			// zero if the packet doesn't match the filter and non-zero
			// if the packet matches the filter.
			return TRUE;   // useless to proceed!
		}
	}


	// GTPu capture filter:

	if (filter->gtpu_filter_set)
	{
		// is this a GTPu packet?
		int offset = 0, ipver = 0;
		ParserRetCode_t errcode = get_gtpu_inner_ip_offset(pcap_header, pcap_packet, &offset, &ipver);
		if (is_gtpu && errcode == GPRC_VALID_PKT)
		{
			*is_gtpu = TRUE;

			// is there a GTPu PCAP filter?
			int len = pcap_header->len - offset;
			if (offset > 0 && len > 0)
			{
				// run the filter only on inner/encapsulated frame:
				if (apply_filter_on_inner_ipv4_frame(pcap_header, pcap_packet, offset, len, &filter->gtpu_filter))
					return TRUE;   // useless to proceed!
			}
		}
	}


	// valid-TCP-stream filter:

	if (filter->valid_tcp_filter)
	{
		flow_hash_t hash = compute_flow_hash(pcap_header, pcap_packet, *is_gtpu);

		if (hash != INVALID_FLOW_HASH)
		{
			flow_map_t::const_iterator entry = filter->valid_tcp_firstpass_flows.find(hash);
			if (entry != filter->valid_tcp_firstpass_flows.end() &&
					entry->second == FLOW_FOUND_SYN_AND_SYNACK)
				return TRUE;   // useless to proceed! in the 1st run this connection was tagged as VALID
		}
	}

	return FALSE;
}
