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

#include "filter.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* superset of previous */
#include <linux/udp.h>
#include <linux/tcp.h>

#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <string>

//------------------------------------------------------------------------------
// Globals
//------------------------------------------------------------------------------

u_char g_buffer[MAX_SNAPLEN];


//------------------------------------------------------------------------------
// FilterCriteria
//------------------------------------------------------------------------------

bool FilterCriteria::prepare_filter(const std::string& pcap_filter_str,
		const std::string& gtpu_filter_str, const std::string& str_filter,
		TcpFilterMode valid_tcp_filter)
{
	// PCAP filter
	if (!pcap_filter_str.empty()) {
		if (pcap_compile_nopcap(MAX_SNAPLEN, DLT_EN10MB, &capture_filter,
				pcap_filter_str.c_str(), 0 /* optimize */, PCAP_NETMASK_UNKNOWN)
				!= 0) {
			printf_error( "Cannot parse PCAP filter: %s\n",
					pcap_filter_str.c_str());
			return false;
		}

		capture_filter_set = true;
		printf_verbose("Successfully compiled PCAP filter: %s\n", pcap_filter_str.c_str());
	}
	// GTPu PCAP filter
	if (!gtpu_filter_str.empty()) {

		if (pcap_compile_nopcap(MAX_SNAPLEN, DLT_EN10MB, &gtpu_filter,
				gtpu_filter_str.c_str(), 0 /* optimize */, PCAP_NETMASK_UNKNOWN)
				!= 0) {
			printf_error( "Cannot parse GTPu filter: %s\n",
					gtpu_filter_str.c_str());
			return false;
		}

		gtpu_filter_set = true;
		printf_verbose("Successfully compiled GTPu PCAP filter: %s\n", gtpu_filter_str.c_str());
	}
	// other filters:
	string_filter = str_filter;
	valid_tcp_filter_mode = valid_tcp_filter;
	return true;
}

//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

/* static */
bool FilterCriteria::convert_extract_filter(const std::string& extract_filter, std::string& output_pcap_filter)
{
	std::istringstream iss(extract_filter);
	std::string token;
	std::vector < std::string > tokens;
	while (std::getline(iss, token, ' '))
		tokens.push_back(token);
	std::vector < std::string > ip_port;
	switch (tokens.size()) {
	case 2:
		for (int i = 0; i < 2; i++) {
			// assume the 2 tokens are IP:port strings
			std::istringstream iss(tokens[i]);
			std::string token;
			while (std::getline(iss, token, ':'))
				ip_port.push_back(token);
		}
		if (ip_port.size() != 4) {
			printf_error(
					"Expected an IP address and a port number separated by a colon; found: %s and %s invalid IP:port strings.\n",
					tokens[0].c_str(), tokens[1].c_str());
			return false;
		}
		break;
	case 4:
		// ok as is
		ip_port = tokens;
		break;
	default:
		printf_error(
				"Expected space-separated IP:port strings instead of %s\n",
				extract_filter.c_str());
		return false;
	}
	// very basic IPv4 validation check; todo: ipv6
	for (int i = 0; i < 4; i += 2) {
		if (std::count(ip_port[i].begin(), ip_port[i].end(), '.') != 3) {
			printf_error( "Expected a valid IPv4 address, found instead %s\n",
					ip_port[i].c_str());
			return false;
		}
	}
	output_pcap_filter = "host " + ip_port[0] + " && port " + ip_port[1]
			+ " && host " + ip_port[2] + " && port " + ip_port[3];
	return true;
}

static bool apply_filter_on_inner_ip_frame(const Packet& pkt,
											unsigned int inner_ip_offset, unsigned int ipver, unsigned int len_after_inner_ip_start,
											const struct bpf_program* gtpu_filter)
{
	bool tosave = false;
	//memset(g_buffer, 0, sizeof(g_buffer));   // not actually needed

	// rebuild the ethernet frame, copying the original one possibly
	const struct ether_header* orig_ehdr = (struct ether_header*)pkt.data();
	struct ether_header* fake_ehdr = (struct ether_header*)g_buffer;
	memcpy(fake_ehdr, orig_ehdr, sizeof(*orig_ehdr));

	switch (ipver)
	{
	case 4:
		fake_ehdr->ether_type = htons(ETH_P_IP);			// erase any layer (like VLAN) possibly present in orig packet
		break;

	case 6:
		fake_ehdr->ether_type = htons(ETH_P_IPV6);			// erase any layer (like VLAN) possibly present in orig packet
		break;

	default:
		assert(0);
	}

	// copy from IPv4/v6 onward:
	const u_char* inner_ip = pkt.data() + inner_ip_offset;
	u_char* fake_ip = g_buffer + sizeof(struct ether_header);
	memcpy(fake_ip, inner_ip, len_after_inner_ip_start);
	fake_ip[len_after_inner_ip_start] = 0;		// put a NULL byte after last copied byte just in case

	// create also a fake PCAP header
	struct pcap_pkthdr fakehdr;
	memcpy(&fakehdr.ts, &pkt.header()->ts, sizeof(pkt.header()->ts));
	fakehdr.caplen = fakehdr.len = sizeof(struct ether_header) + len_after_inner_ip_start;

	// pcap_offline_filter returns
	// zero if the packet doesn't match the filter and non-zero
	// if the packet matches the filter.
	int ret = pcap_offline_filter(gtpu_filter, &fakehdr, g_buffer);
	if (ret != 0)
	{
		tosave = true;
	}

	return tosave;
}


//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

bool FilterCriteria::must_be_saved(const Packet& pkt, bool* is_gtpu) const	// will do a logical OR of all filters set
{
	// string-search filter:

	if (UNLIKELY( !string_filter.empty() ))
	{
		unsigned int len = MIN(pkt.len(), MAX_SNAPLEN);

		memcpy(g_buffer, pkt.data(), len);
		g_buffer[len] = '\0';

		void* result = memmem(g_buffer, len, string_filter.c_str(), string_filter.size());
		if (result != NULL)
			// string was found inside the packet!
			return true;   // useless to proceed!
	}


	// PCAP capture filter:

	if (UNLIKELY( capture_filter_set ))
	{
		int ret = pcap_offline_filter(&capture_filter, pkt.header(), pkt.data());
		if (ret != 0)
		{
			// pcap_offline_filter returns
			// zero if the packet doesn't match the filter and non-zero
			// if the packet matches the filter.
			return true;   // useless to proceed!
		}
	}


	// GTPu capture filter:

	if (UNLIKELY( gtpu_filter_set ))
	{
		// is this a GTPu packet?
		int offset = 0, ipver = 0, len_after_inner_ip_start = 0;
		ParserRetCode_t errcode = get_gtpu_inner_ip_start_offset(pkt, &offset, &ipver, &len_after_inner_ip_start, NULL);
		if (errcode == GPRC_VALID_PKT)
		{
			if (is_gtpu) *is_gtpu = true;

			if (offset > 0 && len_after_inner_ip_start > 0)
			{
				// run the filter only on inner/encapsulated frame:
				if (apply_filter_on_inner_ip_frame(pkt, offset, ipver, len_after_inner_ip_start, &gtpu_filter))
					return true;   // useless to proceed!
			}
		}
	}


	// valid-TCP-stream filter:

	if (UNLIKELY( valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE ))
	{
		flow_hash_t hash = compute_flow_hash(pkt);
		if (hash != INVALID_FLOW_HASH)
		{
			flow_map_t::const_iterator entry = valid_tcp_firstpass_flows.find(hash);
			if (entry != valid_tcp_firstpass_flows.end())
			{
				switch (valid_tcp_filter_mode)
				{
				case TCP_FILTER_CONN_HAVING_SYN:
					if (entry->second >= FLOW_FOUND_SYN_AND_SYNACK)
						return true;   // this TCP packet belongs to a connection that in the 1st pass was detected as having at least one SYN
					break;
				case TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE:
					if (entry->second >= FLOW_FOUND_SYN_AND_SYNACK_AND_ACK)
						return true;   // this TCP packet belongs to a connection that in the 1st pass was detected as having the full 3way handshake
					break;
				case TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE_AND_DATA:
					if (entry->second == FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA)
						return true;   // this TCP packet belongs to a connection that in the 1st pass was detected as having the full 3way handshake
					break;
				default:
					assert(0);
				}
			}
		}
	}

	return false;
}
