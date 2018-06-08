/*
 * parse.h
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


#ifndef PARSE_H_
#define PARSE_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "large-pcap-analyzer.h"

//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

typedef enum
{
	GPRC_VALID_PKT = 0,

	GPRC_NOT_GTPU_PKT = -1,
	GPRC_TOO_SHORT_PKT = -2,
	GPRC_INVALID_PKT = -3,
} ParserRetCode_t;

typedef enum
{
	FLOW_FOUND = 1,
	FLOW_FOUND_SYN,
	FLOW_FOUND_SYN_AND_SYNACK,
	FLOW_FOUND_SYN_AND_SYNACK_AND_ACK,
	FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA,
} FlowStatus_t;

typedef uint64_t   flow_hash_t;								// init to INVALID_FLOW_HASH
#if __cplusplus <= 199711L
	// no C++11 support
	#include <map>
	typedef std::map<flow_hash_t /* key */, FlowStatus_t /* value */>     flow_map_t;
#else
	// C++11 support available
	#include <unordered_map>
	typedef std::unordered_map<flow_hash_t /* key */, FlowStatus_t /* value */>     flow_map_t;
#endif

class ParsingStats
{
public:
	ParsingStats()
	{
		pkts_valid_gtpu_transport=0;
		pkts_valid_gtpu_ip=0;
		pkts_valid_tranport=0;
		pkts_valid_ip=0;
		pkts_invalid=0;
		pkts_total=0;
	}

	double perc_pkts_valid_gtpu_transport() const			{ return 100.0*double(pkts_valid_gtpu_transport)/double(pkts_total); }
	double perc_pkts_valid_gtpu_ip() const					{ return 100.0*double(pkts_valid_gtpu_ip)/double(pkts_total); }
	double perc_pkts_valid_tranport() const					{ return 100.0*double(pkts_valid_tranport)/double(pkts_total); }
	double perc_pkts_valid_ip() const						{ return 100.0*double(pkts_valid_ip)/double(pkts_total); }
	double perc_pkts_invalid() const						{ return 100.0*double(pkts_invalid)/double(pkts_total); }

public:
	uint64_t 					pkts_valid_gtpu_transport;
	uint64_t 					pkts_valid_gtpu_ip;
	uint64_t 					pkts_valid_tranport;
	uint64_t 					pkts_valid_ip;
	uint64_t 					pkts_invalid;

	uint64_t 					pkts_total;
};



//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

extern ParserRetCode_t get_transport_start_offset(const Packet& pkt, int* offsetTransportOut, int* ipprotOut, int* remainingLen, flow_hash_t* hash);

extern ParserRetCode_t get_gtpu_inner_ip_start_offset(const Packet& pkt, int* offsetIpInner, int* ipver, int* remainingLen, flow_hash_t* hash);
extern ParserRetCode_t get_gtpu_inner_transport_start_offset(const Packet& pkt, int* offsetTransportInner, int* ipprotInner, int* remainingLen, flow_hash_t* hash);

extern void update_parsing_stats(const Packet& pkt, ParsingStats& outstats);

extern flow_hash_t compute_flow_hash(const Packet& pkt);

#endif		// PARSE_H_
