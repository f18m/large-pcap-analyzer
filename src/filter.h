/*
 * filter.h
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

#ifndef FILTER_H_
#define FILTER_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "large-pcap-analyzer.h"
#include "parse.h"

#include <string>


//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

typedef enum
{
	TCP_FILTER_NOT_ACTIVE,
	TCP_FILTER_CONN_HAVING_SYN,
	TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE,
	TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE_AND_DATA,
} TcpFilterMode;

class FilterCriteria
{
public:
	FilterCriteria()
	{
		memset(&capture_filter, 0, sizeof(capture_filter));
		memset(&gtpu_filter, 0, sizeof(gtpu_filter));
		capture_filter_set = false;
		gtpu_filter_set = false;
		valid_tcp_filter_mode = TCP_FILTER_NOT_ACTIVE;
	}

	~FilterCriteria()
	{
		if (capture_filter_set)
			pcap_freecode(&capture_filter);
		if (gtpu_filter_set)
			pcap_freecode(&gtpu_filter);
	}

	bool prepare_filter(const std::string& pcap_filter_str,
			const std::string& gtpu_filter_str, const std::string& str_filter,
			TcpFilterMode valid_tcp_filter);


	static bool convert_extract_filter(const std::string& extract_filter, std::string& output_pcap_filter);


	bool is_some_filter_active() const
		{ return (capture_filter_set || gtpu_filter_set || !string_filter.empty() || valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE); }

	bool is_capture_filter_set() const { return capture_filter_set; }
	bool is_gtpu_filter_set() const { return gtpu_filter_set; }

	bool needs_2passes() const
		{ return valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE; }

	bool must_be_saved(const Packet& pkt, bool* is_gtpu) const;


private:
	struct bpf_program 			capture_filter;
	bool 						capture_filter_set;

	struct bpf_program 			gtpu_filter;
	bool 						gtpu_filter_set;

	std::string					string_filter;

	TcpFilterMode				valid_tcp_filter_mode;

public:
	flow_map_t 					valid_tcp_firstpass_flows;			// contains the result of the 1st pass
};


#endif	// FILTER_H_
