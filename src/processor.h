/*
 * processor.h
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 * Created: June 2018
 * Last Modified: June 2018
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

#ifndef PROCESSING_H_
#define PROCESSING_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "large-pcap-analyzer.h"
#include "parse.h"

#include <string>
#include <algorithm>


//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

class PacketProcessor
{
public:
	PacketProcessor()
	{
		m_change_duration = false;
		m_duration_secs = 0;
		m_first_pkt_ts_sec = 0;
		m_num_input_pkts = 0;
	}

	~PacketProcessor()
	{
	}
	bool prepare_processor(const std::string& set_duration);

	bool is_some_processing_active() const
		{ return m_change_duration; }
	bool needs_2passes() const
		{ return m_change_duration; }

	void set_num_packets(unsigned long npkts)
		{ m_num_input_pkts = npkts; }

	// returns true if the output packet has been filled or false if no action
	// was performed on the input packet and thus the caller should use the pktIn instance
	bool process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx);

private:
	// configuration:
	bool m_change_duration;
	double m_duration_secs;

	// status:
	double m_first_pkt_ts_sec;
	unsigned long m_num_input_pkts;
};


#endif	// PROCESSING_H_
