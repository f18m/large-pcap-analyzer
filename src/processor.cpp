/*
 * processor.cpp
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


//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "processor.h"
#include "large-pcap-analyzer.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* superset of previous */
#include <linux/udp.h>
#include <linux/tcp.h>


//------------------------------------------------------------------------------
// PacketProcessorConfig
//------------------------------------------------------------------------------

bool PacketProcessor::prepare_processor(const std::string& set_duration)
{
	if (!set_duration.empty()) {
		// the duration string can be a number in format
		//     SECONDS.FRACTIONAL_SECONDS
		// or: HH:MM:SS.FRACTIONAL_SECONDS
		//     ^^^^^^^^
		//     8 characters
		int num_dots = std::count(set_duration.begin(), set_duration.end(), '.');
		int num_colons = std::count(set_duration.begin(), set_duration.end(), ':');
		if (num_dots == 1 && num_colons == 0) {
			// FIRST SYNTAX FORMAT
			m_duration_secs = atof(set_duration.c_str()) ;
		} else if (num_dots == 0 && num_colons == 0) {
			// FIRST SYNTAX FORMAT WITHOT FRACTIONAL SECS
			m_duration_secs = atoi(set_duration.c_str()) ;
		} else if (num_dots <= 1 && num_colons == 2 &&
				set_duration.size() >= 8 /* chars */ &&
				set_duration[2] == ':' &&
				set_duration[5] == ':') {

			// SECOND SYNTAX FORMAT
			int hh = atoi(set_duration.substr(0, 2).c_str());
			int mm = atoi(set_duration.substr(3, 5).c_str());
			double ss = atof(set_duration.substr(6).c_str());

			m_duration_secs = hh*3600 + mm*60 + ss;

		} else {
			printf_error( "Cannot parse PCAP duration to set: %s\n", set_duration.c_str());
			return false;
		}

		m_change_duration = true;
		printf_verbose("PCAP duration will be set to: %f secs\n", m_duration_secs);
	}
	return true;
}

bool PacketProcessor::process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx)
{
	if (UNLIKELY(m_change_duration))
	{
		assert(m_duration_secs>0);
		assert(m_num_input_pkts>0);

		if (pktIdx == 0)
		{
			assert(m_first_pkt_ts_sec == 0);
			m_first_pkt_ts_sec = pktIn.pcap_timestamp_to_seconds();
			if (m_first_pkt_ts_sec == 0)
				printf_error("WARNING: invalid timestamp zero (Thursday, 1 January 1970 00:00:00) for the first packet. This is unusual.\n");

			return false; // no proc done
		}
		else
		{
			//if (m_first_pkt_ts_sec == 0)
				//return false; // cannot process

			double secInterPktGap = m_duration_secs/m_num_input_pkts;
			double thisPktTs = m_first_pkt_ts_sec + secInterPktGap*(pktIdx+1);

			pktOut.copy(pktIn.header(), pktIn.data());
			pktOut.set_timestamp_from_seconds(thisPktTs);

			return true;
		}
	}

	return false; // no proc done
}
