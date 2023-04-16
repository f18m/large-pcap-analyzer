/*
 * processor.h
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

#ifndef TRAFFIC_STATS_PROCESSOR_H_
#define TRAFFIC_STATS_PROCESSOR_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include <map>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unordered_map>

#include "parse.h"
#include "processor.h"

#include <algorithm>
#include <string>
#include <vector>

//------------------------------------------------------------------------------
// TrafficStatsPacketProcessor
// Packet processor specialized in manipulation of packet to extract Traffic Stats
//------------------------------------------------------------------------------

class FlowStats_t {
public:
    // identifiers of the flow:
    ParsingInfo m_FlowInfo;
    flow_hash_t m_FlowHash = 0;
    // stats about this flow:
    uint64_t m_npackets = 0;
    uint64_t m_nbytes = 0;
};

typedef std::unordered_map<flow_hash_t /* key */, FlowStats_t /* value */>
    flow_map_for_traffic_stats_t;

class TrafficStatsPacketProcessor : public IPacketProcessor {
public:
    TrafficStatsPacketProcessor()
    {
        m_num_input_pkts = 0;
        m_conn_map.clear();
    }

    ~TrafficStatsPacketProcessor() { }

    bool prepare_processor(bool inner, int topflow_max);

    // does
    virtual bool process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx, bool& pktWasChangedOut) override;
    virtual bool post_processing(const std::string& file, unsigned int totNumPkts) override;

private:
    // configuration:
    bool m_inner;
    int m_topflow_max;

    // status:
    unsigned long m_num_input_pkts;
    flow_map_for_traffic_stats_t m_conn_map;
};

#endif // TRAFFIC_STATS_PROCESSOR_H_
