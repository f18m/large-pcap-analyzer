/*
 * traffic_stats_processor.cpp
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

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "trafficstats_pkt_processor.h"
#include "large-pcap-analyzer.h"
#include "printf_helpers.h"

#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */

#include <assert.h>
#include <fstream>
#include <sstream>

//------------------------------------------------------------------------------
// Globals
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// TrafficStatsPacketProcessor
//------------------------------------------------------------------------------

bool TrafficStatsPacketProcessor::prepare_processor()
{
    return true;
}

bool TrafficStatsPacketProcessor::process_packet(const Packet& pktIn, Packet& pktOut, unsigned int, bool&)
{
    FlowStats_t FlowStats;

    // Compute hash on outer only !
    flow_hash_t hash = compute_flow_hash(pktIn, /*inner*/ false);

    // Flow Lookupt
    flow_map_for_traffic_stats_t::iterator itr = m_conn_map.find(hash);
    if (itr != m_conn_map.end()) {
        // This flow is already present
        FlowStats = itr->second;
    } else {

        // This is the first packet of the flaw
        memset(&FlowStats, 0, sizeof(FlowStats));

        // Parse the packet Info
        ParserRetCode_t ret
            = get_transport_start_offset(pktIn, NULL, NULL,
                NULL, &hash, &FlowStats.m_FlowInfo);

        if (UNLIKELY(ret != GPRC_VALID_PKT))
            return false;

        m_conn_map.insert(std::make_pair(hash, FlowStats));
        FlowStats.m_FlowHash = hash;
    }

    // Stats update
    FlowStats.m_npackets++;
    FlowStats.m_nbytes += pktIn.len();

    // no change to input
    pktOut = pktIn;

    return true;
}

bool TrafficStatsPacketProcessor::post_processing(unsigned int /* totNumPkts */)
{

    // Here we need to create a new temp map to sort the connection based on number of packets
    std::map<uint64_t, FlowStats_t> temp;

    for (auto conn : m_conn_map) {
        temp.insert(std::pair<uint64_t, FlowStats_t>(conn.second.m_npackets, conn.second));
    }

    // read first 10 entries of "temp"
    printf_normal("nPkts, FlowHash, ip_src, ip_dst, ip_proto, port_src, port_dst \n");
    for (auto conn_top : temp) {

        printf_normal(" %lu, %lu, %lu, %lu, %d, %d, %d \n", conn_top.first, conn_top.second.m_FlowHash, conn_top.second.m_FlowInfo.m_ip_src, conn_top.second.m_FlowInfo.m_ip_dst, conn_top.second.m_FlowInfo.m_ip_proto, conn_top.second.m_FlowInfo.m_port_src, conn_top.second.m_FlowInfo.m_port_dst);
    }

    return true;
}
