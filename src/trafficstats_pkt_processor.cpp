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
    flow_hash_t hash;
    memset(&FlowStats, 0, sizeof(FlowStats));

    m_num_input_pkts++;

    // Parse the packet Info
    ParserRetCode_t ret
        = get_transport_start_offset(pktIn, NULL, NULL,
            NULL, &hash, &FlowStats.m_FlowInfo);

    // Flow Lookup
    flow_map_for_traffic_stats_t::iterator itr = m_conn_map.find(hash);
    if (itr != m_conn_map.end()) {
        // This flow is already present
        //printf_normal("GTODBG: TrafficStatsPacketProcessor::process_packet() - Found: %lu\n", hash);
        itr->second.m_npackets++;
        itr->second.m_nbytes += pktIn.len();
        FlowStats = itr->second;
    } else {
        // This is the first packet of the flaw

        if (UNLIKELY(ret != GPRC_VALID_PKT)) {
            printf_error("TrafficStatsPacketProcessor::process_packet() - Invalid Packet");
            return false;
        }

        //printf_normal("GTODBG: TrafficStatsPacketProcessor::process_packet() - Insert: %lu\n", hash);
        FlowStats.m_FlowHash = hash;
        FlowStats.m_npackets = 1;
        FlowStats.m_nbytes = pktIn.len();
        m_conn_map.insert(std::make_pair(hash, FlowStats));

#if 0
        printf_normal("GTODBG: %lu, %lu, %lu, %d, %d, %d \n", FlowStats.m_FlowHash, FlowStats.m_FlowInfo.m_ip_src, FlowStats.m_FlowInfo.m_port_dst, FlowStats.m_FlowInfo.m_ip_proto, FlowStats.m_FlowInfo.m_port_src, FlowStats.m_FlowInfo.m_port_dst);
        printf_normal("GTODBG: %lu, %lu\n", FlowStats.m_FlowInfo.m_ip_src, FlowStats.m_FlowInfo.m_ip_dst);
        printf_normal("GTODBG: %lu, %lu, %lu\n", FlowStats.m_FlowHash, FlowStats.m_FlowInfo.m_ip_src, FlowStats.m_FlowInfo.m_ip_dst);

        exit(0);
#endif
    }

    // no change to input
    pktOut = pktIn;

    return true;
}

bool TrafficStatsPacketProcessor::post_processing(unsigned int /* totNumPkts */)
{
    int conn_top_num = 0;

    // Here we need to create a new temp map to sort the connection based on number of packets (Descending order)
    std::multimap<uint64_t, FlowStats_t, std::greater<int>> temp;

    for (auto conn : m_conn_map) {
        temp.insert(std::pair<uint64_t, FlowStats_t>(conn.second.m_npackets, conn.second));
    }

    printf_normal("------------------------------------------------------------------------------------------\n");
    printf_normal("Total number of Packets/Flows: %d/%d\n", m_num_input_pkts, m_conn_map.size());
    printf_normal("------------------------------------------------------------------------------------------\n");

    // read first N entries of "temp"
    printf_normal("Num,nPkts,%Pkts,FlowHash,ip_src,ip_dst,ip_proto,port_src,port_dst\n");
    printf_normal("------------------------------------------------------------------------------------------\n");

    for (auto conn_top : temp) {
        double pkt_percentage = ((double)(conn_top.first) / m_num_input_pkts) * 100;

        printf_normal("%d,%lu,%.2f%,%lu,%s,%s,%d,%d,%d\n",
            conn_top_num, conn_top.first, pkt_percentage,
            conn_top.second.m_FlowHash,
            conn_top.second.m_FlowInfo.m_ip_src.toString().c_str(),
            conn_top.second.m_FlowInfo.m_ip_dst.toString().c_str(),
            conn_top.second.m_FlowInfo.m_ip_proto,
            conn_top.second.m_FlowInfo.m_port_src,
            conn_top.second.m_FlowInfo.m_port_dst);

        if (++conn_top_num >= 10)
            break;
    }
    printf_normal("------------------------------------------------------------------------------------------\n");

    return true;
}
