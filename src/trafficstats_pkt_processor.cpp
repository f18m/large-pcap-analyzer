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

bool TrafficStatsPacketProcessor::prepare_processor(bool inner, int topflow_max)
{
    m_inner = inner;
    m_topflow_max = topflow_max;
    return true;
}

bool TrafficStatsPacketProcessor::process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx, bool& pktWasChangedOut)
{
    (void)pktIdx;
    (void)pktWasChangedOut;
    ParserRetCode_t ret = GPRC_NOT_GTPU_PKT;
    FlowStats_t FlowStats;
    flow_hash_t hash = 0;
    int offsetTransport = 0, ip_prot = 0, offsetInnerTransport = 0;

    m_num_input_pkts++;

    // compute_flow_hash
    if (m_inner) {
        // detect if this is an encapsulated packet or not
        ret = get_gtpu_inner_transport_start_offset(
            pktIn, &offsetTransport, &ip_prot, &offsetInnerTransport, &hash, &FlowStats.m_FlowInfo);
    }

    if (ret == GPRC_NOT_GTPU_PKT) {
        ret = get_transport_start_offset(pktIn, &offsetTransport, &ip_prot, NULL,
            &hash, &FlowStats.m_FlowInfo);
    }

#if 0 // GTOTODO: Sometime the inner packet fails here !!!!
    if (UNLIKELY(ret != GPRC_VALID_PKT))
        return false;
#endif

    // Flow Lookup
    flow_map_for_traffic_stats_t::iterator itr = m_conn_map.find(hash);
    if (itr != m_conn_map.end()) {
        // This flow is already present
        itr->second.m_npackets++;
        itr->second.m_nbytes += pktIn.len();
        FlowStats = itr->second;
    } else {
        // This is the first packet of the flaw

#if 0 // GTOTODO: Sometime the inner packet fails here !!!!
        if (UNLIKELY(ret != GPRC_VALID_PKT)) {
            printf_error("TrafficStatsPacketProcessor::process_packet() - Invalid Packet");
            return false;
        }
#endif

        FlowStats.m_FlowHash = hash;
        FlowStats.m_npackets = 1;
        FlowStats.m_nbytes = pktIn.len();
        m_conn_map.insert(std::make_pair(hash, FlowStats));
    }

    // no change to input
    pktOut = pktIn;

    return true;
}

bool TrafficStatsPacketProcessor::post_processing(const std::string& infile, unsigned int /* totNumPkts */)
{
    int flow_id = 0;
    std::string csv_header = "Num,nPkts,%Pkts,FlowHash,ip_src,ip_dst,ip_proto,port_src,port_dst"; // infile

    // Create a new temp map to sort the connection based on number of packets (Descending order)
    std::multimap<uint64_t, FlowStats_t, std::greater<int>> temp;
    for (auto conn : m_conn_map) {
        temp.insert(std::pair<uint64_t, FlowStats_t>(conn.second.m_npackets, conn.second));
    }

    // Open the CSV output file
    const auto outfile = infile + ".csv";
    std::ofstream fout(outfile);
    if (!fout)
        printf_error("Error opening the output file [%s]: %s\n", outfile.c_str(), strerror(errno));

    // Print first TOP N entries of "temp"
    printf_normal("------------------------------------------------------------------------------------------\n");
    printf_normal("Input file: %s - Total number of Packets/Flows: %d/%d\n", infile.c_str(), m_num_input_pkts, m_conn_map.size());
    printf_normal("------------------------------------------------------------------------------------------\n");

    for (auto conn_top : temp) {
        double pkt_percentage = ((double)(conn_top.first) / m_num_input_pkts) * 100;

        if (flow_id < m_topflow_max || m_topflow_max == 0) {
            // PRINT first TOP N entries of "temp" on console
            if (flow_id == 0) {
                printf_normal("%s\n", csv_header.c_str());
                printf_normal("------------------------------------------------------------------------------------------\n");
            }
            printf_normal("%d,%lu,%.2f%,%lu,%s,%s,%d,%d,%d\n", // ,%s
                flow_id, conn_top.first,
                pkt_percentage,
                conn_top.second.m_FlowHash,
                conn_top.second.m_FlowInfo.m_ip_src.toString().c_str(),
                conn_top.second.m_FlowInfo.m_ip_dst.toString().c_str(),
                conn_top.second.m_FlowInfo.m_ip_proto,
                conn_top.second.m_FlowInfo.m_port_src,
                conn_top.second.m_FlowInfo.m_port_dst);
            //infile.c_str());

            // WRITE the first TOP N entries of "temp" in a CV file.
            if (fout) {
                if (flow_id == 0)
                    fout << csv_header << std::endl;

                fout << flow_id << ",";
                fout << conn_top.first << ",";
                fout << pkt_percentage << ",";
                fout << conn_top.second.m_FlowHash << ",";
                fout << conn_top.second.m_FlowInfo.m_ip_src.toString().c_str() << ",";
                fout << conn_top.second.m_FlowInfo.m_ip_dst.toString().c_str() << ",";
                fout << (int)conn_top.second.m_FlowInfo.m_ip_proto << ",";
                fout << conn_top.second.m_FlowInfo.m_port_src << ",";
                fout << conn_top.second.m_FlowInfo.m_port_dst;
                //fout << infile.c_str() << ",";
                fout << std::endl;
            }
        }
        flow_id++;
    }
    printf_normal("------------------------------------------------------------------------------------------\n");

    // Clear current stats/map
    m_num_input_pkts = 0;
    m_conn_map.clear();

    return true;
}
