/*
 * trafficstats_pkt_processor.cpp
 *
 * Author: Giovanni Tosatti
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

bool TrafficStatsPacketProcessor::process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx, bool& pktWasChangedOut)
{
    (void)pktIdx; // not used
    pktWasChangedOut = false; // this processor never edits the packet
    pktOut = pktIn; // this processor never edits the packet
    m_num_input_pkts++;

    ParserRetCode_t ret = GPRC_NOT_GTPU_PKT;
    FlowInfo flow_id;
    int offset_transport = 0, ip_proto = 0;

    // parse the packet
    if (m_inner) {
        // detect if this is a GTPu-encapsulated packet or not
        ret = get_gtpu_inner_transport_start_offset(pktIn, &offset_transport, &ip_proto, NULL, &flow_id);
        if (ret == GPRC_NOT_GTPU_PKT) {
            // not a GTPu packet... look at the network/transport layers that are present:
            ret = get_transport_start_offset(pktIn, &offset_transport, &ip_proto, NULL, &flow_id);
        }
    } else {
        // just check the outer layer also for GTPu-encapsulated packets
        ret = get_transport_start_offset(pktIn, &offset_transport, &ip_proto, NULL, &flow_id);
    }

    if (UNLIKELY(ret != GPRC_VALID_PKT)) {
        m_num_parse_failed_pkts++;
        return true; // keep going, don't stop here
    }

    // flow hash lookup
    flow_hash_t hash = flow_id.compute_flow_hash();
    traffic_stats_by_flow_t::iterator itr = m_conn_map.find(hash);
    if (itr != m_conn_map.end()) {
        // This flow is already present -- just update its stats
        itr->second.update_stats(pktIn.len());
    } else {
        // This is the first packet of a new flow -- add it to the map
        m_conn_map.insert(std::make_pair(hash, FlowStats(flow_id, pktIn.len())));
    }

    return true;
}

bool TrafficStatsPacketProcessor::post_processing(const std::string& /* infile */, unsigned int /* totNumPkts */)
{
    // summarize the result so far
    printf_normal("Packet parsing failed for %lu/%lu pkts. Total number of packets/flows detected: %ld/%zu.\n",
        m_num_parse_failed_pkts, m_num_input_pkts, m_num_input_pkts - m_num_parse_failed_pkts, m_conn_map.size());

    // Create a new temp map to sort the connections based on number of packets (key sorted in descending order)
    std::multimap<uint64_t, FlowStats, std::greater<int>> temp;
    uint64_t total_pkts = 0, total_bytes = 0;
    for (auto conn : m_conn_map) {
        uint64_t n_packets = conn.second.get_packets();
        const FlowStats& stats = conn.second;
        temp.insert(std::make_pair(n_packets, stats));
        total_pkts += n_packets;
        total_bytes += conn.second.get_bytes();
    }

    // If needed, save the report in an output CSV file
    std::ofstream fout;
    if (!m_report_outfile.empty()) {
        fout.open(m_report_outfile);
        if (!fout) {
            printf_error("Error opening the output file [%s]: %s\n", m_report_outfile.c_str(), strerror(errno));
            return false;
        }
    }

    // Print first TOP N entries of "temp"
    unsigned int nflow = 0;
    char csv_line[8192];
    for (auto conn_top : temp) {
        if (nflow < m_topflow_max /* one of the topN flows?*/ || m_topflow_max == 0 /* print all flows? */) {
            if (nflow == 0) {
                std::string csv_header = "flow_num,num_pkts,%pkts,num_bytes,%bytes,flow_hash,ip_src,ip_dst,ip_proto,port_src,port_dst"; // all columns
                if (fout.is_open()) {
                    fout << csv_header << std::endl;
                } else {
                    printf_normal("%s\n", csv_header.c_str());
                }
            }

            // prepare CSV line
            double pkt_percentage = ((double)(conn_top.second.get_packets()) / total_pkts) * 100;
            double bytes_percentage = ((double)(conn_top.second.get_bytes()) / total_bytes) * 100;
            snprintf(csv_line, sizeof(csv_line), "%u,%lu,%.2f,%lu,%.2f,%lX,%s,%s,%d,%d,%d\n",
                nflow,
                conn_top.second.get_packets(),
                pkt_percentage,
                conn_top.second.get_bytes(),
                bytes_percentage,
                conn_top.second.get_flow_info().get_flow_hash(),
                conn_top.second.get_flow_info().m_ip_src.toString().c_str(),
                conn_top.second.get_flow_info().m_ip_dst.toString().c_str(),
                conn_top.second.get_flow_info().m_ip_proto,
                conn_top.second.get_flow_info().m_port_src,
                conn_top.second.get_flow_info().m_port_dst);

            // write output
            if (fout.is_open()) {
                fout << csv_line;
            } else {
                printf_normal("%s", csv_line);
            }
        }
        nflow++;
    }
    if (fout.is_open())
        printf_normal("Written %lu lines in CSV traffic report output file %s.\n", nflow, m_report_outfile.c_str());
    else
        printf_normal("Completed generation of %lu lines of traffic report.\n", nflow);

    // Clear current stats/map
    m_num_input_pkts = 0;
    m_conn_map.clear();

    return true;
}
