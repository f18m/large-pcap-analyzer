/*
 * filter.h
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

typedef enum {
    TCP_FILTER_NOT_ACTIVE,
    TCP_FILTER_CONN_HAVING_SYN,
    TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE,
    TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE_AND_DATA,
} TcpFilterMode;

//------------------------------------------------------------------------------
// FilterCriteria
// Implements all possible filtering mechanisms supported by LPA to decide
// which packets need to be processed/analyzed
//------------------------------------------------------------------------------

class FilterCriteria {
public:
    FilterCriteria()
    {
        memset(&m_capture_filter, 0, sizeof(m_capture_filter));
        memset(&m_gtpu_filter, 0, sizeof(m_gtpu_filter));
        m_capture_filter_set = false;
        m_gtpu_filter_set = false;
        m_valid_tcp_filter_mode = TCP_FILTER_NOT_ACTIVE;
        m_num_gtpu_pkts = 0;
    }

    ~FilterCriteria()
    {
        if (m_capture_filter_set)
            pcap_freecode(&m_capture_filter);
        if (m_gtpu_filter_set)
            pcap_freecode(&m_gtpu_filter);
    }

    bool prepare_filter(const std::string& pcap_filter_str,
        const std::string& gtpu_filter_str,
        const std::string& str_filter,
        TcpFilterMode valid_tcp_filter);

    static bool convert_extract_filter(const std::string& extract_filter,
        std::string& output_pcap_filter);

    // getters

    bool is_some_filter_active() const
    {
        return (m_capture_filter_set || m_gtpu_filter_set || !m_string_filter.empty() || m_valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE);
    }

    bool is_capture_filter_set() const { return m_capture_filter_set; }
    bool is_gtpu_filter_set() const { return m_gtpu_filter_set; }

    // some filtering criteria will be able to decide correctly if a packet is matching/not-matching the filter
    // only by running 2 passes on each input PCAP file
    bool needs_2passes() const
    {
        return m_valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE;
    }

    flow_map_t& flow_map() { return m_valid_tcp_firstpass_flows; }

    // main API
    bool is_matching(const Packet& pkt, bool* is_gtpu);

    bool post_filtering(unsigned long nloaded);

private: // filter configuration
    // BPF filtering on the outer frame:
    struct bpf_program m_capture_filter;
    bool m_capture_filter_set;

    // BPF filtering on the inner frame of GTPu packets:
    struct bpf_program m_gtpu_filter;
    bool m_gtpu_filter_set;

    // text/binary search in packet:
    std::string m_string_filter;

    // TCP filtering:
    TcpFilterMode m_valid_tcp_filter_mode;

private: // filter status
    unsigned long m_num_gtpu_pkts;
    flow_map_t m_valid_tcp_firstpass_flows; // contains the result of the 1st pass
};

#endif // FILTER_H_
