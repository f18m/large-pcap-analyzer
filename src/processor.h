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

#ifndef PROCESSING_H_
#define PROCESSING_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "large-pcap-analyzer.h"
#include "parse.h"

#include <algorithm>
#include <string>
#include <vector>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

enum AlternativeProcessingModes {
    PROCMODE_NONE,
    PROCMODE_CHANGE_DURATION_RESET_IFG,
    PROCMODE_CHANGE_DURATION_PRESERVE_IFG,
    PROCMODE_SET_TIMESTAMPS
};

//------------------------------------------------------------------------------
// PacketProcessor
//------------------------------------------------------------------------------

class PacketProcessor {
public:
    PacketProcessor()
    {
        m_proc_mode = PROCMODE_NONE;
        m_new_duration_secs = 0;
        m_first_pkt_ts_sec = 0;
        m_last_pkt_ts_sec = 0;
        m_previous_pkt_ts_sec = 0;
        m_num_input_pkts = 0;
        m_current_pass = 0;
    }

    ~PacketProcessor() { }

    bool prepare_processor(const std::string& set_duration, bool preserve_ifg,
        const std::string& timestamp_file);

    bool is_some_processing_active() const
    {
        return m_proc_mode != PROCMODE_NONE;
    }

    // to compute correctly the timestamps in --set-duration mode, we need 2
    // passes: first to find out how many packets are present in the PCAP and then
    // to actually alter timestamps:
    bool needs_2passes() const
    {
        return m_proc_mode == PROCMODE_CHANGE_DURATION_RESET_IFG || m_proc_mode == PROCMODE_CHANGE_DURATION_PRESERVE_IFG;
    }

    void set_pass_index(unsigned int passIdx) { m_current_pass = passIdx; }

    // returns true if the processing is successful or false if it should be
    // aborted. NOTE: pktWasChanged will be set to true if output packet has been
    // filled or false if no action
    //       was performed on the input packet and thus the caller should use the
    //       pktIn instance
    bool process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx,
        bool& pktWasChangedOut);

    bool post_processing(unsigned int totNumPkts);

private:
    // configuration:
    AlternativeProcessingModes m_proc_mode;
    double m_new_duration_secs;
    std::vector<double> m_timestamps;
    std::string m_timestamps_input_file;
    unsigned int m_current_pass; // 0 or 1

    // status:
    double m_first_pkt_ts_sec;
    double m_last_pkt_ts_sec;

    double m_previous_pkt_ts_sec;
    unsigned long m_num_input_pkts;
};

#endif // PROCESSING_H_
