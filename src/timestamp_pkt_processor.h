/*
 * timestamp_pkt_processor.h
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

#ifndef TIMESTAMP_PKT_PROCESSOR_H_
#define TIMESTAMP_PKT_PROCESSOR_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "processor.h"

#include <algorithm>
#include <string>
#include <vector>

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

enum TimestampProcessingModes {
    PROCMODE_NONE,
    PROCMODE_CHANGE_DURATION_RESET_IFG,
    PROCMODE_CHANGE_DURATION_PRESERVE_IFG,
    PROCMODE_SET_TIMESTAMPS
};

//------------------------------------------------------------------------------
// TimestampPacketProcessor
// Packet processor specialized in manipulation of packet timestamps
//------------------------------------------------------------------------------

class TimestampPacketProcessor : public IPacketProcessor {
public:
    TimestampPacketProcessor()
    {
        // config
        m_proc_mode = PROCMODE_NONE;
        m_print_timestamp_analysis = false;
        m_new_duration_secs = 0;

        // status
        m_first_pkt_ts_sec = 0;
        m_last_pkt_ts_sec = 0;
        m_previous_pkt_ts_sec = 0;
        m_num_input_pkts = 0;
        m_nbytes_pcap = 0;
        m_nbytes_original = 0;
    }

    ~TimestampPacketProcessor() { }

    bool prepare_processor(bool print_timestamp_analysis, const std::string& set_duration, bool preserve_ifg, const std::string& timestamp_file);

    virtual bool is_some_processing_active() const
    {
        return m_proc_mode != PROCMODE_NONE;
    }

    // to compute correctly the timestamps in --set-duration mode, we need 2
    // passes: first to find out how many packets are present in the PCAP and then
    // to actually alter timestamps:
    virtual bool needs_2passes() const override
    {
        return m_proc_mode == PROCMODE_CHANGE_DURATION_RESET_IFG || m_proc_mode == PROCMODE_CHANGE_DURATION_PRESERVE_IFG;
    }

    // does
    virtual bool process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx, bool& pktWasChangedOut) override;

    virtual bool post_processing(const std::string& file, unsigned int totNumPkts) override;

protected:
    bool print_timestamp_analysis();

private:
    // configuration:
    TimestampProcessingModes m_proc_mode;
    bool m_print_timestamp_analysis;
    double m_new_duration_secs;
    std::vector<double> m_timestamps; // timestamps loaded from input file, to apply to all packets
    std::string m_timestamps_input_file;

    // status:
    double m_first_pkt_ts_sec;
    double m_last_pkt_ts_sec;
    double m_previous_pkt_ts_sec;
    unsigned long m_num_input_pkts;
    uint64_t m_nbytes_pcap;
    uint64_t m_nbytes_original;
};

#endif // TIMESTAMP_PKT_PROCESSOR_H_
