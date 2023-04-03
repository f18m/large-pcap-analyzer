/*
 * processor.cpp
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

#include "timestamp_pkt_processor.h"
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

bool String2TimestampInSecs(const std::string& str, double& result)
{
    std::stringstream ss(str);
    if (!(ss >> result)) {
        return false;
    }

    return true;
}

//------------------------------------------------------------------------------
// TimestampPacketProcessor
//------------------------------------------------------------------------------

bool TimestampPacketProcessor::prepare_processor(const std::string& set_duration, bool preserve_ifg, const std::string& timestamp_file)
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
            m_new_duration_secs = atof(set_duration.c_str());
        } else if (num_dots == 0 && num_colons == 0) {
            // FIRST SYNTAX FORMAT WITHOT FRACTIONAL SECS
            m_new_duration_secs = atoi(set_duration.c_str());
        } else if (num_dots <= 1 && num_colons == 2 && set_duration.size() >= 8 /* chars */ && set_duration[2] == ':' && set_duration[5] == ':') {

            // SECOND SYNTAX FORMAT
            int hh = atoi(set_duration.substr(0, 2).c_str());
            int mm = atoi(set_duration.substr(3, 5).c_str());
            double ss = atof(set_duration.substr(6).c_str());

            m_new_duration_secs = hh * 3600 + mm * 60 + ss;

        } else {
            printf_error("Cannot parse PCAP duration to set: %s\n",
                set_duration.c_str());
            return false;
        }

        if (preserve_ifg)
            m_proc_mode = PROCMODE_CHANGE_DURATION_PRESERVE_IFG;
        else
            m_proc_mode = PROCMODE_CHANGE_DURATION_RESET_IFG;
        printf_verbose("PCAP duration will be set to: %f secs (IFG will be %s)\n",
            m_new_duration_secs, preserve_ifg ? "preserved" : "reset");
    } else if (!timestamp_file.empty()) {
        // validate input file:

        m_timestamps_input_file = timestamp_file;
        std::ifstream infile(timestamp_file);
        if (infile.good()) {
            printf_normal("Successfully opened input timings file '%s'\n",
                timestamp_file.c_str());
        } else {
            printf_error("Cannot open the file with packet timings '%s'\n",
                timestamp_file.c_str());
            return false;
        }

        size_t lineIdx = 0;
        std::string line;
        double ts;
        while (std::getline(infile, line)) {
            if (line.empty()) {
                // give 1-based line index:
                printf_error(
                    "Invalid empty line %d in the file with packet timings '%s'\n",
                    lineIdx + 1, timestamp_file.c_str());
                return false;
            }
            if (!String2TimestampInSecs(line, ts)) {
                // give 1-based line index:
                printf_error("Invalid timestamp at line %d in the file with packet "
                             "timings '%s': %s\n",
                    lineIdx + 1, timestamp_file.c_str(), line.c_str());
                return false;
            }
            m_timestamps.push_back(ts);
            lineIdx++;
        }

        m_proc_mode = PROCMODE_SET_TIMESTAMPS;
        printf_verbose("%zu timestamps loaded from '%s'\n", m_timestamps.size(),
            timestamp_file.c_str());
    }

    return true;
}

bool TimestampPacketProcessor::process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx, bool& pktWasChangedOut)
{
    pktWasChangedOut = false; // by default: no proc done, use original packet

    switch (m_proc_mode) {
    case PROCMODE_NONE: {
        pktWasChangedOut = false; // no proc done, use original packet
    } break;

    case PROCMODE_CHANGE_DURATION_RESET_IFG:
    case PROCMODE_CHANGE_DURATION_PRESERVE_IFG: {
        if (IPacketProcessor::get_pass_index() == 0) {
            // in the first pass just count the number of packets to process &
            // remember the timestamp of the last packet:
            m_num_input_pkts++;
            m_last_pkt_ts_sec = pktIn.pcap_timestamp_to_seconds();
        } else // second pass
        {
            assert(m_new_duration_secs > 0);
            assert(m_num_input_pkts > 0);

            // it's not always garantueed that the timestamp of the last packet is valid; indeed the user might
            // be trying to rewrite timestamps in an invalid PCAP file (having wrong timestamps) for which the libpcap
            // is returning 0 as timestamp
            //assert(m_last_pkt_ts_sec > 0);

            if (pktIdx == 0) {
                assert(m_first_pkt_ts_sec == 0);
                m_first_pkt_ts_sec = pktIn.pcap_timestamp_to_seconds();

                printf_verbose("First pkt timestamp is %f and there are %zu pkts; target duration is %f\n",
                    m_first_pkt_ts_sec, m_num_input_pkts, m_new_duration_secs);

                if (m_first_pkt_ts_sec == 0) {
                    printf_error(
                        "WARNING: invalid timestamp set to zero (Thursday, 1 January 1970 00:00:00) for the first packet. This is unusual and typically indicates an invalid PCAP file.\n");

                    // make sure we set the timestamp to ZERO since the incoming packet has probably invalid timestamp:
                    pktOut.copy(pktIn.header(), pktIn.data());
                    pktOut.set_timestamp_from_seconds(m_first_pkt_ts_sec);
                    pktWasChangedOut = true;

                } else {
                    pktWasChangedOut = false; // no proc done, use original packet
                }

            } else {
                double thisPktTs = 0;

                if (m_proc_mode == PROCMODE_CHANGE_DURATION_RESET_IFG) {
                    double secInterPktGap = m_new_duration_secs / m_num_input_pkts;
                    thisPktTs = m_first_pkt_ts_sec + secInterPktGap * (pktIdx + 1);
                } else // PROCMODE_CHANGE_DURATION_PRESERVE_IFG
                {
                    double originalDuration = m_last_pkt_ts_sec - m_first_pkt_ts_sec; // constant for the whole PCAP of course
                    double pktTsOffsetSincePcapStart = pktIn.pcap_timestamp_to_seconds() - m_first_pkt_ts_sec;

                    double newPktOffsetSincePcapStart = pktTsOffsetSincePcapStart * (m_new_duration_secs / originalDuration);
                    thisPktTs = m_first_pkt_ts_sec + newPktOffsetSincePcapStart;

                    // printf_verbose("pkt %u: original ts=%f, currentIFG=%f\n",
                    // m_first_pkt_ts_sec, m_num_input_pkts, m_new_duration_secs);
                }

                pktOut.copy(pktIn.header(), pktIn.data());
                pktOut.set_timestamp_from_seconds(thisPktTs);
                pktWasChangedOut = true;
            }

            m_previous_pkt_ts_sec = pktIn.pcap_timestamp_to_seconds();
        }
    } break;

    case PROCMODE_SET_TIMESTAMPS: {
        if (pktIdx >= m_timestamps.size()) {
            printf_error(
                "Too few timestamps specified in the file with timestamps '%s': "
                "found %zu but input PCAP has more than %zu packets.\n",
                m_timestamps_input_file.c_str(), m_timestamps.size(),
                m_timestamps.size());
            return false; // abort processing!
        }

        pktOut.copy(pktIn.header(), pktIn.data());
        pktOut.set_timestamp_from_seconds(m_timestamps[pktIdx]);

        pktWasChangedOut = true;
    } break;

    default:
        assert(0);
        return false;
    }

    return true;
}

bool TimestampPacketProcessor::post_processing(unsigned int totNumPkts)
{
    switch (m_proc_mode) {
    case PROCMODE_NONE:
    case PROCMODE_CHANGE_DURATION_RESET_IFG:
    case PROCMODE_CHANGE_DURATION_PRESERVE_IFG:
        return true; // no error

    case PROCMODE_SET_TIMESTAMPS: {
        if (totNumPkts < m_timestamps.size()) {
            printf_error("Too many timestamps specified in the file with timestamps '%s': %zu but input PCAP has %zu packets.\n",
                m_timestamps_input_file.c_str(), m_timestamps.size(),
                totNumPkts);
            return false;
        }

        return true;
    } break;

    default:
        assert(0);
        return false;
    }
}
