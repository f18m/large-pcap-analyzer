/*
 * process_file.cpp
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 *
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

#include "filter.h"
#include "large-pcap-analyzer.h"
#include "parse.h"
#include "pcap_helpers.h"
#include "printf_helpers.h"
#include "timestamp_pkt_processor.h"

#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/in.h>
#include <netinet/ip.h> /* superset of previous */
#include <netinet/ip6.h>
#include <sys/stat.h>

#include <algorithm>
#include <assert.h>
#include <getopt.h>
#include <signal.h>
#include <sstream>
#include <stdarg.h>
#include <string>
#include <unistd.h>
#include <vector>

//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

static bool
firstpass_process_pcap_handle_for_tcp_streams(pcap_t* pcap_handle_in, FilterCriteria* filter, unsigned long* nvalidflowsOUT)
{
    unsigned long nloaded_pkts = 0, ninvalid_pkts = 0, nnottcp_pkts = 0;
    unsigned long nfound_streams = 0, nsyn_streams = 0, nsyn_synack_streams = 0,
                  nfull3way_streams = 0, nfull3way_with_data_streams = 0;
    struct timeval start, stop;
    const u_char* pcap_packet;
    struct pcap_pkthdr* pcap_header;

    // the output of this function is saved inside the FILTER object:
    filter->flow_map().clear();

    gettimeofday(&start, NULL);
    while (!g_config.m_termination_requested && pcap_next_ex(pcap_handle_in, &pcap_header, &pcap_packet) > 0) {
        Packet pkt(pcap_header, pcap_packet);

        nloaded_pkts++;
        if ((nloaded_pkts % MILLION) == 0 && nloaded_pkts > 0)
            printf_verbose("%luM packets loaded from PCAP...\n",
                nloaded_pkts / MILLION);

        // first, detect if this is a TCP SYN/SYN-ACK packet
        bool is_tcp_syn = false, is_tcp_syn_ack = false, is_tcp_ack = false;
        FlowInfo flow_info;

        int offsetInnerTransport = 0, innerIpProt = 0,
            len_after_transport_start = 0;
        ParserRetCode_t ret = get_gtpu_inner_transport_start_offset(
            pkt, &offsetInnerTransport, &innerIpProt, &len_after_transport_start,
            &flow_info);
        if (ret != GPRC_VALID_PKT) {
            // not a GTPu packet... try treating it as non-encapsulated TCP packet:
            ParserRetCode_t ret = get_transport_start_offset(pkt, &offsetInnerTransport, &innerIpProt,
                &len_after_transport_start, &flow_info);
            if (ret != GPRC_VALID_PKT) {
                offsetInnerTransport = 0;
                innerIpProt = 0;
                ninvalid_pkts++;
                continue;
            }
        }

        if (innerIpProt != IPPROTO_TCP) {
            nnottcp_pkts++;
            continue;
        }

        // then save the state for the TCP connection associated to this packet:

        flow_hash_t hash = flow_info.compute_flow_hash();
        assert(hash != INVALID_FLOW_HASH);
        std::pair<flow_map_t::iterator, bool> result = filter->flow_map().insert(
            std::pair<flow_hash_t /* key */, TcpFlowStatus_t /* value */>(hash,
                FLOW_FOUND));
        if (result.second)
            nfound_streams++; // this stream is a new connection

        const struct tcphdr* tcp = (const struct tcphdr*)(pcap_packet + offsetInnerTransport);
        if (tcp->syn == 1 && tcp->ack == 0)
            is_tcp_syn = true;
        if (tcp->syn == 1 && tcp->ack == 1)
            is_tcp_syn_ack = true;
        if (tcp->syn == 0 && tcp->ack == 1)
            is_tcp_ack = true;

        int transport_hdr_len = 4 * tcp->doff;
        int len_after_transport_end = len_after_transport_start - transport_hdr_len;

        if (is_tcp_syn) {
            assert(!is_tcp_syn_ack);
            assert(!is_tcp_ack);

            // SYN packet found, remember this:

            flow_map_t::iterator entry = filter->flow_map().find(hash);
            if (entry != filter->flow_map().end()) {
                if (entry->second == FLOW_FOUND)
                    nsyn_streams++;

                entry->second = FLOW_FOUND_SYN; // reset status to only SYN found
            }
        } else if (is_tcp_syn_ack) {
            assert(!is_tcp_syn);
            assert(!is_tcp_ack);

            flow_map_t::iterator entry = filter->flow_map().find(hash);
            if (entry != filter->flow_map().end() && entry->second == FLOW_FOUND_SYN) {
                entry->second = FLOW_FOUND_SYN_AND_SYNACK; // existing connection, found
                    // SYN-ACK packet for that
                nsyn_synack_streams++;
            }
        } else if (is_tcp_ack) {
            assert(!is_tcp_syn);
            assert(!is_tcp_syn_ack);

            flow_map_t::iterator entry = filter->flow_map().find(hash);
            if (entry != filter->flow_map().end()) {
                if (entry->second == FLOW_FOUND_SYN_AND_SYNACK) {
                    entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK; // existing connection, found
                        // the 3way handshake for that!
                    nfull3way_streams++;

                    if (len_after_transport_end > 0) {
                        entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA; // existing
                            // connection, found
                            // the 1st data
                            // packet after 3way
                            // handshake
                        nfull3way_with_data_streams++;
                    }
                } else if (entry->second == FLOW_FOUND_SYN_AND_SYNACK_AND_ACK && len_after_transport_end > 0) {
                    entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA; // existing
                        // connection, found
                        // the 1st data packet
                        // after 3way
                        // handshake
                    nfull3way_with_data_streams++;
                }
            }
        } else if (len_after_transport_end > 0) {
            assert(!is_tcp_syn);
            assert(!is_tcp_syn_ack);
            assert(!is_tcp_ack);

            // looks like a TCP data packet: no SYN/ACK flags and there is payload
            // after TCP header

            flow_map_t::iterator entry = filter->flow_map().find(hash);
            if (entry != filter->flow_map().end() && entry->second == FLOW_FOUND_SYN_AND_SYNACK_AND_ACK) {
                entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA; // existing connection,
                    // found the 1st data
                    // packet after 3way
                    // handshake
                nfull3way_with_data_streams++;
            }
        }
    }
    gettimeofday(&stop, NULL);

    printf_verbose("Processing took %i seconds.\n",
        (int)(stop.tv_sec - start.tv_sec));
    printf_verbose("Detected %lu invalid packets and %lu non-TCP packets (on "
                   "total of %lu packets)\n",
        ninvalid_pkts, nnottcp_pkts, nloaded_pkts);

    printf_normal(
        "Detected flows:\n  Having at least 1SYN: %lu\n  Having SYN-SYNACK: "
        "%lu\n  Having full 3way handshake: %lu\n  Having full 3way handshake "
        "and data: %lu\n  Total TCP flows found: %lu\n",
        nsyn_streams, nsyn_synack_streams, nfull3way_streams,
        nfull3way_with_data_streams, nfound_streams);

    if (nvalidflowsOUT)
        *nvalidflowsOUT = nfound_streams;

    return true;
}

static bool process_pcap_handle(
    const std::string& infile,
    pcap_t* pcap_handle_in,
    FilterCriteria* filter, /* can be NULL */
    IPacketProcessor* pktprocessor, /* can be NULL */
    pcap_dumper_t* pcap_dumper, /* can be NULL */
    unsigned long* nloadedOUT,
    unsigned long* nmatchingOUT)
{
    unsigned long nloaded = 0, nmatching = 0, ngtpu = 0, nbytes_avail = 0,
                  nbytes_orig = 0;
    struct timeval start, stop;
    bool first = true;
    ParsingStats parsing_stats;

    const u_char* pcap_packet;
    struct pcap_pkthdr* pcap_header;
    struct pcap_pkthdr first_pcap_header, last_pcap_header;

    memset(&first_pcap_header, 0, sizeof(first_pcap_header));
    memset(&last_pcap_header, 0, sizeof(last_pcap_header));

    std::string pcapfilter_desc = "";
    if (filter && filter->is_capture_filter_set())
        pcapfilter_desc = " (matching PCAP filter)";

    gettimeofday(&start, NULL);
    Packet tempPkt;
    while (!g_config.m_termination_requested && pcap_next_ex(pcap_handle_in, &pcap_header, &pcap_packet) > 0) {
        Packet pkt(pcap_header, pcap_packet);

        if ((nloaded % MILLION) == 0 && nloaded > 0)
            printf_verbose("%luM packets loaded from PCAP%s...\n", nloaded / MILLION,
                pcapfilter_desc.c_str());

        // filter and save to output eventually

        bool is_gtpu = false;
        bool tosave = true;

        if (filter)
            tosave = filter->is_matching(pkt, &is_gtpu);
        // else: filtering disabled, save all packets

        if (tosave) {
            if (pktprocessor) {
                bool pktWasChanged = false;
                if (!pktprocessor->process_packet(pkt, tempPkt,
                        nmatching /* this is the index of the saved packets */,
                        pktWasChanged)) {
                    printf_error("Error while processing packet %lu. Aborting.\n", nmatching);
                    return false;
                }

                if (pktWasChanged) {
                    if (pcap_dumper)
                        pcap_dump((u_char*)pcap_dumper, tempPkt.header(), tempPkt.data());
                } else {
                    // dump original packet
                    if (pcap_dumper)
                        pcap_dump((u_char*)pcap_dumper, pcap_header, pcap_packet);
                }
            } else {
                // no packet processor provided: just dump original packet
                if (pcap_dumper)
                    pcap_dump((u_char*)pcap_dumper, pcap_header, pcap_packet);
            }

            nmatching++;
        }
        if (is_gtpu)
            ngtpu++;

        if (g_config.m_timestamp_analysis) {
            // save timestamps for later analysis:
            if (UNLIKELY(first)) {
                memcpy(&first_pcap_header, pcap_header, sizeof(struct pcap_pkthdr));
                first = false;
            } else
                memcpy(&last_pcap_header, pcap_header, sizeof(struct pcap_pkthdr));
        }

        if (g_config.m_parsing_stats) {
            update_parsing_stats(pkt, parsing_stats);
        }

        // advance main stats counters:

        nbytes_avail += pcap_header->caplen;
        nbytes_orig += pcap_header->len;
        nloaded++;
    }
    gettimeofday(&stop, NULL);

    printf_verbose("Processing took %i seconds.\n", (int)(stop.tv_sec - start.tv_sec));
    printf_normal("%luM packets (%lu packets) were loaded from PCAP%s.\n", nloaded / MILLION, nloaded, pcapfilter_desc.c_str());

    if (filter) {
        if (!filter->post_filtering(nloaded))
            return false;
    }

    if (pktprocessor) {
        if (!pktprocessor->post_processing(infile, nloaded))
            return false;
    }

    if (pcap_dumper) {
        if (filter && filter->is_some_filter_active()) {
            printf_normal("%luM packets (%lu packets) matched the filtering criteria "
                          "(search string / PCAP filters / TCP streams filter) and "
                          "were saved into output PCAP.\n",
                nmatching / MILLION, nmatching);
        } else if (filter && !filter->is_some_filter_active()) {
            assert(nmatching == 0);
            printf_normal("No criteria for packet selection specified (search string "
                          "/ GTPu filter / TCP streams filter) so nothing was "
                          "written into output PCAP.\n");
        } else if (pktprocessor) {
            printf_normal("%luM packets (%lu packets) were processed and saved into output PCAP.\n",
                nmatching / MILLION, nmatching);
        }
    }

    // FIXME: move into TimestampPacketProcessor::post_processing():
    if (g_config.m_timestamp_analysis) {
        if (!Packet::pcap_timestamp_is_valid(&first_pcap_header) && !Packet::pcap_timestamp_is_valid(&last_pcap_header)) {
            printf_normal("Apparently both the first and last packet packets of the PCAP have no valid timestamp... cannot compute PCAP duration.\n");
            return false;
        }

        if (!Packet::pcap_timestamp_is_valid(&last_pcap_header) && nloaded == 1) {

            // corner case: PCAP with just 1 packet... duration is zero by definition:

            if (g_config.m_quiet)
                printf_quiet("0\n"); // be machine-friendly and indicate an error
            else
                printf_normal("The PCAP contains just 1 packet: duration is zero.\n");
        } else {

            double secStart = Packet::pcap_timestamp_to_seconds(&first_pcap_header);
            double secStop = Packet::pcap_timestamp_to_seconds(&last_pcap_header);
            double sec = secStop - secStart;
            if (secStart < SMALL_NUM && secStop == SMALL_NUM) {
                if (g_config.m_quiet)
                    printf_quiet("-1\n"); // be machine-friendly and indicate an error
                else
                    printf_normal("Apparently the packets of the PCAP have no valid timestamp... cannot compute PCAP duration.\n");

                return false;
            }

            if (g_config.m_quiet)
                printf_quiet("%f\n", sec); // be machine-friendly
            else
                printf_normal("Last packet has a timestamp offset = %.2fsec = %.2fmin = %.2fhours\n",
                    sec, sec / 60.0, sec / 3600.0);

            printf_verbose("Bytes loaded from PCAP = %lukiB = %luMiB; total bytes on wire = %lukiB = %luMiB\n",
                nbytes_avail / KB, nbytes_avail / MB, nbytes_orig / KB, nbytes_orig / MB);
            if (nbytes_avail == nbytes_orig)
                printf_verbose("  => all packets in the PCAP have been captured WITHOUT truncation.\n");

            if (sec > 0) {
                printf_normal("Tcpreplay should replay this PCAP at an average of %.2fMbps / %.2fpps to respect PCAP timings.\n",
                    (float)(8 * nbytes_avail / MB) / sec, (float)nloaded / sec);
            } else {
                printf_normal("Cannot compute optimal tcpreplay speed for replaying: duration is null or negative.\n");
                return false;
            }
        }
    }

    if (g_config.m_parsing_stats) {
        if (g_config.m_quiet) {
            // be machine-friendly: use CSV format
            printf_quiet(
                "GTPu pkts with valid inner transport,GTPu pkts with valid inner "
                "IP,Pkts with valid transport,Pkts with valid IP,Pkts invalid\n");
            printf_quiet(
                "%lu,%lu,%lu,%lu,%lu\n", parsing_stats.pkts_valid_gtpu_transport,
                parsing_stats.pkts_valid_gtpu_ip, parsing_stats.pkts_valid_tranport,
                parsing_stats.pkts_valid_ip, parsing_stats.pkts_invalid);
        } else {
            printf_normal("Parsing stats: %.2f%% GTPu with valid inner transport, "
                          "%.2f%% GTPu with valid inner IP, %.2f%% with valid "
                          "transport, %.2f%% with valid IP, %.2f%% invalid.\n",
                parsing_stats.perc_pkts_valid_gtpu_transport(),
                parsing_stats.perc_pkts_valid_gtpu_ip(),
                parsing_stats.perc_pkts_valid_tranport(),
                parsing_stats.perc_pkts_valid_ip(),
                parsing_stats.perc_pkts_invalid());
        }
    }

    // provide output info
    if (nloadedOUT)
        *nloadedOUT += nloaded;
    if (nmatchingOUT)
        *nmatchingOUT += nmatching;

    return true;
}

//------------------------------------------------------------------------------
// process_file
//------------------------------------------------------------------------------

bool process_file(
    const std::string& infile, const std::string& outfile, bool outfile_append, FilterCriteria* filter,
    IPacketProcessor* pktprocessor, unsigned long* nloadedOUT, unsigned long* nmatchingOUT)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle_in = NULL;
    pcap_dumper_t* pcap_dumper = NULL;

    struct stat st;
    memset(&st, 0, sizeof(st));
    stat(infile.c_str(), &st);

    // open infile
    pcap_handle_in = pcap_open_offline(infile.c_str(), pcap_errbuf);
    if (pcap_handle_in == NULL) {
        printf_error("Cannot open file: %s\n", pcap_errbuf);
        return false;
    }
    printf_verbose("Analyzing PCAP file '%s'...\n", infile.c_str());
    if (st.st_size)
        printf_verbose("The PCAP file has size %.2fGiB = %luMiB.\n", (double)st.st_size / (double)GB, st.st_size / MB);

    // open outfile
    if (!outfile.empty()) {
        if (outfile_append) {
            // NOTE: the PCAP produced by appending cannot be opened correctly by
            // Wireshark in some cases...

            pcap_dumper = pcap_dump_append(pcap_handle_in, outfile.c_str());
            if (pcap_dumper == NULL)
                return false;

            printf_normal("Successfully opened output PCAP '%s' in APPEND mode\n",
                outfile.c_str());
        } else {
            // NOTE: the pcap_dump_open() seems to open always PCAP files with the MAGIC 0xa1b2c3d4
            //       that indicates MICROSECOND timestamp accuracy; see
            //       https://wiki.wireshark.org/Development/LibpcapFileFormat#nanosecond-pcap
            pcap_dumper = pcap_dump_open(pcap_handle_in, outfile.c_str());
            if (!pcap_dumper) {
                printf_error("Cannot open file: %s\n", pcap_geterr(pcap_handle_in));
                return false;
            }
            printf_normal("Successfully opened output PCAP '%s'\n", outfile.c_str());
        }
    }

    // do the real job

    if (filter->needs_2passes()) {
        // special mode: this requires 2 pass over the PCAP file: first one to get
        // hash values for valid FLOWS; second one to actually filter all flows with
        // valid hashes

        // first pass:
        printf_normal("TCP connection filtering enabled: performing first pass\n");

        unsigned long nvalidflows = 0;
        if (!firstpass_process_pcap_handle_for_tcp_streams(pcap_handle_in, filter, &nvalidflows))
            return false;

        if (nvalidflows) {
            // second pass:

            printf_normal("TCP connection filtering enabled: performing second pass\n");

            // reopen infile
            pcap_close(pcap_handle_in);
            pcap_handle_in = pcap_open_offline(infile.c_str(), pcap_errbuf);
            if (pcap_handle_in == NULL) {
                printf_error("Cannot open file: %s\n", pcap_errbuf);
                return false;
            }

            printf_verbose("Analyzing PCAP file '%s'...\n", infile.c_str());
            if (st.st_size)
                printf_verbose("The PCAP file has size %.2fGiB = %luMiB.\n", (double)st.st_size / (double)GB, st.st_size / MB);

            if (!process_pcap_handle(infile.c_str(), pcap_handle_in, filter, pktprocessor, pcap_dumper, nloadedOUT, nmatchingOUT))
                return false;
        } else {
            return false;
        }
    } else {
        // if no filtering is given, but we want to process output packets, then we
        // invert the selection criteria: by default each packet of the input will
        // be processed (by default an empty FilterCriteria instance would instead
        // discard ALL packets!)
        FilterCriteria* filterToUse = filter;
        if (!filter->is_some_filter_active()) {
            printf_verbose("Selected some packet processing operation but no filter was specified: processing ALL input packets\n");
            filterToUse = NULL; // disable filter-out logic
        }

        if (pktprocessor && pktprocessor->needs_2passes()) {
            // first pass
            printf_normal("Packet processing require 2 passes: performing first pass\n");
            unsigned long nFilteredPkts = 0;
            pktprocessor->set_pass_index(0);
            if (!process_pcap_handle(infile.c_str(), pcap_handle_in, filterToUse, pktprocessor, NULL, NULL, &nFilteredPkts))
                return false;

            if (nFilteredPkts) {
                printf_normal("Packet processing require 2 passes: performing second pass\n");

                // reopen infile
                pcap_close(pcap_handle_in);
                pcap_handle_in = pcap_open_offline(infile.c_str(), pcap_errbuf);
                if (pcap_handle_in == NULL) {
                    printf_error("Cannot open file: %s\n", pcap_errbuf);
                    return false;
                }

                // re-process this time with PROCESSOR and OUTPUT DUMPER active!
                pktprocessor->set_pass_index(1);
                if (!process_pcap_handle(infile.c_str(), pcap_handle_in, filterToUse, pktprocessor, pcap_dumper, nloadedOUT, nmatchingOUT))
                    return false;
            }
        } else {
            // standard mode: do all the processing in 1 pass

            if (!process_pcap_handle(infile.c_str(), pcap_handle_in, filterToUse, pktprocessor, pcap_dumper, nloadedOUT, nmatchingOUT))
                return false;
        }
    }

    // cleanup
    if (!outfile.empty())
        pcap_dump_close(pcap_dumper);
    pcap_close(pcap_handle_in);

    return true;
}
