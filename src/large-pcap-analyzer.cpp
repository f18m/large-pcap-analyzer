/*
 * large-pcap-analyzer.cpp
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 * Created: Nov 2014
 * Last Modified: June 2018
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

#include "large-pcap-analyzer.h"
#include "parse.h"
#include "filter.h"
#include "processor.h"
#include "pcap_helpers.h"

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* superset of previous */
#include <linux/udp.h>
#include <linux/tcp.h>

#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <string>


//------------------------------------------------------------------------------
// Globals
//------------------------------------------------------------------------------

bool g_verbose = false;
bool g_quiet = false;
bool g_timestamp_analysis = false;
bool g_parsing_stats = false;
bool g_termination_requested = false;

static struct option g_long_options[] = {

	// misc options
	{"help",              no_argument,       0,  'h' },
	{"verbose",           no_argument,       0,  'v' },
	{"quiet",             no_argument,       0,  'q' },
	{"timing",            no_argument,       0,  't'},
	{"stats",             no_argument,       0,  'p'},
	{"append",            no_argument,       0,  'a'},
	{"write",             required_argument, 0,  'w' },

	// filters
	{"display-filter",    required_argument, 0,  'Y' },
	{"inner-filter",      required_argument, 0,  'G' },
	{"connection-filter", required_argument, 0,  'C' },
	{"string-filter",     required_argument, 0,  'S' },
	{"tcp-filter",        required_argument, 0,  'T' },

	// processing options
	{"set-duration",      required_argument, 0,  'D' },

	{0,                   0,                 0,  0 }
};

#define SHORT_OPTS		"hvqtpaw:Y:G:C:S:T:"


//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

void printf_verbose(const char *fmtstr, ...)
{
	va_list args;
	va_start(args, fmtstr);
	if (g_verbose)
	{
		assert(!g_quiet);
		vprintf(fmtstr, args);
	}
	va_end(args);
}

void printf_normal(const char *fmtstr, ...)
{
	va_list args;
	va_start(args, fmtstr);
	if (!g_quiet)
		vprintf(fmtstr, args);
	va_end(args);
}

void printf_quiet(const char *fmtstr, ...)
{
	va_list args;
	va_start(args, fmtstr);
	if (g_quiet)
		vprintf(fmtstr, args);
	va_end(args);
}

void printf_error(const char *fmtstr, ...)
{
	va_list args;
	va_start(args, fmtstr);
	if (g_quiet)
		vfprintf(stderr, fmtstr, args);
	va_end(args);
}

//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

static void print_help()
{
	printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
	printf("by Francesco Montorsi, (c) 2014-2018\n");
	printf("Usage:\n");
	printf("  %s [options] somefile.pcap ...\n", PACKAGE_NAME);
	printf("Miscellaneous options:\n");
	printf(" -h,--help                this help\n");
	printf(" -v,--verbose             be verbose\n");
	printf(" -q,--quiet               suppress all normal output, be script-friendly\n");
	printf(" -t,--timing              provide timestamp analysis on loaded packets\n");
	printf(" -p,--stats               provide basic parsing statistics on loaded packets\n");
	printf(" -a,--append              open output file in APPEND mode instead of TRUNCATE\n");
	printf(" -w <outfile.pcap>\n");
	printf(" --write <outfile.pcap>   where to save the PCAP containing the results of filtering\n");
	printf("Filtering options (to select packets to save in outfile.pcap):\n");
	printf(" -Y <tcpdump_filter>, --display-filter <tcpdump_filter>\n");
	printf("                          the PCAP filter to apply on packets (will be applied on outer IP frames for GTPu pkts)\n");
	printf(" -G <gtpu_tcpdump_filter>, --inner-filter <gtpu_tcpdump_filter>\n");
	printf("                          the PCAP filter to apply on inner/encapsulated GTPu frames (or outer IP frames for non-GTPu pkts)\n");
	printf(" -C <conn_filter>, --connection-filter <conn_filter>\n");
	printf("                          4-tuple identifying a connection to filter; syntax is 'IP1:port1 IP2:port2'\n");
	printf(" -S <search-string>, --string-filter <search-string>\n");
	printf("                          a string filter that will be searched inside loaded packets\n");
	printf(" -T <syn|full3way|full3way-data>, --tcp-filter  <syn|full3way|full3way-data>\n");
	printf("                          filter for entire TCP connections having \n");
	printf("                            -T syn: at least 1 SYN packet\n");
	printf("                            -T full3way: the full 3way handshake\n");
	printf("                            -T full3way-data: the full 3way handshake and data packets\n");
	printf("Processing options (changes that will be done on packets selected for output):\n");
	printf(" --set-duration <HH:MM:SS>\n");
	printf("                          alters packet timestamps so that the time difference between first and last packet\n");
	printf("                          matches the given amount of time. All packets in the middle will be equally spaced in time.\n");
	printf("Inputs:\n");
	printf(" somefile.pcap            the large PCAP to analyze (you can provide more than 1 file)\n");
	printf("\n");
	printf("Note that the -Y and -G options accept filters expressed in tcpdump/pcap_filters syntax.\n");
	printf("See http://www.manpagez.com/man/7/pcap-filter/ for more info.\n");
	printf("Other PCAP utilities you may be looking for are:\n");
	printf(" * mergecap: to merge PCAP files\n");
	printf(" * tcpdump: can be used to split PCAP files (and more)\n");
	printf(" * editcap: can be used to manipulate timestamps in PCAP files (and more)\n");
	printf(" * tcprewrite: can be used to rewrite some packet fields in PCAP files (and more)\n");
	exit(0);
}

static bool firstpass_process_pcap_handle_for_tcp_streams(pcap_t* pcap_handle_in, FilterCriteria* filter, unsigned long* nvalidflowsOUT)
{
	unsigned long nloaded_pkts = 0, ninvalid_pkts = 0, nnottcp_pkts = 0;
	unsigned long nfound_streams = 0, nsyn_streams = 0, nsyn_synack_streams = 0, nfull3way_streams = 0, nfull3way_with_data_streams = 0;
	struct timeval start, stop;
	const u_char *pcap_packet;
	struct pcap_pkthdr *pcap_header;

	// the output of this function is saved inside the FILTER object:
	filter->valid_tcp_firstpass_flows.clear();

	gettimeofday(&start, NULL);
	while (!g_termination_requested && pcap_next_ex(pcap_handle_in, &pcap_header, &pcap_packet) > 0)
	{
		Packet pkt(pcap_header, pcap_packet);

		nloaded_pkts++;
		if ((nloaded_pkts % MILLION) == 0 && nloaded_pkts > 0)
			printf_verbose("%luM packets loaded from PCAP...\n", nloaded_pkts/MILLION);


		// first, detect if this is a TCP SYN/SYN-ACK packet
		flow_hash_t hash=INVALID_FLOW_HASH;
		bool is_tcp_syn=false, is_tcp_syn_ack=false, is_tcp_ack=false;

		int offsetInnerTransport = 0, innerIpProt = 0, len_after_transport_start = 0;
		ParserRetCode_t ret = get_gtpu_inner_transport_start_offset(pkt, &offsetInnerTransport, &innerIpProt, &len_after_transport_start, &hash);
		if (ret != GPRC_VALID_PKT)
		{
			// not a GTPu packet...try treating it as non-encapsulated TCP packet:
			ParserRetCode_t ret = get_transport_start_offset(pkt, &offsetInnerTransport, &innerIpProt, &len_after_transport_start, &hash);
			if (ret != GPRC_VALID_PKT)
			{
				offsetInnerTransport = 0;
				innerIpProt = 0;
				hash=INVALID_FLOW_HASH;
				ninvalid_pkts++;
				continue;
			}
		}

		if (innerIpProt != IPPROTO_TCP)
		{
			nnottcp_pkts++;
			continue;
		}


		// then save the state for the TCP connection associated to this packet:

		assert(hash!=INVALID_FLOW_HASH);
		std::pair<flow_map_t::iterator,bool> result =
				filter->valid_tcp_firstpass_flows.insert( std::pair<flow_hash_t /* key */, FlowStatus_t /* value */>(hash, FLOW_FOUND) );
		if (result.second)
			nfound_streams++;		// this stream is a new connection


		const struct tcphdr* tcp = (const struct tcphdr*)(pcap_packet + offsetInnerTransport);
		if (tcp->syn == 1 && tcp->ack == 0)
			is_tcp_syn=true;
		if (tcp->syn == 1 && tcp->ack == 1)
			is_tcp_syn_ack=true;
		if (tcp->syn == 0 && tcp->ack == 1)
			is_tcp_ack=true;

		int transport_hdr_len = 4*tcp->doff;
		int len_after_transport_end = len_after_transport_start - transport_hdr_len;

		if (is_tcp_syn)
		{
			assert(!is_tcp_syn_ack);
			assert(!is_tcp_ack);

			// SYN packet found, remember this:

			flow_map_t::iterator entry = filter->valid_tcp_firstpass_flows.find(hash);
			if (entry != filter->valid_tcp_firstpass_flows.end())
			{
				if (entry->second == FLOW_FOUND)
					nsyn_streams++;

				entry->second = FLOW_FOUND_SYN;		// reset status to only SYN found
			}
		}
		else if (is_tcp_syn_ack)
		{
			assert(!is_tcp_syn);
			assert(!is_tcp_ack);

			flow_map_t::iterator entry = filter->valid_tcp_firstpass_flows.find(hash);
			if (entry != filter->valid_tcp_firstpass_flows.end() &&
					entry->second == FLOW_FOUND_SYN)
			{
				entry->second = FLOW_FOUND_SYN_AND_SYNACK;		// existing connection, found SYN-ACK packet for that
				nsyn_synack_streams++;
			}
		}
		else if (is_tcp_ack)
		{
			assert(!is_tcp_syn);
			assert(!is_tcp_syn_ack);

			flow_map_t::iterator entry = filter->valid_tcp_firstpass_flows.find(hash);
			if (entry != filter->valid_tcp_firstpass_flows.end())
			{
				if (entry->second == FLOW_FOUND_SYN_AND_SYNACK)
				{
					entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK;		// existing connection, found the 3way handshake for that!
					nfull3way_streams++;

					if (len_after_transport_end > 0)
					{
						entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA;		// existing connection, found the 1st data packet after 3way handshake
						nfull3way_with_data_streams++;
					}
				}
				else if (entry->second == FLOW_FOUND_SYN_AND_SYNACK_AND_ACK &&
						len_after_transport_end > 0)
				{
					entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA;		// existing connection, found the 1st data packet after 3way handshake
					nfull3way_with_data_streams++;
				}
			}
		}
		else if (len_after_transport_end > 0)
		{
			assert(!is_tcp_syn);
			assert(!is_tcp_syn_ack);
			assert(!is_tcp_ack);

			// looks like a TCP data packet: no SYN/ACK flags and there is payload after TCP header

			flow_map_t::iterator entry = filter->valid_tcp_firstpass_flows.find(hash);
			if (entry != filter->valid_tcp_firstpass_flows.end() &&
					entry->second == FLOW_FOUND_SYN_AND_SYNACK_AND_ACK)
			{
				entry->second = FLOW_FOUND_SYN_AND_SYNACK_AND_ACK_AND_DATA;		// existing connection, found the 1st data packet after 3way handshake
				nfull3way_with_data_streams++;
			}
		}
	}
	gettimeofday(&stop, NULL);

	printf_verbose("Processing took %i seconds.\n", (int) (stop.tv_sec - start.tv_sec));
	printf_verbose("Detected %lu invalid packets and %lu non-TCP packets (on total of %lu packets)\n",
					ninvalid_pkts, nnottcp_pkts, nloaded_pkts);

	printf_normal("Detected flows:\n  Having at least 1SYN: %lu\n  Having SYN-SYNACK: %lu\n  Having full 3way handshake: %lu\n  Having full 3way handshake and data: %lu\n  Total TCP flows found: %lu\n",
			nsyn_streams, nsyn_synack_streams, nfull3way_streams, nfull3way_with_data_streams, nfound_streams);

	if (nvalidflowsOUT)
		*nvalidflowsOUT = nfound_streams;

	return true;
}


static bool process_pcap_handle(pcap_t* pcap_handle_in,
									const FilterCriteria* filter, /* can be NULL */
									PacketProcessor* processorcfg, /* can be NULL */
									pcap_dumper_t* pcap_dumper,
									unsigned long* nloadedOUT, unsigned long* nmatchingOUT)
{
	unsigned long nloaded = 0, nmatching = 0, ngtpu = 0, nbytes_avail = 0, nbytes_orig = 0;
	struct timeval start, stop;
	bool first = true;
	ParsingStats parsing_stats;

	const u_char *pcap_packet;
	struct pcap_pkthdr *pcap_header;
	struct pcap_pkthdr first_pcap_header, last_pcap_header;

	std::string pcapfilter_desc = "";
	if (filter && filter->is_capture_filter_set())
		pcapfilter_desc = " (matching PCAP filter)";

	gettimeofday(&start, NULL);
	Packet tempPkt;
	while (!g_termination_requested && pcap_next_ex(pcap_handle_in, &pcap_header, &pcap_packet) > 0)
	{
		Packet pkt(pcap_header, pcap_packet);

		if ((nloaded % MILLION) == 0 && nloaded > 0)
			printf_verbose("%luM packets loaded from PCAP%s...\n", nloaded/MILLION, pcapfilter_desc.c_str());


		// filter and save to output eventually

		bool is_gtpu = false;
		bool tosave = true;

		if (filter)
			tosave = filter->must_be_saved(pkt, &is_gtpu);
		//else: filtering disabled, save all packets

		if (tosave) {
			if (processorcfg && processorcfg->process_packet(pkt, tempPkt, nmatching /* this is the index of the saved packets */))
			{
				if (pcap_dumper)
					pcap_dump((u_char *) pcap_dumper, tempPkt.header(), tempPkt.data());
			}
			else
			{
				// dump original packet
				if (pcap_dumper)
					pcap_dump((u_char *) pcap_dumper, pcap_header, pcap_packet);
			}
			nmatching++;
		}
		if (is_gtpu)
			ngtpu++;


		if (g_timestamp_analysis)
		{
			// save timestamps for later analysis:
			if (UNLIKELY( first ))
			{
				memcpy(&first_pcap_header, pcap_header, sizeof(struct pcap_pkthdr));
				first = false;
			}
			else
				memcpy(&last_pcap_header, pcap_header, sizeof(struct pcap_pkthdr));
		}

		if (g_parsing_stats)
		{
			update_parsing_stats(pkt, parsing_stats);
		}


		// advance main stats counters:

		nbytes_avail += pcap_header->caplen;
		nbytes_orig += pcap_header->len;
		nloaded++;
	}
	gettimeofday(&stop, NULL);


	printf_verbose("Processing took %i seconds.\n", (int) (stop.tv_sec - start.tv_sec));
	printf_normal("%luM packets (%lu packets) were loaded from PCAP%s.\n", nloaded/MILLION, nloaded, pcapfilter_desc.c_str());

	if (filter && filter->is_gtpu_filter_set())
		// in this case, the GTPu parser was run and we have a stat about how many packets are GTPu
		printf_verbose("%luM packets (%lu packets) loaded from PCAP%s are GTPu packets (%.1f%%).\n",
						ngtpu/MILLION, ngtpu, pcapfilter_desc.c_str(), (double)(100.0*(double)(ngtpu)/(double)(nloaded)));

	if (pcap_dumper)
	{
		if (filter && filter->is_some_filter_active())
		{
			printf_normal("%luM packets (%lu packets) matched the filtering criteria (search string / PCAP filters / TCP streams filter) and were saved into output PCAP.\n",
					nmatching/MILLION, nmatching);
		}
		else if (filter && !filter->is_some_filter_active())
		{
			assert(nmatching == 0);
			printf_normal("No criteria for packet selection specified (search string / GTPu filter / TCP streams filter) so nothing was written into output PCAP.\n");
		}
		else if (processorcfg)
		{
			printf_normal("%luM packets (%lu packets) were processed and saved into output PCAP.\n",
					nmatching/MILLION, nmatching);
		}
	}

	if (g_timestamp_analysis)
	{
		double secStart = Packet::pcap_timestamp_to_seconds(&first_pcap_header);
		double secStop = Packet::pcap_timestamp_to_seconds(&last_pcap_header);
		double sec = secStop - secStart;
		if (secStart < SMALL_NUM && secStop == SMALL_NUM)
		{
			printf_normal("Apparently the packets of the PCAP have no valid timestamp... cannot compute PCAP duration.\n");
		}
		else
		{
			if (g_quiet)
				printf_quiet("%f\n",sec);		// be machine-friendly
			else
				printf_normal("Last packet has a timestamp offset = %.2fsec = %.2fmin = %.2fhours\n",
							sec, sec/60.0, sec/3600.0);
		}

		printf_verbose("Bytes loaded from PCAP = %lukiB = %luMiB; total bytes on wire = %lukiB = %luMiB\n",
			   nbytes_avail/KB, nbytes_avail/MB, nbytes_orig/KB, nbytes_orig/MB);
		if (nbytes_avail == nbytes_orig)
			printf_verbose("  => all packets in the PCAP have been captured WITHOUT truncation.\n");

		if (sec)
		{
			printf_normal("Tcpreplay should replay this PCAP at an average of %.2fMbps / %.2fpps to respect PCAP timings.\n",
				  (float)(8*nbytes_avail/MB)/sec, (float)nloaded/sec);
		}
		else
		{
			printf_normal("Cannot compute optimal tcpreplay speed for replaying: duration is 0sec.\n");
		}
	}

	if (g_parsing_stats)
	{
		if (g_quiet)
		{
			// be machine-friendly: use CSV format
			printf_quiet("GTPu pkts with valid inner transport,GTPu pkts with valid inner IP,Pkts with valid transport,Pkts with valid IP,Pkts invalid\n");
			printf_quiet("%lu,%lu,%lu,%lu,%lu\n",
							parsing_stats.pkts_valid_gtpu_transport,
							parsing_stats.pkts_valid_gtpu_ip,
							parsing_stats.pkts_valid_tranport,
							parsing_stats.pkts_valid_ip,
							parsing_stats.pkts_invalid);
		}
		else
		{
			printf_normal("Parsing stats: %.2f%% GTPu with valid inner transport, %.2f%% GTPu with valid inner IP, %.2f%% with valid transport, %.2f%% with valid IP, %.2f%% invalid.\n",
					parsing_stats.perc_pkts_valid_gtpu_transport(),
					parsing_stats.perc_pkts_valid_gtpu_ip(),
					parsing_stats.perc_pkts_valid_tranport(),
					parsing_stats.perc_pkts_valid_ip(),
					parsing_stats.perc_pkts_invalid());
		}
	}

	// provide output info
	if (nloadedOUT) *nloadedOUT += nloaded;
	if (nmatchingOUT) *nmatchingOUT += nmatching;

	return true;
}

static bool process_file(const std::string& infile, const std::string& outfile, bool outfile_append,
							FilterCriteria *filter, PacketProcessor* processorcfg,
							unsigned long* nloadedOUT, unsigned long* nmatchingOUT)
{
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap_handle_in = NULL;
	pcap_dumper_t *pcap_dumper = NULL;

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
		printf_verbose("The PCAP file has size %.2fGiB = %luMiB.\n", (double)st.st_size/(double)GB, st.st_size/MB);


	// open outfile
	if (!outfile.empty())
	{
		if (outfile_append)
		{
			// NOTE: the PCAP produced by appending cannot be opened correctly by Wireshark in some cases...

			pcap_dumper = pcap_dump_append(pcap_handle_in, outfile.c_str());
			if (pcap_dumper == NULL)
				return false;

			printf_normal("Successfully opened output PCAP '%s' in APPEND mode\n", outfile.c_str());
		}
		else
		{
			pcap_dumper = pcap_dump_open(pcap_handle_in, outfile.c_str());
			if (!pcap_dumper)
			{
				printf_error("Cannot open file: %s\n", pcap_geterr(pcap_handle_in));
				return false;
			}
			printf_normal("Successfully opened output PCAP '%s'\n", outfile.c_str());
		}
	}

	// do the real job

	if (filter->needs_2passes())
	{
		// special mode: this requires 2 pass over the PCAP file: first one to get hash values for valid FLOWS;
		// second one to save to disk all flows with valid hashes


		// first pass:
		printf_normal("TCP connection filtering enabled: performing first pass\n");

		unsigned long nvalidflows=0;
		if (!firstpass_process_pcap_handle_for_tcp_streams(pcap_handle_in, filter, &nvalidflows))
			return false;


		if (nvalidflows)
		{
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
				printf_verbose("The PCAP file has size %.2fGiB = %luMiB.\n", (double)st.st_size/(double)GB, st.st_size/MB);

			if (!process_pcap_handle(pcap_handle_in, filter, processorcfg, pcap_dumper, nloadedOUT, nmatchingOUT))
				return false;
		}
		else
		{
			return false;
		}
	}
	else if (processorcfg->needs_2passes())
	{
		// if no filtering is given, but we want to process output packets, then we invert the
		// selection criteria: by default each packet of the input will be processed
		// (by default an empty FilterCriteria instance would instead discard ALL packets!)
		FilterCriteria *filterToUse = filter;
		if (!filter->is_some_filter_active())
		{
			printf_verbose("Packet processing operations active but no filter specified: processing ALL input packets\n");
			filterToUse = NULL;		// disable filter-out logic
		}

		// first pass
		printf_normal("Packet processing operations require 2 passes: performing first pass\n");
		unsigned long nFilteredPkts = 0;
		if (!process_pcap_handle(pcap_handle_in,
								filterToUse, NULL /* no packet processing this time */,
								NULL, NULL, &nFilteredPkts))
			return false;

		if (nFilteredPkts)
		{
			printf_normal("Packet processing operations require 2 passes: performing second pass\n");
			processorcfg->set_num_packets(nFilteredPkts);

			// reopen infile
			pcap_close(pcap_handle_in);
			pcap_handle_in = pcap_open_offline(infile.c_str(), pcap_errbuf);
			if (pcap_handle_in == NULL) {
				printf_error("Cannot open file: %s\n", pcap_errbuf);
				return false;
			}

			// re-process this time with PROCESSOR and OUTPUT DUMPER active!
			if (!process_pcap_handle(pcap_handle_in, filterToUse, processorcfg, pcap_dumper, nloadedOUT, nmatchingOUT))
				return false;
		}
	}
	else
	{
		// standard mode (no -T option)

		if (!process_pcap_handle(pcap_handle_in, filter, processorcfg, pcap_dumper, nloadedOUT, nmatchingOUT))
			return false;
	}

	// cleanup
	if (!outfile.empty())
		pcap_dump_close(pcap_dumper);
	pcap_close(pcap_handle_in);

	return true;
}


//------------------------------------------------------------------------------
// signal handler
//------------------------------------------------------------------------------

static void sigint_handler(int /*sigNum*/, siginfo_t* /*sigInfo*/, void* /*context*/)
{
	printf("Received interruption... aborting. Output results may be incomplete.\n");
	g_termination_requested = true;
}

//------------------------------------------------------------------------------
// main: argument parsing
//------------------------------------------------------------------------------

int main(int argc, char **argv)
{
	int opt;
	bool append = false;
	std::string outfile;
	std::string pcap_filter;
	std::string pcap_gtpu_filter;
	std::string extract_filter;
	std::string search;
	std::string set_duration;
	TcpFilterMode valid_tcp_filter_mode = TCP_FILTER_NOT_ACTIVE;

	while (true) {

		opt = getopt_long(argc, argv, SHORT_OPTS,  g_long_options, 0);
		if (opt == -1)
			break;

		switch (opt) {
		case 'v':
			g_verbose = true;
			break;
		case 'q':
			g_quiet = true;
			break;
		case 'p':
			g_parsing_stats = true;
			break;
		case 'a':
			append = true;
			break;
		case 'w':
			outfile = optarg;
			break;
		case 'h':
			print_help();
			break;
		case 't':
			g_timestamp_analysis = true;
			break;


			// filters:

		case 'Y':
			pcap_filter = optarg;
			break;
		case 'G':
			pcap_gtpu_filter = optarg;
			break;
		case 'C':
			extract_filter = optarg;
			break;
		case 'S':
			search = optarg;
			break;
		case 'T':
			if (strcmp(optarg, "syn") == 0)
				valid_tcp_filter_mode = TCP_FILTER_CONN_HAVING_SYN;
			else if (strcmp(optarg, "full3way") == 0)
				valid_tcp_filter_mode = TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE;
			else if (strcmp(optarg, "full3way-data") == 0)
				valid_tcp_filter_mode = TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE_AND_DATA;
			else
				printf_error("Unsupported TCP filtering mode: %s\n", optarg);
			break;


			// processing options:
		case 'D':
			set_duration = optarg;
			break;


			// detect errors:

		case '?':
			{
				if (optopt == 'w' || optopt == 'Y' || optopt == 'G' || optopt == 's')
					printf_error("Option -%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					printf_error("Unknown option `-%c'.\n", optopt);
				else
					printf_error("Unknown option character `\\x%x'.\n", optopt);
			}
			return 1;

		default:
			abort();
		}
	}

	// validate option combinations

	if (g_verbose && g_quiet)
	{
		printf_error("Both verbose mode (-v) and quiet mode (-q) were specified... aborting.\n");
		return 1;	// failure
	}

	bool some_filter_set = !pcap_filter.empty() || !pcap_gtpu_filter.empty() || !extract_filter.empty() || !search.empty() || (valid_tcp_filter_mode!=TCP_FILTER_NOT_ACTIVE);
	if (some_filter_set && outfile.empty())
	{
		printf_error("A filtering option (-Y, -G, -C, -S or -T) was provided but no output file (-w) was specified... aborting.\n");
		return 1;	// failure
	}

	if (!set_duration.empty() && outfile.empty())
	{
		printf_error("A processing option (--set-duration) was provided but no output file (-w) was specified... aborting.\n");
		return 1;	// failure
	}

	if (valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE && !set_duration.empty())
	{
		// for implementation simplicity, we don't allow to both TCP filter (which is 2pass filtering)
		// with duration setting (which is 2pass filtering)
		printf_error("Both -T and --set-duration were specified: this is not supported.\n");
		return 1;	// failure
	}

	if (!extract_filter.empty() && !pcap_gtpu_filter.empty())
	{
		// we will convert the -C filter to -G filter, so you cannot give both -C and -G!
		printf_error("Both -G and -C were specified: this is not supported.\n");
		return 1;	// failure
	}

	if (!extract_filter.empty())
	{
		// extraction filters are just converted directly to PCAP GTPu filters
		if (!FilterCriteria::convert_extract_filter(extract_filter, pcap_gtpu_filter))
		{
			printf_error("Invalid format for the 4tuple argument of -C option: %s\n", extract_filter.c_str());
			printf_error("Syntax is 'IP1:port1 IP2:port2'\n");
			return 1;	// failure
		}
	}


	// install signal handler:

	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigint_handler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_SIGINFO;			// use the advanced callback, specially useful because provides the PID of the signal sender
	if (sigaction(SIGINT, &sa, NULL) < 0)
	{
		printf_error("Failed to intercept signal %d.", SIGTERM);
		return 1;	// failure
	}




	FilterCriteria filter;
	if (!filter.prepare_filter(pcap_filter, pcap_gtpu_filter, search, valid_tcp_filter_mode))
	{
		// error was already logged
		return 1;
	}


	PacketProcessor processor;
	if (!processor.prepare_processor(set_duration))
	{
		// error was already logged
		return 1;
	}



	// the last non-option arguments are the input filenames:

	if (optind >= argc || !argv[optind])
	{
		printf_error("Please provide at least one input PCAP file to analyze. Use --help for help.\n");
		return 1;
	}
	else if (optind == argc-1)
	{
		std::string infile(argv[optind]);

		if (!outfile.empty() && strcmp(infile.c_str(), outfile.c_str()) == 0)
		{
			printf_error("The PCAP to analyze '%s' is also the output PCAP file specified with -w?\n", outfile.c_str());
			return 1;
		}

		// just 1 input file
		if (!process_file(infile.c_str(), outfile.c_str(), append, &filter, &processor, NULL, NULL))
			return 2;
	}
	else
	{
		// more than 1 input file

		unsigned long nloaded = 0, nmatching = 0;
		int currfile = optind;
		for (; currfile < argc; currfile++)
		{
			if (!outfile.empty() && strcmp(argv[currfile], outfile.c_str()) == 0)
			{
				printf_error("Skipping the PCAP '%s': it is the output PCAP file specified with -w\n", outfile.c_str());
				continue;
			}

			if (!process_file(argv[currfile], outfile.c_str(), append, &filter, &processor, &nloaded, &nmatching))
				return 2;
			printf("\n");

			append = true;		// regardless of what user asked for, when processing 2nd file avoid overwrite the filtering result of the 1st file :)
		}

		printf_verbose("Total number of loaded packets: %lu\n", nloaded);
		printf_verbose("Total number of matching packets: %lu\n", nmatching);
	}

	return 0;
}




