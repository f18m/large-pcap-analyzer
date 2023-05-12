/*
 * large-pcap-analyzer.cpp
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

#include "large-pcap-analyzer.h"
#include "filter.h"
#include "parse.h"
#include "pcap_helpers.h"
#include "printf_helpers.h"
#include "process_file.h"
#include "timestamp_pkt_processor.h"
#include "trafficstats_pkt_processor.h"

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
// Globals
//------------------------------------------------------------------------------

LPAConfig g_config;

static struct option g_long_options[] = {

    // misc options
    { "help", no_argument, 0, 'h' },
    { "verbose", no_argument, 0, 'v' },
    { "version", no_argument, 0, 'V' },
    { "quiet", no_argument, 0, 'q' },
    { "write", required_argument, 0, 'w' },
    { "append", no_argument, 0, 'a' },

    // filters
    { "display-filter", required_argument, 0, 'Y' },
    { "inner-filter", required_argument, 0, 'G' },
    { "connection-filter", required_argument, 0, 'C' },
    { "string-filter", required_argument, 0, 'S' },
    { "tcp-filter", required_argument, 0, 'T' },

    // timestamp processing options
    { "timing", no_argument, 0, 't' },
    { "set-duration", required_argument, 0, 'D' },
    { "set-duration-preserve-ifg", required_argument, 0, 'd' },
    { "set-timestamps-from", required_argument, 0, 's' },

    // reporting options
    { "stats", no_argument, 0, 'p' },
    { "report", required_argument, 0, 'r' },

    { 0, 0, 0, 0 }
};

// define only short options now:
#define SHORT_OPTS_MISC "hvVqw:a"
#define SHORT_OPTS_FILTERS "Y:G:C:S:T:"
#define SHORT_OPTS_TIMESTAMPS "t"
#define SHORT_OPTS_REPORTING "p"

#define SHORT_OPTS        \
    SHORT_OPTS_MISC       \
    SHORT_OPTS_FILTERS    \
    SHORT_OPTS_TIMESTAMPS \
    SHORT_OPTS_REPORTING

//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

static void print_help()
{
    printf("%s version %s, built with libpcap %s\n", PACKAGE_NAME, PACKAGE_VERSION, pcap_lib_version());
    printf("by Francesco Montorsi, (c) 2014-2023\n");
    printf("Usage:\n");
    printf("  %s [options] somefile.pcap ...\n", PACKAGE_NAME);
    printf("Miscellaneous options:\n");
    printf(" -h,--help                this help\n");
    printf(" -v,--verbose             be verbose\n");
    printf(" -V,--version             print version and exit\n");
    printf(" -q,--quiet               suppress all normal output, be script-friendly\n");
    printf(" -w <outfile.pcap>, --write <outfile.pcap>\n");
    printf("                          where to save the PCAP containing the results of filtering/processing\n");
    printf(" -a,--append              open output file in APPEND mode instead of TRUNCATE\n");
    printf("Filtering options (i.e., options to select the packets to save in <outfile.pcap>):\n");
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
    printf("Timestamp processing options (i.e., options that will change packets saved in <outfile.pcap>):\n");
    printf(" -t,--timing              provide timestamp analysis on loaded packets\n");
    printf(" --set-duration <HH:MM:SS>\n");
    printf("                          alters packet timestamps so that the time difference between first and last packet\n");
    printf("                          matches the given amount of time. All packets in the middle will be equally spaced in time.\n");
    printf(" --set-duration-preserve-ifg <HH:MM:SS>\n");
    printf("                          alters packet timestamps so that the time difference between first and last packet\n");
    printf("                          matches the given amount of time. Interframe gaps (IFG) are scaled accordingly.\n");
    printf(" --set-timestamps-from <infile.txt>\n");
    printf("                          alters all packet timestamps using the list of Unix timestamps contained in the given text file;\n");
    printf("                          the file format is: one line per packet, a single Unix timestamp in seconds (floating point supported)\n");
    printf("                          per line; the number of lines must match exactly the number of packets of the filtered input PCAP.\n");
    printf("Reporting options:\n");
    printf(" -p,--stats               provide basic parsing statistics on loaded packets\n");
    printf(" --report <report-name>\n");
    printf("                          provide a report on loaded packets; list of supported reports is:\n");
    printf("                          allflows_by_pkts: print in CSV format all the flows sorted by number of packets\n");
    printf("                          top10flows_by_pkts: print in CSV format the top 10 flows sorted by number of packets\n");
    printf("                          allflows_by_pkts_outer: same as <allflows_by_pkts> but stop at GTPu outer tunnel, don't parse the tunneled packet\n");
    printf("                          top10flows_by_pkts_outer: same as <top10flows_by_pkts> but stop at GTPu outer tunnel, don't parse the tunneled packet\n");
    printf("Inputs:\n");
    printf(" somefile.pcap            the large PCAP trace to analyze; more than 1 file can be specified.\n");
    printf("\n");
    printf("Note that:\n");
    printf("  -Y and -G options accept filters expressed in tcpdump/pcap_filters syntax. See http://www.manpagez.com/man/7/pcap-filter/ for more info.\n");
    printf("  A 'flow' is defined as a unique tuple of (srcIP, srcPort, dstIP, dstPort) for UDP,TCP,SCTP protocols.\n");
    printf("Other PCAP utilities you may be looking for are:\n");
    printf(" * mergecap: to merge PCAP files\n");
    printf(" * tcpdump: can be used to split PCAP files (and more)\n");
    printf(" * editcap: can be used to manipulate timestamps in PCAP files (and more)\n");
    printf(" * tcprewrite: can be used to rewrite some packet fields in PCAP files (and more)\n");
    exit(0);
}

//------------------------------------------------------------------------------
// signal handler
//------------------------------------------------------------------------------

static void sigint_handler(int /*sigNum*/, siginfo_t* /*sigInfo*/,
    void* /*context*/)
{
    printf(
        "Received interruption... aborting. Output results may be incomplete.\n");
    g_config.m_termination_requested = true;
}

//------------------------------------------------------------------------------
// main: argument parsing
//------------------------------------------------------------------------------

int main(int argc, char** argv)
{
    int opt;
    bool append = false;
    bool preserve_ifg = false;
    bool timestamp_processing_option_present = false;
    bool traffic_report_present = false;
    bool report_based_on_inner = false;
    int report_max_flows = 0;
    std::string outfile;
    std::string pcap_filter;
    std::string pcap_gtpu_filter;
    std::string extract_filter;
    std::string search;
    std::string new_duration;
    std::string set_duration_reset_ifg;
    std::string set_duration_saving_ifg;
    std::string set_timestamps;
    TcpFilterMode valid_tcp_filter_mode = TCP_FILTER_NOT_ACTIVE;

    while (true) {

        opt = getopt_long(argc, argv, SHORT_OPTS, g_long_options, 0);
        if (opt == -1)
            break;

        switch (opt) {
        case 'v':
            g_config.m_verbose = true;
            break;
        case 'V':
            printf("%s\n", PACKAGE_VERSION);
            exit(0);
            break;
        case 'q':
            g_config.m_quiet = true;
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
            else {
                printf_error("Unsupported TCP filtering mode: %s. Please check supported TCP filtering modes in --help output.\n", optarg);
                return 1; // failure
            }
            break;

            // timestamp processing options:
        case 't':
            g_config.m_timestamp_analysis = true;
            timestamp_processing_option_present = true;
            break;
        case 'D':
            set_duration_reset_ifg = optarg;
            new_duration = optarg;
            preserve_ifg = false;
            timestamp_processing_option_present = true;
            break;
        case 'd':
            set_duration_saving_ifg = optarg;
            new_duration = optarg;
            preserve_ifg = true;
            timestamp_processing_option_present = true;
            break;
        case 's':
            set_timestamps = optarg;
            timestamp_processing_option_present = true;
            break;

            // report options:
        case 'p':
            g_config.m_parsing_stats = true;
            break;
        case 'r':
            traffic_report_present = true;
            if (strcmp(optarg, "top10flows_by_pkts_outer") == 0) {
                report_max_flows = 10;
                report_based_on_inner = false;
            } else if (strcmp(optarg, "allflows_by_pkts_outer") == 0) {
                report_max_flows = 0; // means 'all flows'
                report_based_on_inner = false;
            } else if (strcmp(optarg, "top10flows_by_pkts") == 0) {
                report_max_flows = 10;
                report_based_on_inner = true;
            } else if (strcmp(optarg, "allflows_by_pkts") == 0) {
                report_max_flows = 0; // means 'all flows'
                report_based_on_inner = true;
            } else {
                printf_error("Unsupported report <%s>. Please check supported report names in --help output.\n", optarg);
                return 1; // failure
            }
            break;

            // detect errors:

        case '?': {
            if (optopt == 'w' || optopt == 'Y' || optopt == 'G' || optopt == 's' || optopt == 'D' || optopt == 'd')
                printf_error("Option -%c requires an argument.\n", optopt);
            else if (isprint(optopt))
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

    if (g_config.m_verbose && g_config.m_quiet) {
        printf_error("Both verbose mode (-v) and quiet mode (-q) were specified... aborting.\n");
        return 1; // failure
    }

    bool some_filter_set = !pcap_filter.empty() || !pcap_gtpu_filter.empty() || !extract_filter.empty() || !search.empty()
        || (valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE);
    if (some_filter_set && outfile.empty()) {
        printf_error("A filtering option (-Y, -G, -C, -S or -T) was provided but no output file (-w) was specified... aborting.\n");
        return 1; // failure
    }

    bool some_processing_set = !new_duration.empty() || !set_timestamps.empty();
    if (some_processing_set && outfile.empty()) {
        printf_error(
            "A processing option (--set-duration or --set-duration-preserve-ifg or "
            "--set-timestamps-from) was provided but no output file (-w) was "
            "specified... aborting.\n");
        return 1; // failure
    }

    if (traffic_report_present && timestamp_processing_option_present) {
        printf_error(
            "The options related to 'timestamp processing' cannot be combined with the options related to 'report' generation. "
            "See --help for more details about how options are categorized. Aborting.\n");
        return 1; // failure
    }

    if (valid_tcp_filter_mode != TCP_FILTER_NOT_ACTIVE && !new_duration.empty()) {
        // for implementation simplicity, we don't allow to both TCP filter (which
        // is 2pass filtering) with duration setting (which is 2pass filtering)
        printf_error("Both -T and --set-duration or --set-duration-preserve-ifg "
                     "were specified: this is not supported.\n");
        return 1; // failure
    }
    if (!extract_filter.empty() && !pcap_gtpu_filter.empty()) {
        // we will convert the -C filter to -G filter, so you cannot give both -C and -G!
        printf_error("Both -G and -C were specified: this is not supported.\n");
        return 1; // failure
    }

    if (!extract_filter.empty()) {
        // extraction filters are just converted directly to PCAP GTPu filters
        if (!FilterCriteria::convert_extract_filter(extract_filter,
                pcap_gtpu_filter)) {
            printf_error("Invalid format for the 4tuple argument of -C option: %s\n",
                extract_filter.c_str());
            printf_error("Syntax is 'IP1:port1 IP2:port2'\n");
            return 1; // failure
        }
    }

    unsigned int timestamp_opts_given = 0;
    if (!set_duration_reset_ifg.empty())
        timestamp_opts_given++;
    if (!set_duration_saving_ifg.empty())
        timestamp_opts_given++;
    if (!set_timestamps.empty())
        timestamp_opts_given++;
    if (timestamp_opts_given > 1) {
        // either we compress all timestamps with given duration or rather we set
        // all packet timestamps using input file, not both!
        fprintf(
            stderr,
            "Both --set-duration and/or --set-timestamps-from and/or "
            "--set-duration-preserve-ifg were specified: this is not supported.\n");
        return 1; // failure
    }

    // install signal handler:

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO; // use the advanced callback, specially useful
        // because provides the PID of the signal sender
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        printf_error("Failed to intercept signal %d.", SIGTERM);
        return 1; // failure
    }

    // select the FILTER criteria to use when loading the PCAP file
    FilterCriteria filter;
    if (!filter.prepare_filter(pcap_filter, pcap_gtpu_filter, search, valid_tcp_filter_mode)) {
        // error was already logged
        return 1;
    }

    // select the PACKET PROCESSOR to fullfill user's requests
    TrafficStatsPacketProcessor trafficstats_packet_proc;
    TimestampPacketProcessor timestamp_packet_proc;
    IPacketProcessor* pproc = nullptr;
    if (traffic_report_present) {
        pproc = &trafficstats_packet_proc;
        if (!trafficstats_packet_proc.prepare_processor(report_based_on_inner, report_max_flows)) {
            // error was already logged
            return 1;
        }
    } else if (timestamp_processing_option_present) {
        pproc = &timestamp_packet_proc;
        if (!timestamp_packet_proc.prepare_processor(new_duration, preserve_ifg, set_timestamps)) {
            // error was already logged
            return 1;
        }
    }
    //else: leave pproc to NULL: no packet processor is needed

    // the last non-option arguments are the input filenames:

    if (optind >= argc || !argv[optind]) {
        printf_error("Please provide at least one input PCAP file to analyze. Use --help for help.\n");
        return 1;
    } else if (optind == argc - 1) {
        std::string infile(argv[optind]);

        if (!outfile.empty() && strcmp(infile.c_str(), outfile.c_str()) == 0) {
            printf_error("The PCAP to analyze '%s' is also the output PCAP file  specified with -w?\n",
                outfile.c_str());
            return 1;
        }

        // just 1 input file
        if (!process_file(infile.c_str(), outfile.c_str(), append, &filter, pproc, NULL, NULL))
            return 2;
    } else {
        // more than 1 input file

        unsigned long nloaded = 0, nmatching = 0;
        int currfile = optind;
        for (; currfile < argc; currfile++) {
            if (!outfile.empty() && strcmp(argv[currfile], outfile.c_str()) == 0) {
                printf_error("Skipping the PCAP '%s': it is the output PCAP file  specified with -w\n",
                    outfile.c_str());
                continue;
            }

            if (!process_file(argv[currfile], outfile.c_str(), append, &filter, pproc, &nloaded, &nmatching))
                return 2;
            printf("\n");

            append = true; // regardless of what user asked for, when processing 2nd file
                // avoid overwrite the filtering result of the 1st file :)
        }

        printf_verbose("Total number of loaded packets: %lu\n", nloaded);
        printf_verbose("Total number of matching packets: %lu\n", nmatching);
    }

    return 0;
}
