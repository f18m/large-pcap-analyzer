/*
 * large-pcap-analyzer.cpp
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 * Created: Nov 2014
 * Last Modified: Jan 2017
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

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <netinet/ip.h> /* superset of previous */
#include <linux/udp.h>
#include <linux/tcp.h>


//------------------------------------------------------------------------------
// Globals
//------------------------------------------------------------------------------

u_char g_buffer[MAX_SNAPLEN];
boolean g_verbose = FALSE;
boolean g_timestamp_analysis = FALSE;


//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

void printf_verbose(const char *fmtstr, ...)
{
	va_list args;
	va_start(args, fmtstr);
	if (g_verbose)
		vprintf(fmtstr, args);
	va_end(args);
}


//------------------------------------------------------------------------------
// Static Functions
//------------------------------------------------------------------------------

static void print_help()
{
	printf("%s [-h] [-v] [-a] [-w outfile.pcap] [-Y tcpdump_filter] [-G gtpu_tcpdump_filter] [-S string] [-T] somefile.pcap ...\n", PACKAGE_NAME);
	printf("by Francesco Montorsi, (c) Nov 2014-2017\n");
	printf("version %s\n\n", PACKAGE_VERSION);
	printf("Miscellaneous options:\n");
	printf(" -h                       this help\n");
	printf(" -v                       be verbose\n");
	printf(" -t                       provide timestamp analysis on loaded packets\n");
	printf(" -a                       open output file in APPEND mode instead of TRUNCATE\n");
	printf(" -w <outfile.pcap>        where to save the PCAP containing the results of filtering\n");
	printf("Filtering options:\n");
	printf(" -Y <tcpdump_filter>      the PCAP filter to apply when READING the pcap\n");
	printf(" -G <gtpu_tcpdump_filter> the PCAP filter to apply on inner GTPu frames (if any) to select packets to save in outfile.pcap\n");
	printf(" -S <search-string>       an string filter  to select packets to save in outfile.pcap\n");
	printf(" -T                       select packets part of valid TCP connections, i.e. connections having at least 1 SYN and 1 SYN/ACK\n");
	printf("Inputs:\n");
	printf(" somefile.pcap            the large PCAP to analyze (you can provide more than 1 file)\n");
	printf("Note that the -Y and -G options accept filters expressed in tcpdump/pcap_filters syntax.\n");
	printf("See http://www.manpagez.com/man/7/pcap-filter/ for more info.\n");
	printf("\n");
	exit(0);
}

static boolean firstpass_process_pcap_handle_for_tcp_valid_streams(pcap_t* pcap_handle_in, FilterCriteria* filter, unsigned long* nvalidflowsOUT)
{
	unsigned long nloaded_pkts = 0, ninvalid_pkts = 0, nnottcp_pkts = 0, nvalid_streams = 0;
	struct timeval start, stop;
	const u_char *pcap_packet;
	struct pcap_pkthdr *pcap_header;

	// the output of this function is saved inside the FILTER object:
	filter->valid_tcp_firstpass_flows.clear();

	gettimeofday(&start, NULL);
	while (pcap_next_ex(pcap_handle_in, &pcap_header, &pcap_packet) > 0)
	{
		if ((nloaded_pkts % MILLION) == 0 && nloaded_pkts > 0)
			printf_verbose("%luM packets loaded from PCAP...\n", nloaded_pkts/MILLION);


		// first, detect if this is a TCP SYN/SYN-ACK packet

		boolean is_gtpu=FALSE, is_tcp_syn=FALSE, is_tcp_syn_ack=FALSE;
		int offsetInnerTransport = 0, innerIpProt = 0;
		ParserRetCode_t ret = get_gtpu_inner_transport_offset(pcap_header, pcap_packet, &offsetInnerTransport, &innerIpProt);
		if (ret == GPRC_VALID_PKT)
		{
			is_gtpu = TRUE;
		}
		else		// not a GTPu packet
		{
			ParserRetCode_t ret = get_transport_offset(pcap_header, pcap_packet, &offsetInnerTransport, &innerIpProt);
			if (ret != GPRC_VALID_PKT)
			{
				offsetInnerTransport = 0;
				innerIpProt = 0;
				ninvalid_pkts++;
			}
		}

		if (innerIpProt == IPPROTO_TCP)
		{
			const struct tcphdr* tcp = (const struct tcphdr*)(pcap_packet + offsetInnerTransport);
			if (tcp->syn == 1 && tcp->ack == 0)
				is_tcp_syn=TRUE;
			if (tcp->syn == 1 && tcp->ack == 1)
				is_tcp_syn_ack=TRUE;
		}
		else
		{
			nnottcp_pkts++;
		}


		// then save the state for the TCP connection associated to this packet:

		if (is_tcp_syn || is_tcp_syn_ack)
		{
			flow_hash_t tag = compute_flow_hash(pcap_header, pcap_packet, is_gtpu);
			if (tag != INVALID_FLOW_HASH)
			{
				if (is_tcp_syn)
				{
					assert(!is_tcp_syn_ack);

					// new connection, SYN packet found
					filter->valid_tcp_firstpass_flows.insert( std::pair<flow_hash_t /* key */, FlowStatus_t /* value */>(tag, FLOW_FOUND_SYN) );
				}
				else if (is_tcp_syn_ack)
				{
					assert(!is_tcp_syn);

					flow_map_t::iterator entry = filter->valid_tcp_firstpass_flows.find(tag);
					if (entry != filter->valid_tcp_firstpass_flows.end() &&
							entry->second == FLOW_FOUND_SYN)
					{
						entry->second = FLOW_FOUND_SYN_AND_SYNACK;		// existing connection, found SYN-ACK packet for that
						nvalid_streams++;
					}
				}
			}
		}

		nloaded_pkts++;
	}
	gettimeofday(&stop, NULL);

	printf_verbose("Processing took %i seconds.\n", (int) (stop.tv_sec - start.tv_sec));
	printf_verbose("Detected %lu invalid packets, %lu non-TCP packets and %lu valid TCP flows.\n", ninvalid_pkts, nnottcp_pkts, nvalid_streams);

	if (nvalidflowsOUT)
		*nvalidflowsOUT = nvalid_streams;

	return TRUE;
}


static boolean process_pcap_handle(pcap_t* pcap_handle_in,
									const FilterCriteria* filter,
									pcap_dumper_t* pcap_dumper,
									unsigned long* nloadedOUT, unsigned long* nmatchingOUT)
{
    unsigned long nloaded = 0, nmatching = 0, ngtpu = 0, nbytes_avail = 0, nbytes_orig = 0;
    struct timeval start, stop;
    boolean first = TRUE;

    const u_char *pcap_packet;
    struct pcap_pkthdr *pcap_header;
    struct pcap_pkthdr first_pcap_header, last_pcap_header;

    const char* pcapfilter_desc = filter->capture_filter_set ? " (matching PCAP filter)" : "";

    gettimeofday(&start, NULL);
    while (pcap_next_ex(pcap_handle_in, &pcap_header, &pcap_packet) > 0)
    {
        if ((nloaded % MILLION) == 0 && nloaded > 0)
        	printf_verbose("%luM packets loaded from PCAP%s...\n", nloaded/MILLION, pcapfilter_desc);


        // filter and save to output eventually

        boolean is_gtpu = FALSE;
        boolean tosave = must_be_saved(pcap_header, pcap_packet, filter, &is_gtpu);
        if (tosave) {
            nmatching++;

            if (pcap_dumper)
                pcap_dump((u_char *) pcap_dumper, pcap_header, pcap_packet);
        }
        if (is_gtpu)
        	ngtpu++;


        // save timestamps for later analysis:

        if (first)
        {
            memcpy(&first_pcap_header, pcap_header, sizeof(struct pcap_pkthdr));
            first = 0;
        }
        else
            memcpy(&last_pcap_header, pcap_header, sizeof(struct pcap_pkthdr));

        nbytes_avail += pcap_header->caplen;
        nbytes_orig += pcap_header->len;
        nloaded++;
    }
    gettimeofday(&stop, NULL);


    printf_verbose("Processing took %i seconds.\n", (int) (stop.tv_sec - start.tv_sec));
    printf("%luM packets (%lu packets) were loaded from PCAP%s.\n", nloaded/MILLION, nloaded, pcapfilter_desc);

    if (filter->gtpu_filter_set)
    	// in this case, the GTPu parser was run and we have a stat about how many packets are GTPu
		printf_verbose("%luM packets (%lu packets) loaded from PCAP%s are GTPu packets (%.1f%%).\n",
						ngtpu/MILLION, ngtpu, pcapfilter_desc, (double)(100.0*(double)(ngtpu)/(double)(nloaded)));

    if (pcap_dumper)
    {
		if (filter->string_filter || filter->gtpu_filter_set || filter->valid_tcp_filter)
		{
			printf("%lu packets matched the filtering criteria (search string / GTPu filter / valid TCP streams filter) and were saved into output PCAP.\n",
				   nmatching);
		}
		else
		{
			assert(nmatching == 0);
			printf("No criteria for packet selection specified (search string / GTPu filter / valid TCP streams filter) so nothing was written into output PCAP.\n");
		}
    }

    if (g_timestamp_analysis)
    {
		double secStart = (double)first_pcap_header.ts.tv_sec +
							(double)first_pcap_header.ts.tv_usec / (double)MILLION;
		double secStop = (double)last_pcap_header.ts.tv_sec +
							(double)last_pcap_header.ts.tv_usec / (double)MILLION;
		double sec = secStop - secStart;
		if (secStart < SMALL_NUM && secStop == SMALL_NUM)
		{
			printf("Apparently the packets of the PCAP have no valid timestamp... cannot compute PCAP duration.\n");
		}
		else
		{
			printf_verbose("Last packet has a timestamp offset = %.2fsec = %.2fmin = %.2fhours\n",
					sec, sec/60.0, sec/3600.0);
		}

		printf_verbose("Bytes loaded from PCAP = %lukiB = %luMiB; total bytes on wire = %lukiB = %luMiB\n",
			   nbytes_avail/KB, nbytes_avail/MB, nbytes_orig/KB, nbytes_orig/MB);
		if (nbytes_avail == nbytes_orig)
			printf_verbose("  => all packets in the PCAP have been captured WITHOUT truncation.\n");

		if (sec)
		{
			printf("Tcpreplay should replay this PCAP at an average of %.2fMbps / %.2fpps to respect PCAP timings.\n",
				  (float)(8*nbytes_avail/MB)/sec, (float)nloaded/sec);
		}
		else
		{
			printf("Cannot compute optimal tcpreplay speed for replaying: duration is 0sec.\n");
		}
    }

    // provide output info
    if (nloadedOUT) *nloadedOUT += nloaded;
    if (nmatchingOUT) *nmatchingOUT += nmatching;

    return TRUE;
}


// adapted from http://sourcecodebrowser.com/libpcapnav/0.8/pcapnav__append_8c.html#a918994d1d2d679e4aaad41f7724360ea

static pcap_dumper_t* pcap_dump_append( pcap_t* pcap,
                                        const char * filename )
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pn = NULL;
    FILE *result = NULL;

    pn = pcap_open_offline(filename, pcap_errbuf);
    if (pn == NULL) {

        result = (FILE*)pcap_dump_open(pcap, filename);
        if (result)
        {
            // file does not exit... create it with the regular PCAP API function
            return (pcap_dumper_t *) result;
        }
        else
        {
            fprintf(stderr, "Couldn't open file: %s\n", pcap_errbuf);
            return NULL;
        }
    }

    /* Check whether the linklayer protocols are compatible -- if not,
    * then we cannot append (at least not without linklayer adaptors).
    *
    * Note that we do NOT check against pn->trace.filehdr.linktype
    * directly. Pcap's internal mapping mechanism may cause a different
    * value to be stored in the header structure than reported through
    * pcap_datalink(), so we must make sure we use pcap_datalink() in
    * both cases to ensure comparability.
    */
    if (pcap_datalink(pn) != pcap_datalink(pcap))
    {
        fprintf(stderr, "linklayer protocols incompatible (%i/%i)",
                       pcap_datalink(pn), pcap_datalink(pcap));
        pcap_close(pn);
        return NULL;
    }

    if (! (result = fopen(filename, "r+")))
    {
        fprintf(stderr, "Error opening '%s' in r+ mode.\n", filename);
        goto error_return;
    }

    #if 0
    /* Check whether the snaplen will need to be updated: */
    if (pcap_snapshot(pn) < pcap_snapshot(pcap))
    {
        //struct pcap_file_header filehdr;

        fprintf(stderr, "snaplen needs updating from %d to %d.\n",
                pcap_snapshot(pn), pcap_snapshot(pcap));

/*
        filehdr = pn->trace.filehdr;
        filehdr.snaplen = pcap_snapshot(pcap);

        if (fwrite(&filehdr, sizeof(struct pcap_file_header), 1, result) != 1)
        {
            D(("Couldn't write corrected file header.\n"));
            goto error_return;
        }*/
        goto error_return;
    }
    #endif

    if (fseek(result, 0, SEEK_END) < 0)
    {
        fprintf(stderr, "Error seeking to end of file.\n");
        goto error_return;
    }

    #if 0
    if (mode == PCAPNAV_DUMP_APPEND_SAFE)
    {
      if (! append_fix_trunc_packet(pn, result))
       {
         D(("Fixing truncated packet failed.\n"));
         goto error_return;
       }
    }
    #endif

    pcap_close(pn);
    return (pcap_dumper_t *) result;

error_return:
    pcap_close(pn);
    return NULL;
}

/*
int pcap_compile_nopcap_with_err(int snaplen_arg, int linktype_arg,
		struct bpf_program *program,
		const char *buf, int optimize, bpf_u_int32 mask,
		)
{
	// --- code taken from pcap_compile_nopcap() implementation in libpcap/gencode.c: ---
	pcap_t *p;
	int ret;

	p = pcap_open_dead(DLT_EN10MB, MAX_SNAPLEN);
	if (p == NULL)
	{
		return -1;
	}

	ret = pcap_compile(p, program, buf, optimize, mask);
	pcap_close(p);
	return ret;
}*/

static boolean process_file(const char* infile, const char *outfile, boolean outfile_append,
							FilterCriteria *filter,
							unsigned long* nloadedOUT, unsigned long* nmatchingOUT)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap_handle_in = NULL;
    pcap_dumper_t *pcap_dumper = NULL;

    struct stat st;
    memset(&st, 0, sizeof(st));
    stat(infile, &st);

    // open infile
    pcap_handle_in = pcap_open_offline(infile, pcap_errbuf);
    if (pcap_handle_in == NULL) {
        fprintf(stderr, "Couldn't open file: %s\n", pcap_errbuf);
        return FALSE;
    }
    printf_verbose("Analyzing PCAP file '%s'...\n", infile);

    if (st.st_size)
    {
    	printf_verbose("The PCAP file has size %.2fGiB = %luMiB.\n", (double)st.st_size/(double)GB, st.st_size/MB);
    }

    // PCAP capture filter
    if (filter->capture_filter_set)
    {
        if (pcap_setfilter(pcap_handle_in, (struct bpf_program*) &filter->capture_filter) != 0) {
            fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(pcap_handle_in));
            return FALSE;
        }
    }
    else
        printf("No PCAP filter set: all packets inside the PCAP will be loaded.\n");


    // open outfile
    if (outfile)
    {
        if (outfile_append)
        {
            // NOTE: the PCAP produced by appending cannot be opened correctly by Wireshark in some cases...

            pcap_dumper = pcap_dump_append(pcap_handle_in, outfile);
            if (pcap_dumper == NULL)
                return FALSE;

            printf("Successfully opened output PCAP '%s' in APPEND mode\n", outfile);
        }
        else
        {
            pcap_dumper = pcap_dump_open(pcap_handle_in, outfile);
            if (!pcap_dumper)
            {
                fprintf(stderr, "Couldn't open file: %s\n", pcap_geterr(pcap_handle_in));
                return FALSE;
            }
            printf("Successfully opened output PCAP '%s'\n", outfile);
        }
    }

    // do the real job

    if (filter->valid_tcp_filter)
    {
    	// special mode: this requires 2 pass over the PCAP file: first one to get hash values for valid FLOWS;
    	// second one to save to disk all flows with valid hashes


    	// first pass:
        printf("Valid TCP filtering enabled: performing first pass\n");

    	unsigned long nvalidflows=0;
    	if (!firstpass_process_pcap_handle_for_tcp_valid_streams(pcap_handle_in, filter, &nvalidflows))
    		return FALSE;


    	if (nvalidflows)
    	{
			// second pass:

            printf("Valid TCP filtering enabled: performing second pass\n");

			// reopen infile
			pcap_close(pcap_handle_in);
			pcap_handle_in = pcap_open_offline(infile, pcap_errbuf);
			if (pcap_handle_in == NULL) {
				fprintf(stderr, "Couldn't open file: %s\n", pcap_errbuf);
				return FALSE;
			}

			printf_verbose("Analyzing PCAP file '%s'...\n", infile);
			if (st.st_size)
				printf_verbose("The PCAP file has size %.2fGiB = %luMiB.\n", (double)st.st_size/(double)GB, st.st_size/MB);

			if (!process_pcap_handle(pcap_handle_in, filter, pcap_dumper, nloadedOUT, nmatchingOUT))
				return FALSE;
    	}
    	else
    	{
    		return FALSE;
    	}
    }
    else
    {
    	// standard mode (no -T option)

		if (!process_pcap_handle(pcap_handle_in, filter, pcap_dumper, nloadedOUT, nmatchingOUT))
			return FALSE;
    }

    // cleanup
    if (outfile)
        pcap_dump_close(pcap_dumper);
    pcap_close(pcap_handle_in);

    return TRUE;
}

static boolean prepare_filter(FilterCriteria* out,
								const char* pcap_filter_str, const char* gtpu_filter_str, const char* string_filter, boolean valid_tcp_filter)
{
    // PCAP filter
    if (pcap_filter_str)
    {
        if (pcap_compile_nopcap(MAX_SNAPLEN, DLT_EN10MB, &out->capture_filter, pcap_filter_str, 0 /* optimize */, PCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "Couldn't parse PCAP filter\n");
            return FALSE;
        }

        out->capture_filter_set = TRUE;
        printf("Successfully compiled PCAP filter: %s\n", pcap_filter_str);
    }


    // GTPu PCAP filter
    if (gtpu_filter_str)
    {

        if (pcap_compile_nopcap(MAX_SNAPLEN, DLT_EN10MB, &out->gtpu_filter, gtpu_filter_str, 0 /* optimize */, PCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "Couldn't parse GTPu filter\n");
            return FALSE;
        }

        out->gtpu_filter_set = TRUE;
        printf("Successfully compiled GTPu PCAP filter: %s\n", gtpu_filter_str);
    }


    // other filters:

    out->string_filter = string_filter;
    out->valid_tcp_filter = valid_tcp_filter;


    return TRUE;
}

//------------------------------------------------------------------------------
// main: argument parsing
//------------------------------------------------------------------------------

int main(int argc, char **argv)
{
    int opt;
    boolean append = FALSE, valid_tcp_filter = FALSE;
    char *outfile = NULL;
    char *pcap_filter = NULL;
    char *pcap_gtpu_filter = NULL;
    char *search = NULL;

    while ((opt = getopt(argc, argv, "thvaw:Y:G:S:T")) != -1) {
        switch (opt) {
        case 'v':
			g_verbose = TRUE;
			break;
        case 'a':
            append = TRUE;
            break;
        case 'w':
            outfile = optarg;
            break;
        case 'h':
            print_help();
            break;
        case 't':
        	g_timestamp_analysis = TRUE;
        	break;


            // filters:

        case 'Y':
            pcap_filter = optarg;
            break;
        case 'G':
            pcap_gtpu_filter = optarg;
            break;
        case 'S':
            search = optarg;
            break;
        case 'T':
        	valid_tcp_filter = TRUE;
            break;

        case '?':
            {
                if (optopt == 'w' || optopt == 'Y' || optopt == 'G' || optopt == 's')
                    fprintf (stderr, "Option -%c requires an argument.\n", optopt);
                else if (isprint (optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
            }
            return 1;

        default:
            abort();
        }
    }


    FilterCriteria filter;
    if (!prepare_filter(&filter, pcap_filter, pcap_gtpu_filter, search, valid_tcp_filter))
    {
    	// error was already logged
        return 1;
    }



    // the last non-option arguments are the input filenames:

    if (optind >= argc || !argv[optind])
    {
        fprintf(stderr, "Please provide at least one input PCAP file to analyze...\n");
        print_help();
        return 1;
    }
    else if (optind == argc-1)
    {
        if (outfile && strcmp(argv[optind], outfile) == 0)
        {
            fprintf(stderr, "The PCAP to analyze '%s' is also the dump PCAP?\n", outfile);
            return 1;
        }

        // just 1 input file
        if (!process_file(argv[optind], outfile, append, &filter, NULL, NULL))
            return 2;
    }
    else
    {
        // more than 1 input file

        unsigned long nloaded = 0, nmatching = 0;
        int currfile = optind;
        for (; currfile < argc; currfile++)
        {
            if (outfile && strcmp(argv[currfile], outfile) == 0)
            {
                printf("Skipping the PCAP '%s': it is the dump PCAP specified with -w\n", outfile);
                printf("\n");
                continue;
            }

            if (!process_file(argv[currfile], outfile, append, &filter, &nloaded, &nmatching))
                return 2;
            printf("\n");
        }

        printf_verbose("Total number of loaded packets: %lu\n", nloaded);
        printf_verbose("Total number of matching packets: %lu\n", nmatching);
    }

    return 0;
}




