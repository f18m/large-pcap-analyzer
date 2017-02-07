/*
 * large-pcap-analyzer
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 * Created: Nov 2014
 * Last Modified: Jan 2017
 *
 * History:
 *
 * v3.1 = first version released in Github
 * v3.2 = reworked command-line arguments to match those of "tshark" command line utility;
 *        added support for GTPu-filtering (-G option)
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


//------------------------------------------------------------------------------
// Globals
//------------------------------------------------------------------------------

u_char g_buffer[MAX_SNAPLEN];
boolean g_verbose = FALSE;


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
	printf("%s [-h] [-v] [-a] [-w outfile.pcap] [-Y tcpdump_filter] [-G gtpu_tcpdump_filter] [-s string] somefile.pcap ...\n", PACKAGE_NAME);
	printf("by Francesco Montorsi, (c) Nov 2014-2017\n");
	printf("version %s\n\n", PACKAGE_VERSION);
	printf("Help:\n");
	printf(" -h                       this help\n");
	printf(" -v                       be verbose\n");
	printf(" -a                       open output file in APPEND mode instead of TRUNCATE\n");
	printf(" -w <outfile.pcap>        where to save the PCAP containing the results of filtering\n");
	printf(" -Y <tcpdump_filter>      the PCAP filter to apply when READING the pcap\n");
	printf(" -G <gtpu_tcpdump_filter> the PCAP filter to apply on inner GTPu frames (if any) to select packets to save in outfile.pcap\n");
	printf(" -s <search-string>       an string filter  to select packets to save in outfile.pcap\n");
	printf(" somefile.pcap            the large PCAP to analyze (you can provide more than 1 file)\n");
	printf("Note that the -Y and -G options accept filters expressed in tcpdump/pcap_filters syntax.\n");
	printf("See http://www.manpagez.com/man/7/pcap-filter/ for more info.\n");
	printf("\n");
	exit(0);
}

static boolean process_pcap_handle(pcap_t* pcap_handle_in,
							struct bpf_program* gtpu_filter, const char *search,
							pcap_dumper_t* pcap_dumper, boolean pcapfilter_set,
							unsigned long* nloadedOUT, unsigned long* nmatchingOUT)
{
    unsigned long nloaded = 0, nmatching = 0, ngtpu = 0, nbytes_avail = 0, nbytes_orig = 0;
    struct timeval start, stop;
    boolean first = TRUE;

    const u_char *pcap_packet;
    struct pcap_pkthdr *pcap_header;
    struct pcap_pkthdr first_pcap_header, last_pcap_header;

    const char* pcapfilter_desc = pcapfilter_set ? " (matching PCAP filter)" : "";

    gettimeofday(&start, NULL);
    while (pcap_next_ex(pcap_handle_in, &pcap_header, &pcap_packet) > 0)
    {
        if ((nloaded % MILLION) == 0 && nloaded > 0)
        	printf_verbose("%luM packets loaded from PCAP%s...\n", nloaded/MILLION, pcapfilter_desc);


        // filter and save to output eventually

        boolean is_gtpu = FALSE;
        boolean tosave = must_be_saved(pcap_header, pcap_packet, search, gtpu_filter, &is_gtpu);
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


    printf_verbose("Processing took %i seconds.\n",
            (int) (stop.tv_sec - start.tv_sec));
    printf_verbose("%luM packets (%lu packets) were loaded from PCAP%s.\n",
            nloaded/MILLION, nloaded, pcapfilter_desc);

    if (gtpu_filter)
    	// in this case, the GTPu parser was run and we have a stat about how many packets are GTPu
		printf_verbose("%luM packets (%lu packets) loaded from PCAP%s are GTPu packets (%.1f%%).\n",
						ngtpu/MILLION, ngtpu, pcapfilter_desc, (double)(100.0*(double)(ngtpu)/(double)(nloaded)));

    if (search || gtpu_filter)
        printf("%lu packets matched the filtering criteria (search string / GTPu filter) and were saved into output PCAP.\n",
               nmatching);
    else
    {
    	assert(nmatching == 0);
    	printf("No criteria for packet selection specified (search string / GTPu filter) so nothing was written into output PCAP.\n");
    }

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
    	printf_verbose("  => the whole traffic has been captured in this PCAP!\n");

    if (sec)
    {
        printf("Tcpreplay should replay this PCAP at an average of %.2fMbps / %.2fpps to respect PCAP timings!\n",
              (float)(8*nbytes_avail/MB)/sec, (float)nloaded/sec);
    }
    else
    {
        printf("Cannot compute optimal tcpreplay speed for replaying: duration is 0sec.\n");
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
							const char *filter, const char* gtpu_filter, const char *search,
							unsigned long* nloadedOUT, unsigned long* nmatchingOUT)
{
    pcap_t *pcap_handle_in = NULL;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program pcap_filter;
    struct bpf_program gtpu_pcap_filter;
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


    // PCAP filter
    if (filter)
    {
        if (pcap_compile(pcap_handle_in, &pcap_filter, filter, 0 /* optimize */, PCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(pcap_handle_in));
            return FALSE;
        }
        if (pcap_setfilter(pcap_handle_in, &pcap_filter) != 0) {
            fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(pcap_handle_in));
            return FALSE;
        }

        printf("Successfully set PCAP filter: %s\n", filter);
    }
    else
        printf("No PCAP filter set: all packets inside the PCAP will be loaded.\n");


    // GTPu PCAP filter
    if (gtpu_filter)
    {

        if (pcap_compile_nopcap(MAX_SNAPLEN, DLT_EN10MB, &gtpu_pcap_filter, gtpu_filter, 0 /* optimize */, PCAP_NETMASK_UNKNOWN) != 0) {
            fprintf(stderr, "Couldn't parse GTPu filter\n");
            return FALSE;
        }

        printf("Successfully compiled GTPu PCAP filter: %s\n", gtpu_filter);
    }


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
    if (!process_pcap_handle(pcap_handle_in, /* input file */
    						gtpu_filter ? &gtpu_pcap_filter : NULL, search, /* filters */
    						pcap_dumper, filter != NULL, nloadedOUT, nmatchingOUT)) /* misc */
        return FALSE;


    // cleanup
    if (outfile)
        pcap_dump_close(pcap_dumper);
    if (filter)
        pcap_freecode(&pcap_filter);
    pcap_close(pcap_handle_in);

    return TRUE;
}


//------------------------------------------------------------------------------
// main: argument parsing
//------------------------------------------------------------------------------

int main(int argc, char **argv)
{
    int opt;
    boolean append = FALSE;
    char *outfile = NULL;
    char *pcap_filter = NULL;
    char *pcap_gtpu_filter = NULL;
    char *search = NULL;

    while ((opt = getopt(argc, argv, "vaw:Y:G:s:h")) != -1) {
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
        case 'Y':
            pcap_filter = optarg;
            break;
        case 'G':
            pcap_gtpu_filter = optarg;
            break;
        case 's':
            search = optarg;
            break;
        case 'h':
            print_help();
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
        if (!process_file(argv[optind], outfile, append, pcap_filter, pcap_gtpu_filter, search, NULL, NULL))
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

            if (!process_file(argv[currfile], outfile, append, pcap_filter, pcap_gtpu_filter, search, &nloaded, &nmatching))
                return 2;
            printf("\n");
        }

        printf_verbose("Total number of loaded packets: %lu\n", nloaded);
        printf_verbose("Total number of matching packets: %lu\n", nmatching);
    }

    return 0;
}




