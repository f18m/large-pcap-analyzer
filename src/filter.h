#ifndef FILTER_H_
#define FILTER_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "large-pcap-analyzer.h"
#include "parse.h"


//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

class FilterCriteria
{
public:
	FilterCriteria()
	{
		memset(&capture_filter, 0, sizeof(capture_filter));
		memset(&gtpu_filter, 0, sizeof(gtpu_filter));
		capture_filter_set = FALSE;
		gtpu_filter_set = FALSE;
		valid_tcp_filter = FALSE;
		string_filter = NULL;
	}

	~FilterCriteria()
	{
		if (capture_filter_set)
			pcap_freecode(&capture_filter);
		if (gtpu_filter_set)
			pcap_freecode(&gtpu_filter);
	}

public:
	struct bpf_program 			capture_filter;
	bool 						capture_filter_set;

	struct bpf_program 			gtpu_filter;
	bool 						gtpu_filter_set;

	const char* 				string_filter;

	bool 						valid_tcp_filter;
	flow_map_t 					valid_tcp_firstpass_flows;			// contains the result of the 1st pass
};


//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

extern bool must_be_saved(struct pcap_pkthdr* pcap_header, const u_char* pcap_packet,
							const FilterCriteria* filter, bool* is_gtpu);

#endif	// FILTER_H_
