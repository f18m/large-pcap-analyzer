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

typedef enum
{
	TCP_FILTER_NOT_ACTIVE,
	TCP_FILTER_CONN_HAVING_SYN,
	TCP_FILTER_CONN_HAVING_FULL_3WAY_HANDSHAKE,
} TcpFilterMode;

class FilterCriteria
{
public:
	FilterCriteria()
	{
		memset(&capture_filter, 0, sizeof(capture_filter));
		memset(&gtpu_filter, 0, sizeof(gtpu_filter));
		capture_filter_set = false;
		gtpu_filter_set = false;
		valid_tcp_filter_mode = TCP_FILTER_NOT_ACTIVE;
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

	TcpFilterMode				valid_tcp_filter_mode;
	flow_map_t 					valid_tcp_firstpass_flows;			// contains the result of the 1st pass
};


//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

extern bool must_be_saved(const Packet& pkt, const FilterCriteria* filter, bool* is_gtpu);

#endif	// FILTER_H_
