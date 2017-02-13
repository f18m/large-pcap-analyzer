#ifndef PARSE_H_
#define PARSE_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "large-pcap-analyzer.h"


//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Types
//------------------------------------------------------------------------------

typedef enum
{
	GPRC_VALID_PKT = 0,

	GPRC_NOT_GTPU_PKT = -1,
	GPRC_TOO_SHORT_PKT = -2,
	GPRC_INVALID_PKT = -3,
} ParserRetCode_t;

typedef enum
{
	FLOW_FOUND_SYN,
	FLOW_FOUND_SYN_AND_SYNACK,
} FlowStatus_t;

typedef uint64_t   flow_hash_t;								// init to INVALID_FLOW_HASH
typedef std::map<flow_hash_t /* key */, FlowStatus_t /* value */>     flow_map_t;

class ParsingStats
{
public:
	ParsingStats()
	{
		pkts_valid_gtpu_transport=0;
		pkts_valid_gtpu_ip=0;
		pkts_valid_tranport=0;
		pkts_valid_ip=0;
		pkts_invalid=0;
		pkts_total=0;
	}

	double perc_pkts_valid_gtpu_transport() const			{ return 100.0*double(pkts_valid_gtpu_transport)/double(pkts_total); }
	double perc_pkts_valid_gtpu_ip() const					{ return 100.0*double(pkts_valid_gtpu_ip)/double(pkts_total); }
	double perc_pkts_valid_tranport() const					{ return 100.0*double(pkts_valid_tranport)/double(pkts_total); }
	double perc_pkts_valid_ip() const						{ return 100.0*double(pkts_valid_ip)/double(pkts_total); }
	double perc_pkts_invalid() const						{ return 100.0*double(pkts_invalid)/double(pkts_total); }

public:
	uint64_t 					pkts_valid_gtpu_transport;
	uint64_t 					pkts_valid_gtpu_ip;
	uint64_t 					pkts_valid_tranport;
	uint64_t 					pkts_valid_ip;
	uint64_t 					pkts_invalid;

	uint64_t 					pkts_total;
};


//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

extern ParserRetCode_t get_transport_offset(const struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetTransportOut, int* ipprotOut);
extern ParserRetCode_t get_gtpu_inner_ip_offset(const struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetIpInner, int* ipver);
extern ParserRetCode_t get_gtpu_inner_transport_offset(const struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, int* offsetTransportInner, int* ipprotInner);

extern void update_parsing_stats(const struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet, ParsingStats& outstats);

extern flow_hash_t compute_flow_hash(const struct pcap_pkthdr* pcap_header, const u_char* const pcap_packet);

#endif		// PARSE_H_
