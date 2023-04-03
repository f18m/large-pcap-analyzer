/*
 * pcap_helpers.h
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

#ifndef PCAP_HELPERS_H_
#define PCAP_HELPERS_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "large-pcap-analyzer.h"
#include <string>

// libpcap dependency:
// NOTE: in version 1.7.x there is no pcap/pcap.h, just a pcap.h apparently:
//#include <pcap/pcap.h>
#include <pcap.h>

//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

pcap_dumper_t* pcap_dump_append(pcap_t* pcap, const char* filename);

// NOTE: apparently pcap_compile_nopcap() got deprecated six months ago in libpcap v1.11.0:
//    https://github.com/the-tcpdump-group/libpcap/blob/753dc6beddea935c4f0365c3e8634b44db527a82/CHANGES#L19
// so we provide our own substitution (also featuring simplified argument list)
int pcap_compile_bpf(struct bpf_program* program, const char* buf);

#endif // PCAP_HELPERS_H_
