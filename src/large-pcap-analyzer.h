/*
 * large-pcap-analyzer.h
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

#ifndef LPA_H_
#define LPA_H_

//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

#define KB (1024)
#define MB (1024 * 1024)
#define GB (1024 * 1024 * 1024)
#define MILLION (1000000)
#define SMALL_NUM (0.000001) // 1us
#define MAX_SNAPLEN (65535)
#define INVALID_FLOW_HASH (0)

#if !defined(PCAP_NETMASK_UNKNOWN)
/*
 * Value to pass to pcap_compile() as the netmask if you don't know what
 * the netmask is.
 */
#define PCAP_NETMASK_UNKNOWN 0xffffffff
#endif

#ifndef MIN
#define MIN(x, y) ((x) > (y) ? (y) : (x))
#endif /*MIN*/

#define LIKELY(x) __builtin_expect((x), 1)
#define UNLIKELY(x) __builtin_expect((x), 0)

//------------------------------------------------------------------------------
// App configuration
//------------------------------------------------------------------------------

class LPAConfig {
public:
    bool m_verbose = false;
    bool m_quiet = false;
    bool m_timestamp_analysis = false;
    bool m_parsing_stats = false;

    // technically this is not a configuration but the status of the application...
    // but I'm lazy and didn't create a separate global class just for this:
    bool m_termination_requested = false;
};

extern LPAConfig g_config;

#endif
