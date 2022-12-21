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
// Time macros
//------------------------------------------------------------------------------

#define SEC_TO_NSEC(x) (x * (1E9))
#define SEC_TO_USEC(x) (x * (1E6))

#define NSEC_TO_SEC(x) (x / (1E9))
#define NSEC_TO_USEC(x) (x / (1E6))

#define USEC_TO_SEC(x) (x / (1E6))

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

extern void printf_verbose(const char* fmtstr, ...);
extern void printf_normal(const char* fmtstr, ...);
extern void printf_error(const char* fmtstr, ...);

#endif
