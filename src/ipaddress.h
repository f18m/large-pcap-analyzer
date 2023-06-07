/*
 * ipaddress.h
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

#pragma once

#include <arpa/inet.h>
#include <assert.h>

#include <string>

#include "hash_algo.h"

#define IPV6_LEN (16)

//---------------------------------------------------------------------------
// IpAddress
// A simple class that represents either an IPv4 or IPv6 address
//---------------------------------------------------------------------------
class IpAddress {
public:
    IpAddress()
    {
        addrFamily = 0;
    }

    IpAddress(const struct in_addr& ipv4)
    {
        addrFamily = AF_INET;
        addr.ipv4 = ipv4;
    }
    IpAddress(const struct in6_addr& ipv6)
    {
        addrFamily = AF_INET6;
        addr.ipv6 = ipv6;
    }

    // ----------------------------------------------------------------------
    // IPv4 or IPv6 hashing
    // ----------------------------------------------------------------------

    uint64_t get_hash() const
    {
        switch (addrFamily) {
        case AF_INET:
            return FastHash64((const char*)&addr.ipv4.s_addr, sizeof(addr.ipv4.s_addr), 0);
        case AF_INET6:
            return FastHash64((const char*)&addr.ipv4.s_addr, IPV6_LEN, 0);

        default:
            return 0;
        }
    }

    // ----------------------------------------------------------------------
    // String conversion
    // ----------------------------------------------------------------------

    std::string toString() const
    {
        if (addrFamily == 0)
            return "";

        const size_t bufOutLen = 128;
        char bufOut[bufOutLen + 1];

        switch (addrFamily) {
        case AF_INET:
            return ipv4ul_to_string(ntohl(addr.ipv4.s_addr), bufOut, bufOutLen);

        case AF_INET6:
            if (inet_ntop(addrFamily, (const void*)&addr, bufOut, bufOutLen) == NULL)
                return "";
            return std::string(bufOut);

        default:
            bufOut[0] = 0;
            return bufOut;
        }
    }

private:
    // Convert IPv4 stored as 32bits in HOST order to a string.
    static inline char* ipv4ul_to_string(uint32_t addr, char* buf, size_t bufLen)
    {
        char *cp, *retStr;
        uint32_t byte;
        int n;
        cp = &buf[bufLen];
        *--cp = '\0';
        n = 4;
        do {
            byte = addr & 0xff;
            *--cp = byte % 10 + '0';
            byte /= 10;
            if (byte > 0) {
                *--cp = byte % 10 + '0';
                byte /= 10;
                if (byte > 0)
                    *--cp = byte + '0';
            }
            *--cp = '.';
            addr >>= 8;
        } while (--n > 0);
        /* Convert the string to lowercase */
        retStr = (char*)((cp + 1));
        return (retStr);
    }

private:
    uint8_t addrFamily; // AF_INET or AF_INET6
    union {
        // NOTE: both these structures and the POSIX APIs that manipulate them will store the IP
        // 		 addresses in NETWORK order:
        struct in6_addr ipv6; // this is 16 bytes long
        struct in_addr ipv4; // this is 4 bytes long
    } addr;
};
