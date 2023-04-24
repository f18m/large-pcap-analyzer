//------------------------------------------------------------------------------
// ipaddress.h: A simple class able to hold IPv4 and IPv6 addresses
// (C) Copyright 2020 Empirix Inc.
//
//  Created on: Jan, 2020
//      Author: fmontorsi
//
// Description:
// C++ alternative to IpAddress_t structures, with emphasis on
//  - memory compactness
//  - speed in conversion from/to string
// Unlike IpAddress_t the endianness of IP addresses here is coherent between
// IPv4 and IPv6. Moreover the class provides a clean C++ API.
//------------------------------------------------------------------------------

#pragma once

#include <arpa/inet.h>
#include <assert.h>

#include <string>

//---------------------------------------------------------------------------
// IpAddress
// A simple class able to hold IPv4 and IPv6 addresses
// and perform _fast_ conversion to string format.
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
