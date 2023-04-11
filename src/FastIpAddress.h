//------------------------------------------------------------------------------
// FastIpAddress.h: A simple class able to hold IPv4 and IPv6 addresses
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
#include <string.h>

#include "IpAddress.h" // provide interoperability with IpAddress_t

//---------------------------------------------------------------------------
// FastIpAddress
// A simple class able to hold IPv4 and IPv6 addresses
// and perform _fast_ conversion to string format.
//---------------------------------------------------------------------------
class FastIpAddress {
public:
    FastIpAddress()
    {
        addrFamily = 0;
    }

    FastIpAddress(const FastIpAddress& x) = default; // copy ctor
    FastIpAddress(FastIpAddress&& x) = default; // move ctor

    FastIpAddress(const struct in_addr& ipv4)
    {
        addrFamily = AF_INET;
        addr.ipv4 = ipv4;
    }
    FastIpAddress(const struct in6_addr& ipv6)
    {
        addrFamily = AF_INET6;
        addr.ipv6 = ipv6;
    }
    FastIpAddress(const std::string& addr)
    {
        fromString(addr);
    }
    FastIpAddress(const IpAddress_t& x)
    {
        fromIpAddress_t(x);
    }

    // ----------------------------------------------------------------------
    // Operators
    // ----------------------------------------------------------------------

    FastIpAddress& operator=(const FastIpAddress& rhs) = default;
    FastIpAddress& operator=(FastIpAddress&& rhs) = default;

    bool operator==(const FastIpAddress& rhs) const
    {
        if (addrFamily != rhs.addrFamily)
            return false;

        switch (addrFamily) {
        case AF_INET:
            return memcmp((const void*)&addr.ipv4, (const void*)&rhs.addr.ipv4, sizeof(addr.ipv4)) == 0;

        case AF_INET6:
            return memcmp((const void*)&addr.ipv6, (const void*)&rhs.addr.ipv6, sizeof(addr.ipv6)) == 0;

        default:
            return addrFamily == rhs.addrFamily;
        }
    }

    bool operator!=(const FastIpAddress& rhs) const
    {
        return !(*this == rhs);
    }

    bool operator<(const FastIpAddress& rhs) const
    {
        if (addrFamily == rhs.addrFamily) {
            switch (addrFamily) {
            case AF_INET:
                return memcmp((const void*)&addr.ipv4, (const void*)&rhs.addr.ipv4, sizeof(addr.ipv4)) < 0;

            case AF_INET6:
                return memcmp((const void*)&addr.ipv6, (const void*)&rhs.addr.ipv6, sizeof(addr.ipv6)) < 0;
            }
        }
        return addrFamily < rhs.addrFamily;
    }

    bool operator>(const FastIpAddress& rhs) const
    {
        if (addrFamily == rhs.addrFamily) {
            switch (addrFamily) {
            case AF_INET:
                return memcmp((const void*)&addr.ipv4, (const void*)&rhs.addr.ipv4, sizeof(addr.ipv4)) > 0;

            case AF_INET6:
                return memcmp((const void*)&addr.ipv6, (const void*)&rhs.addr.ipv6, sizeof(addr.ipv6)) > 0;
            }
        }
        return addrFamily > rhs.addrFamily;
    }

    // ----------------------------------------------------------------------
    // IpAddress_t helpers
    // ----------------------------------------------------------------------

    void fromIpAddress_t(const IpAddress_t& x)
    {
        if (x.ipVersion == 4) {
            addrFamily = AF_INET;
            addr.ipv4.s_addr = htonl(x.ipType.ipv4); // IpAddress_t stores IPv4 in HOST order
        } else if (x.ipVersion == 6) {
            addrFamily = AF_INET6;
            addr.ipv6 = x.ipType.ipv6;
        } else

        {
            addrFamily = 0;
        }
    }

    IpAddress_t toIpAddress_t() const
    {
        IpAddress_t ret;
        switch (addrFamily) {
        case AF_INET: {
            ret.ipVersion = 4;
            ret.ipType.ipv4 = ntohl(addr.ipv4.s_addr); // IpAddress_t stores IPv4 in HOST order
        } break;

        case AF_INET6: {
            ret.ipVersion = 6;
            ret.ipType.ipv6 = addr.ipv6;
        } break;

        default:
            ret.ipVersion = 0;
        }

        return ret;
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

        /* WARNING:
			if (inet_ntop(addrFamily, (const void*) &addr, bufOut, bufOutLen) == NULL)
				return "";

		  Above implementation turns out to be quite slow: inet_ntop() uses vfprintf() to format IPv4 addresses, which is very slow!!
		  See both glibc and musl:
		    https://github.com/bpowers/musl/blob/master/src/network/inet_ntop.c
		    https://repo.or.cz/w/glibc.git/blob/HEAD:/resolv/inet_ntop.c
		  nicely enough, vfprintf() is not used for IPv6 addresses (and anyway we don't need to optimize for speed for IPv6 case!)
		*/

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

    bool fromString(const std::string& addrstr)
    {
        if (inet_pton(AF_INET, addrstr.c_str(), &addr.ipv4) == 1) {
            addrFamily = AF_INET;
            return true;
        } else if (inet_pton(AF_INET6, addrstr.c_str(), &addr.ipv6) == 1) {
            addrFamily = AF_INET6;
            return true;
        } else {
            addrFamily = 0;
            return false;
        }
    }

    // ----------------------------------------------------------------------
    // Getters
    // ----------------------------------------------------------------------

    uint8_t getFamily() const
    {
        return addrFamily; // AF_INET or AF_INET6
    }

    unsigned int getIpVersion() const
    {
        switch (addrFamily) {
        case AF_INET:
            return 4;

        case AF_INET6:
            return 6;

        default:
            return 0;
        }
    }

    const struct in_addr& getIPv4() const
    {
        return addr.ipv4;
    }
    const struct in6_addr& getIPv6() const
    {
        return addr.ipv6;
    }

    bool isValid() const
    {
        return addrFamily != 0;
    }

    bool empty() const
    {
        return addrFamily == 0;
    }

    // ----------------------------------------------------------------------
    // Setters
    // ----------------------------------------------------------------------

    void reset()
    {
        addrFamily = 0;
        memset(&addr, 0, sizeof(addr));
    }

    void setIPv4NetworkOrder(uint32_t ipv4_netorder)
    {
        addrFamily = AF_INET;
        addr.ipv4.s_addr = ipv4_netorder;
    }
    void setIPv6NetworkOrder(unsigned int idx, uint32_t ipv6_dword_part)
    {
        assert(idx < 4);
        addrFamily = AF_INET6;
        addr.ipv6.__in6_u.__u6_addr32[idx] = ipv6_dword_part;
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
