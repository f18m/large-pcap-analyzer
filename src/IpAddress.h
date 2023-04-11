//------------------------------------------------------------------------------
// IpAddress_t.h: defines structure+helpers to manipulate IPv4/IPv6 addresses
// (C) Copyright 2014 Empirix Inc.
//
//  Created on: Oct 7, 2014
//
// Description:
// DEPRECATED COLLECTION OF C-STYLE IPADDRESS UTILITIES.
// WHEN WRITING C++ CODE, PLEASE USE EITHER
// - FastIpAddress, see header in this same repo
// - boost::asio::ip::address, see https://www.boost.org/doc/libs/1_66_0/doc/html/boost_asio/reference/ip__address.html
//------------------------------------------------------------------------------

#ifndef __IPADDRESS_H__
#define __IPADDRESS_H__

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h> // for strtoul()
#include <string.h> // for memcmp()

#ifdef __cplusplus
#include <string>
#include <tuple>
#include <vector>
#endif

//------------------------------------------------------------------------------
// constants
//------------------------------------------------------------------------------

#define IPV4_LEN (4)
#define IPV6_LEN (16)
#define MAX_IP_LENGTH (41)

enum {
    UNICAST_IPADDR_TYPE,
    MULTICAST_IPADDR_TYPE,
    BROADCAST_IPADDR_TYPE,
    ANYCAST_IPADDR_TYPE
};

//------------------------------------------------------------------------------
// macros
//------------------------------------------------------------------------------

// IPADDR_CREATE_ROUTING_NETMASK() macro creates a 64bit integer containing the specified
// number of bits set to 1 in the most-significant digits, rest set to zero.
// The generated value can be used in logical AND with an IPv4 address to obtain the subnet
// associated with a specific routing prefix (which usually is specified in CIDR notation).
//
// IMPORTANT1: routing_prefix must be in the range [0-32] (i.e., IPv4)
// IMPORTANT2: the returned value is in HOST order, so use logical AND only with addresses
//             stored in HOST order
//
#define IPADDR_CREATE_ROUTING_NETMASK(routing_prefix) (((uint64_t)(0xFFFFFFFF00000000) >> (routing_prefix)) & 0xFFFFFFFF)

//------------------------------------------------------------------------------
// types
//------------------------------------------------------------------------------

typedef struct IpAddress_s {
    uint8_t ipVersion; /* Either 4 or 6 */

    union {
        struct in6_addr ipv6; // this is 16 bytes long, internally contains the IPv6 in NETWORK order
        uint32_t ipv4; // this is 4 bytes long; string_to_ip() stores here the IPv4 in HOST order
    } ipType;

} IpAddress_t;

// for compatibility provide a few synonyms historically used inside our sources:
typedef IpAddress_t IpAddress;
typedef IpAddress_t ipAddress;

typedef struct IpAddressCIDR_s {
    IpAddress_t ip;
    uint8_t routing_prefix;
} IpAddressCIDR_t; // this is is useful for holding IP addresses in CIDR format like "192.168.0.0/16"

typedef struct IpAddressWithMask_s {
    IpAddress_t ip; // masked IP address. It must always hold that "ip & mask == ip"
    IpAddress_t mask;
} IpAddressWithMask_t; // this is is useful for holding IP addresses + bitmask format like "192.168.0.0 with mask 0.255.0.0" that cannot fit CIDR format

typedef struct IpAddressPair_s {
    union {
        struct in6_addr ipv6; // this is 16 bytes long, internally contains the IPv6 in NETWORK order
        uint32_t ipv4; // this is 4 bytes long; for coherency with IpAddress_t, store here the IPv4 in HOST order
    } ipSrc;

    union {
        struct in6_addr ipv6; // this is 16 bytes long, internally contains the IPv6 in NETWORK order
        uint32_t ipv4; // this is 4 bytes long; for coherency with IpAddress_t, store here the IPv4 in HOST order
    } ipDst;

    // keep as last field to ensure that src/dst addresses are memory aligned
    uint8_t ipVersion; /* Either 4 or 6 */

} __attribute__((__packed__)) IpAddressPair_t;

//------------------------------------------------------------------------------
// globals
//------------------------------------------------------------------------------

extern const IpAddress_t IpAddress_empty;

//------------------------------------------------------------------------------
// utils to convert string <-> numeric IP
//------------------------------------------------------------------------------

// Convert IPv4 stored as 32bits in HOST order to a string.
char* ipv4ul_to_string(uint32_t addr, char* buf, size_t bufLen);

// Convert string format of ipv4 address (xxx.xxx.xxx.xxx) into unsigned long integer
int ipv4string_to_ul(const char* ip, uint32_t* plong);

// Convert to a string an IPv4 or IPv6 network byte order address.
char* ip_ul_to_string(uint8_t ipVersion, uint32_t* addr, char* buf, size_t bufLen);

// Converts IpAddress_t to string. Return NULL in case of errors
char* ip_to_string(const IpAddress_t* addr, char* bufOut, size_t bufOutLen);

// Converts string format of ip address (ipv4 or ipv6) into "IpAddress_t" format. Return false in case of errors
bool string_to_ip_ver(int addrvers, const char* addrstr, IpAddress_t* ipaddrOut);
bool string_to_ip(const char* addrstr, IpAddress_t* ipaddr);

// Old names for compat:
#define ip4_to_string ipv4ul_to_string
#define ipv4toul ipv4string_to_ul

#ifdef __cplusplus

// fallbacks to the C versions:

inline char* ip_to_string(const IpAddress_t& addr, char* buf, uint32_t bufLen)
{
    return ip_to_string(&addr, buf, bufLen);
}
inline std::string ipToString(const IpAddress_t& addr)
{
    char buff[64];
    return (ip_to_string(addr, buff, 64));
}
inline bool string_to_ip(int addrvers, const char* addrstr, IpAddress_t& ipaddr)
{
    return string_to_ip_ver(addrvers, addrstr, &ipaddr);
}
inline bool string_to_ip(const char* addrstr, IpAddress_t& ipaddr)
{
    return string_to_ip(addrstr, &ipaddr);
}
inline uint32_t string_to_ipv4(const char* addrstr)
{
    uint32_t ipv4 = 0;
    inet_pton(AF_INET, addrstr, &ipv4);
    return htonl(ipv4);
}

// C++ only functions:

bool string_to_cidr(const char* string, IpAddressCIDR_t& out, bool set_to_zero_subnet_bits = true);
std::string cidr_to_string(const IpAddressCIDR_t& toConv);

bool string_to_ipmask(const char* ip, const char* mask, IpAddressWithMask_t& out);

// Convert to string a (src, dst) ip address pair.
// The v4 version shall be specified in host byte order, while the v6 in network byte order.
std::tuple<std::string, std::string> ipPairToString(const IpAddressPair_t& ip_pair);

#endif // C++

//------------------------------------------------------------------------------
// utils for comparison
//------------------------------------------------------------------------------

#ifdef __cplusplus

static inline bool operator==(const IpAddress_t& src, const IpAddress_t& dst)
{
    if (src.ipVersion != dst.ipVersion)
        return (false);

    if (src.ipVersion == 4) {
        return (src.ipType.ipv4 == dst.ipType.ipv4);
    } else if (src.ipVersion == 6) {
        return (!memcmp(&src.ipType.ipv6, &dst.ipType.ipv6, sizeof(struct in6_addr)));
    }
    //all unknown ip version address are equal!!!
    return true;
}

static inline bool operator!=(const IpAddress_t& src, const IpAddress_t& dst)
{
    return !(src == dst);
}

static inline bool operator<(const IpAddress_t& x, const IpAddress_t& y)
{
    if (x.ipVersion == y.ipVersion) {
        if (x.ipVersion == 4)
            return memcmp(&x.ipType.ipv4, &y.ipType.ipv4, sizeof(x.ipType.ipv4)) < 0;
        if (x.ipVersion == 6)
            return memcmp(&x.ipType.ipv6, &y.ipType.ipv6, sizeof(x.ipType.ipv6)) < 0;
        //tutti gli ip che non hanno versione sono uguali
        return false;
    } else
        return (x.ipVersion < y.ipVersion);
}

static inline bool operator>(const IpAddress_t& x, const IpAddress_t& y)
{
    if (x.ipVersion == y.ipVersion) {
        if (x.ipVersion == 4)
            return memcmp(&x.ipType.ipv4, &y.ipType.ipv4, sizeof(x.ipType.ipv4)) > 0;
        if (x.ipVersion == 6)
            return memcmp(&x.ipType.ipv6, &y.ipType.ipv6, sizeof(x.ipType.ipv6)) > 0;
        //tutti gli ip che non hanno versione sono uguali
        return false;
    } else
        return (x.ipVersion > y.ipVersion);
}

static inline bool ip_cmp(const IpAddress_t& src, const IpAddress_t& dst)
{
    if (src.ipVersion != dst.ipVersion)
        return false;

    if (src.ipVersion == 4)
        return (src.ipType.ipv4 == dst.ipType.ipv4);
    else if (src.ipVersion == 6)
        return (!memcmp(&src.ipType.ipv6, &dst.ipType.ipv6, sizeof(struct in6_addr)));

    //all unknown ip version address are equal!!!
    return true;
}

static inline bool ip_cmp_ex(const IpAddress_t& src, const IpAddress_t& dst)
{
    if (src.ipVersion == dst.ipVersion) {
        if (src.ipVersion == 4) {
            return memcmp(&src.ipType.ipv4, &dst.ipType.ipv4, sizeof(src.ipType.ipv4)) > 0;
        } else if (src.ipVersion == 6) {
            return memcmp(&src.ipType.ipv6, &dst.ipType.ipv6, sizeof(src.ipType.ipv6)) > 0;
        } else {
            return false;
        }
    } else
        return (src.ipVersion < dst.ipVersion);
}

//------------------------------------------------------------------------------
// utils misc
//------------------------------------------------------------------------------

// This function checks if an IP is "null", that is it has every bit == 0
static inline bool ip_is_null(const ipAddress& ip)
{
    bool isNull = false;
    ipAddress nullIp;
    memset(&nullIp, 0, sizeof(ipAddress));

    switch (ip.ipVersion) {
    case 4:
        nullIp.ipVersion = 4;
        if (ip == nullIp)
            isNull = true;
        break;

    case 6:
        nullIp.ipVersion = 6;
        if (ip == nullIp)
            isNull = true;
        break;

    default:
        isNull = true;
        break;
    }

    return isNull;
}

static inline void ip_copy(IpAddress_t& src, const IpAddress_t& dst)
{
    src.ipVersion = dst.ipVersion;
    if (src.ipVersion == 4) {
        src.ipType.ipv4 = dst.ipType.ipv4;
    } else if (src.ipVersion == 6) {
        memcpy(&src.ipType.ipv6, &dst.ipType.ipv6, sizeof(struct in6_addr));
    } else
        memset(&src, 0, sizeof(IpAddress_t));
}

static inline size_t ip_hash(const IpAddress_t& ip) // modified muffer_hash() variant
{
    unsigned char* key = (unsigned char*)&ip;
    unsigned int key_len = sizeof(IpAddress_t);

    switch (ip.ipVersion) {
    case 4:
        key = (unsigned char*)&ip.ipType.ipv4;
        key_len = 4;
        break;

    case 6:
        key = (unsigned char*)&ip.ipType.ipv6;
        key_len = 16;
        break;

    default:
        return 0;
    }

    size_t hash = 0;
    uint32_t i;

    for (i = 0; i < key_len; i++) {
        // NOTE: cppcheck disabled check looks a false positive since cppcheck 2.5 (was passing with cppcheck 2.3)
        hash += key[i]; // cppcheck-suppress objectIndex
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

// for use with std::unordered_map
namespace std {
template <>
struct hash<IpAddress_t> {
    size_t operator()(const IpAddress_t& ip) const
    {
        return (size_t)ip_hash(ip);
    }
};
}

unsigned int ipaddr_routingscheme(const IpAddress& addr);
bool clear_subnet_bits_from_ip(IpAddressCIDR_t& out);
uint64_t num_address_in_cidr(const IpAddressCIDR_t& c);
bool stringCidrToIpMask(const char* ipCidrString, IpAddressWithMask_t& out);
bool IpAddressCIDR_sort_function(const IpAddressCIDR_t& a, const IpAddressCIDR_t& b); // can be used with std::sort()

bool ip_matches_subnetwork(const IpAddress_t& ip, const IpAddressWithMask_t& ipWithMask);

#endif // C++

#endif // __IPADDRESS_H__
