/*
 * hash_algo.cpp
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

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "hash_algo.h"

//------------------------------------------------------------------------------
// Constants
//------------------------------------------------------------------------------

#if defined(__GNUC__) && __GNUC__ >= 7
#define GCC_ALLOW_FALLTHROUGH __attribute__((fallthrough))
#else
#define GCC_ALLOW_FALLTHROUGH /* empty macro */
#endif

//------------------------------------------------------------------------------
// Hash Functions
//------------------------------------------------------------------------------

// Compression function for Merkle-Damgard construction.
#define fasthash64_mix(h)             \
    ({                                \
        (h) ^= (h) >> 23;             \
        (h) *= 0x2127599bf4325c37ULL; \
        (h) ^= (h) >> 47;             \
    })

uint64_t FastHash64(const char* buf, uint32_t len, uint64_t seed)
{
    const uint64_t m = 0x880355f21e6d1965ULL;
    const uint64_t* pos = (const uint64_t*)buf;
    const uint64_t* end = pos + (len / 8);
    const unsigned char* pos2;
    uint64_t h = seed ^ (len * m);
    uint64_t v;

    while (pos != end) {
        v = *pos++;
        h ^= fasthash64_mix(v);
        h *= m;
    }

    pos2 = (const unsigned char*)pos;
    v = 0;

    switch (len & 7) {
    case 7:
        v ^= (uint64_t)pos2[6] << 48;
        GCC_ALLOW_FALLTHROUGH;
    case 6:
        v ^= (uint64_t)pos2[5] << 40;
        GCC_ALLOW_FALLTHROUGH;
    case 5:
        v ^= (uint64_t)pos2[4] << 32;
        GCC_ALLOW_FALLTHROUGH;
    case 4:
        v ^= (uint64_t)pos2[3] << 24;
        GCC_ALLOW_FALLTHROUGH;
    case 3:
        v ^= (uint64_t)pos2[2] << 16;
        GCC_ALLOW_FALLTHROUGH;
    case 2:
        v ^= (uint64_t)pos2[1] << 8;
        GCC_ALLOW_FALLTHROUGH;
    case 1:
        v ^= (uint64_t)pos2[0];
        h ^= fasthash64_mix(v);
        h *= m;
        break;
    }

    return fasthash64_mix(h);
}
