/*
 * printf_helpers.cpp
 *
 * Author: Francesco Montorsi
 * Website: https://github.com/f18m/large-pcap-analyzer
 *
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

#include "printf_helpers.h"
#include "large-pcap-analyzer.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>

//------------------------------------------------------------------------------
// Global Functions
//------------------------------------------------------------------------------

void printf_verbose(const char* fmtstr, ...)
{
    va_list args;
    va_start(args, fmtstr);
    if (g_config.m_verbose) {
        assert(!g_config.m_quiet);
        vprintf(fmtstr, args);
    }
    va_end(args);
}

void printf_normal(const char* fmtstr, ...)
{
    va_list args;
    va_start(args, fmtstr);
    if (!g_config.m_quiet)
        vprintf(fmtstr, args);
    va_end(args);
}

void printf_quiet(const char* fmtstr, ...)
{
    va_list args;
    va_start(args, fmtstr);
    if (g_config.m_quiet)
        vprintf(fmtstr, args);
    va_end(args);
}

void printf_error(const char* fmtstr, ...)
{
    va_list args;
    va_start(args, fmtstr);
    // if (g_quiet) // even if quiet mode is ON, do print errors out
    vfprintf(stderr, fmtstr, args);
    va_end(args);
}
