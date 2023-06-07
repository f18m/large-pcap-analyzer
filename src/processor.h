/*
 * processor.h
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

#ifndef PROCESSING_H_
#define PROCESSING_H_

//------------------------------------------------------------------------------
// Includes
//------------------------------------------------------------------------------

#include "packet.h"
#include <string>

//------------------------------------------------------------------------------
// IPacketProcessor
// This is an abstract class to represent any type of stateful packet processing
// that can be carried out by LPA
//------------------------------------------------------------------------------

class IPacketProcessor {
public:
    IPacketProcessor()
    {
        m_current_pass = 0;
    }

    ~IPacketProcessor() {}

    // some packet processor specialization might need to process each PCAP file twice:
    virtual bool needs_2passes() const
    {
        return false;
    }

    void set_pass_index(unsigned int passIdx) { m_current_pass = passIdx; }

    unsigned int get_pass_index() const { return m_current_pass; }

    // returns true if the processing is successful or false if it should be
    // aborted. NOTE: pktWasChanged will be set to true if output packet has been
    // filled or false if no action was performed on the input packet and thus the
    // caller should use the pktIn instance
    virtual bool process_packet(const Packet& pktIn, Packet& pktOut, unsigned int pktIdx, bool& pktWasChangedOut) = 0;

    // called after processing an entire PCAP file composed by "totNumPkts"
    virtual bool post_processing(const std::string& infile, unsigned int totNumPkts) = 0;

private:
    // configuration:
    unsigned int m_current_pass; // 0 or 1
};

#endif // PROCESSING_H_
