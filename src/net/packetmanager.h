// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_PACKET_MANAGER_H
#define ECCOIN_PACKET_MANAGER_H

#include <map>
#include <utility>
#include <vector>

#include "aodv.h"
#include "datapacket.h"
#include "net.h"
#include "pubkey.h"
#include "util/utiltime.h"
#include "validationinterface.h"

static const int64_t DEFAULT_PACKET_TIMEOUT = 30; // 30 seconds

extern CCriticalSection cs_main;

struct PacketBuffer
{
    // vRecievedPackets should be partially stored on disk at some point
    std::vector<CPacket> vRecievedPackets;
    // the protocol id using this buffer
    uint16_t nProtocolId;
    // the token needed for authentication to read vRecievedPackets
    // TODO : use a different token method because this one is very expensive to use often
    CPubKey boundPubkey;
    // used in the request buffer method for authentication
    uint64_t requestCount;

};

class CPacketManager
{
    // Data members
private:
    // protocolId : Buffer
    std::map<uint16_t, PacketBuffer> mapBuffers;
    // partial packets waiting for all required data segments to reconstruct
    // map stores nonce, time and when packet is complete it is removed from this
    // map and stored in our messages vector
    std::map<uint64_t, int64_t> mapPacketLastUpdated;

    // a map holding incomplete packets sorted by nonce
    std::map<uint64_t, CPacket> mapPartialPackets;

public:


    // Methods
private:
    // disallow copies
    CPacketManager(const CPacketManager &pman){}
    void FinalizePacket(const uint64_t &nonce, std::map<uint64_t, CPacket>::iterator iter);

public:
    CPacketManager()
    {
        mapBuffers.clear();
        mapPacketLastUpdated.clear();
        mapPartialPackets.clear();
    }
    bool BindBuffer(uint16_t protocolId, CPubKey authPubkey);

    bool ProcessPacketHeader(const uint64_t &nonce, CPacketHeader &newHeader);

    bool ProcessDataSegment(const uint64_t &nonce, CPacketDataSegment newSegment);

    void CheckForTimeouts();

    bool SendPacket(const std::vector<unsigned char> &vPubKey, const uint8_t &nProtocolId, const uint8_t &nProtocolVersion, const std::vector<uint8_t> vData);

    bool GetBuffer(uint8_t &protocolId, std::vector<CPacket> &bufferData, const std::string &sig);
};

extern CPacketManager g_packetman;

#endif
