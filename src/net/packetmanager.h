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
    uint8_t nProtocolId;
};

class CPacketManager
{
    // Data members
private:
    // protocolId : Buffer
    std::map<uint8_t, PacketBuffer> mapBuffers;
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
    void FinalizePacket(const uint64_t &nonce, std::map<uint64_t, CPacket>::iterator iter)
    {
        uint8_t &protocolId = iter->second.nProtocolId;
        if (mapBuffers.count(protocolId) == 0)
        {
            PacketBuffer newBuffer;
            newBuffer.vRecievedPackets.push_back(std::move(iter->second));
            mapBuffers.emplace(protocolId, std::move(newBuffer));
        }
        else
        {
            mapBuffers[protocolId].vRecievedPackets.push_back(std::move(iter->second));
        }
        mapPacketLastUpdated.erase(nonce);
        mapPartialPackets.erase(nonce);
        GetMainSignals().PacketComplete(protocolId);
    }

public:
    CPacketManager()
    {
        mapBuffers.clear();
        mapPacketLastUpdated.clear();
        mapPartialPackets.clear();
    }

    bool ProcessPacketHeader(const uint64_t &nonce, CPacketHeader &newHeader)
    {
        if (mapPartialPackets.find(nonce) != mapPartialPackets.end())
        {
            return false;
        }
        CPacket newPacket(newHeader);
        mapPartialPackets.emplace(nonce, std::move(newPacket));
        mapPacketLastUpdated.emplace(nonce, GetTime());
        return true;
    }

    bool ProcessDataSegment(const uint64_t &nonce, CPacketDataSegment newSegment)
    {
        std::map<uint64_t, int64_t>::iterator updateIter;
        std::map<uint64_t, CPacket>::iterator partialIter;
        partialIter = mapPartialPackets.find(nonce);
        updateIter = mapPacketLastUpdated.find(nonce);
        if (partialIter == mapPartialPackets.end() || updateIter == mapPacketLastUpdated.end())
        {
            return false;
        }
        if (!partialIter->second.InsertData(newSegment))
        {
            return false;
        }
        updateIter->second = GetTime();
        if (partialIter->second.IsComplete())
        {
            FinalizePacket(nonce, partialIter);
        }
        return true;
    }

    void CheckForTimeouts()
    {
        // TODO : implement a thread to check for packet timeouts once a minute,
        // a timeout is any partial packet that hasnt been updated in 30 seconds or more
    }

    bool SendPacket(const std::vector<unsigned char> &vPubKey, const uint8_t &nProtocolId, const uint8_t &nProtocolVersion, const std::vector<uint8_t> vData)
    {
        NodeId peerNode;
        if (!g_aodvtable.GetKeyNode(vPubKey, peerNode))
        {
            return false;
        }
        CPubKey searchKey(vPubKey);
        CPacket newPacket(nProtocolId, nProtocolVersion);
        newPacket.PushBackData(vData);

        uint64_t nonce = 0;
        while (nonce == 0)
        {
            GetRandBytes((uint8_t *)&nonce, sizeof(nonce));
        }
        std::vector<CPacketDataSegment> segments = newPacket.GetSegments();
        {
            LOCK(cs_main);
            g_connman->PushMessageToId(peerNode, NetMsgType::SPH, nonce, searchKey, newPacket.GetHeader());
            for (auto segment : segments)
            {
                g_connman->PushMessageToId(peerNode, NetMsgType::SPD, nonce, searchKey, segment);
            }
        }
        return true;
    }

    bool GetBuffer(uint8_t &protocolId, PacketBuffer &buffer)
    {
        if (mapBuffers.count(protocolId) == 1)
        {
            buffer = mapBuffers[protocolId];
            mapBuffers[protocolId].vRecievedPackets.clear();
            return true;
        }
        return false;
    }
};

extern CPacketManager g_packetman;

#endif
