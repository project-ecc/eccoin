// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "packetmanager.h"

////////////////////////
///
///  Private
///
void CPacketManager::FinalizePacket(const uint64_t &nonce, std::map<uint64_t, CPacket>::iterator iter)
{
    uint8_t protocolId = iter->second.nProtocolId;
    if (mapBuffers.count(protocolId) == 0)
    {
        // this is an error, the proper entry should have been made by BindBuffer
        return;
    }
    else
    {
        mapBuffers[protocolId].vRecievedPackets.push_back(std::move(iter->second));
    }
    mapPacketLastUpdated.erase(nonce);
    mapPartialPackets.erase(nonce);
    GetMainSignals().PacketComplete(protocolId);
}


////////////////////////
///
///  Public
///

bool CPacketManager::BindBuffer(uint16_t protocolId, CPubKey authPubkey)
{
    if (mapBuffers.count(protocolId) != 0)
    {
        return false;
    }
    PacketBuffer newBuffer;
    newBuffer.nProtocolId = protocolId;
    newBuffer.boundPubkey = authPubkey;
    mapBuffers.emplace(protocolId, std::move(newBuffer));
    return true;
}

bool CPacketManager::ProcessPacketHeader(const uint64_t &nonce, CPacketHeader &newHeader)
{
    if (mapPartialPackets.find(nonce) != mapPartialPackets.end())
    {
        return false;
    }
    if (mapBuffers.find(newHeader.nProtocolId) == mapBuffers.end())
    {
        // protocolId needs to be bound by BindBuffer
        return false;
    }
    CPacket newPacket(newHeader);
    mapPartialPackets.emplace(nonce, std::move(newPacket));
    mapPacketLastUpdated.emplace(nonce, GetTime());
    return true;
}

bool CPacketManager::ProcessDataSegment(const uint64_t &nonce, CPacketDataSegment newSegment)
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

void CPacketManager::CheckForTimeouts()
{
    // TODO : implement a thread to check for packet timeouts once a minute,
    // a timeout is any partial packet that hasnt been updated in 30 seconds or more
}

bool CPacketManager::SendPacket(const std::vector<unsigned char> &vPubKey, const uint8_t &nProtocolId, const uint8_t &nProtocolVersion, const std::vector<uint8_t> vData)
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
    // segments might not be needed. it is a good way to keep message sizes low to prevent a DOS by sending someone an infinitely
    // large message but might now be necessary
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

bool CPacketManager::GetBuffer(uint8_t &protocolId, std::vector<CPacket> &bufferData, const std::string &sig)
{
    if (mapBuffers.count(protocolId) == 1)
    {
        PacketBuffer buffer = mapBuffers[protocolId];
        bool fInvalid = false;
        std::vector<unsigned char> vchSig = DecodeBase64(sig.c_str(), &fInvalid);
        if (fInvalid)
        {
            return false;
        }
        CHashWriter ss(SER_GETHASH, 0);
        ss << std::string("GetBUfferRequest:");
        std::string requestMessage = std::to_string(protocolId) + std::to_string(buffer.requestCount);
        ss << requestMessage;
        CPubKey pubkey;
        if (!pubkey.RecoverCompact(ss.GetHash(), vchSig))
        {
            return false;
        }
        if (pubkey.GetID() == buffer.boundPubkey.GetID())
        {
            return false;
        }
        bufferData = buffer.vRecievedPackets;
        mapBuffers[protocolId].vRecievedPackets.clear();
        return true;
    }
    return false;
}
