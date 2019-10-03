// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_DATA_PACKET_H
#define ECCOIN_DATA_PACKET_H

#include "serialize.h"
#include "uint256.h"
#include "util/utiltime.h"

#include <inttypes.h>
#include <random>
#include <vector>

const uint64_t PACKET_HEADER_SIZE = 46; // 46 bytes
const uint64_t MEGABYTE = 1000000;
const uint64_t MAX_DATA_SEGMENT_SIZE = 10 * MEGABYTE;
const uint8_t PACKET_VERSION = 1;

class CPacketHeader
{
public:
    uint8_t nPacketVersion;
    uint8_t nProtocolId;
    uint8_t nProtocolVersion;
    uint64_t nTotalLength; // header + data in bytes (does not include extra vector serialization bytes)
    uint16_t nIdenfitication; // randomly generated
    uint256 nDataChecksum; // sha256 checksum

    CPacketHeader() { SetNull(); }
    CPacketHeader(uint8_t nProtocolIdIn, uint8_t nProtocolVersionIn)
    {
        nProtocolId = nProtocolIdIn;
        nProtocolVersion = nProtocolVersionIn;
        GenerateNewIdentifier();
    }

    ADD_SERIALIZE_METHODS
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nPacketVersion);
        READWRITE(nProtocolId);
        READWRITE(nProtocolVersion);
        READWRITE(nTotalLength);
        READWRITE(nIdenfitication);
        READWRITE(nDataChecksum);
    }

    void SetNull()
    {
        nPacketVersion = PACKET_VERSION;
        nProtocolVersion = 0;
        nTotalLength = PACKET_HEADER_SIZE;
        nIdenfitication = 0;
        nProtocolId = 0;
        nDataChecksum.SetNull();
    }

    void CalculateTotalLength(uint64_t datasize) { nTotalLength = PACKET_HEADER_SIZE + datasize; }
    void GenerateNewIdentifier()
    {
        uint64_t seed = GetTime();
        std::mt19937_64 rand(seed); // Standard mersenne_twister_engine seeded with rd()
        nIdenfitication = rand() % std::numeric_limits<uint16_t>::max();
    }
};


// used to send on the network only. these are created and destroyed sending/reading the data,
// we store their data in the packet but dont store the data segment class anywhere
class CPacketDataSegment
{
    // Data members
private:
    uint8_t nFlags;
    uint32_t nFragmentOffset;
    std::vector<uint8_t> vData;

public:
    // Methods
private:
public:
    CPacketDataSegment()
    {
        nFlags = 0;
        nFragmentOffset = 0;
        vData.clear();
    }
    CPacketDataSegment(uint8_t nFlagsIn, uint32_t nFragmentOffsetIn)
    {
        nFlags = nFlagsIn;
        nFragmentOffset = nFragmentOffsetIn;
        vData.clear();
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nFlags);
        READWRITE(nFragmentOffset);
        READWRITE(vData);
    }

    bool AddData(const std::vector<uint8_t> &vDataIn)
    {
        if ((vData.size() + vDataIn.size()) > MAX_DATA_SEGMENT_SIZE)
        {
            return false;
        }
        vData.insert(vData.end(), vDataIn.begin(), vDataIn.end());
        return true;
    }

    std::vector<uint8_t> GetData() { return vData; }
};

// CPacket class is never used over the network

class CPacket : public CPacketHeader
{
    /// Data members
private:
    std::vector<uint8_t> vData;

public:
    /// Methods
private:
    CPacket() : CPacketHeader() {}
    void ClearAndSetSize()
    {
        vData.clear();
        vData = std::vector<uint8_t>(0, 0);
    }


public:
    CPacket(const CPacketHeader &header) : CPacketHeader(header)
    {
        SetNull();
        *((CPacketHeader *)this) = header;
        ClearAndSetSize();
    }

    CPacket(uint8_t nProtocolIdIn, uint8_t nProtocolVersionIn) : CPacketHeader(nProtocolIdIn, nProtocolVersionIn)
    {
        vData.clear();
    }
    void PushBackData(const std::vector<uint8_t> &data)
    {
        vData.insert(vData.end(), data.begin(), data.end());
        CalculateTotalLength(vData.size());
    }
    bool InsertData(CPacketDataSegment &newSegment)
    {
        // TODO : check if there is already data in the specified range, if there is return false, if there
        // is not then move the data segment data into that slot and return true
        std::vector<uint8_t> packetData = newSegment.GetData();
        PushBackData(packetData);
        return true;
    }
    void ClearData()
    {
        vData.clear();
        this->CalculateTotalLength(0);
    }
    std::vector<uint8_t> GetData() { return vData; }
    bool IsComplete() { return ((vData.size() + PACKET_HEADER_SIZE) == this->nTotalLength); }
    CPacketHeader GetHeader()
    {
        CPacketHeader header;
        header.nPacketVersion = this->nPacketVersion;
        header.nProtocolVersion = this->nProtocolVersion;
        header.nProtocolId = this->nProtocolId;
        header.nTotalLength = this->nTotalLength;
        header.nIdenfitication = this->nIdenfitication;
        header.nDataChecksum = this->nDataChecksum;
        return header;
    }

    std::vector<CPacketDataSegment> GetSegments()
    {
        std::vector<CPacketDataSegment> segments;
        if (vData.size() < MAX_DATA_SEGMENT_SIZE)
        {
            CPacketDataSegment newSegment;
            newSegment.AddData(vData);
            segments.push_back(newSegment);
        }
        else
        {
        }
        return segments;
    }
};

#endif
