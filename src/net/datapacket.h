#ifndef ECCOIN_DATA_PACKET_H
#define ECCOIN_DATA_PACKET_H

#include "uint256.h"
#include "util/utiltime.h"

#include <inttypes.h>
#include <random>
#include <vector>

const uint64_t PACKET_HEADER_SIZE = 46; // 46 bytes
const uint64_t MEGABYTE = 1000000;
const uint64_t MAX_DATA_SEGMENT_SIZE = 10 * MEGABYTE;

class CPacketHeader
{
    // Data members
private:
    uint8_t nPacketVersion;
    uint8_t nProtocolVersion;
    uint8_t nProtocolId;
    uint64_t nTotalLength; // header + data in bytes (does not include extra vector serialization bytes)
    uint16_t nIdenfitication; // randomly generated
    uint256 nDataChecksum; // sha256 checksum

    // Methods
private:
    CPacketHeader() { SetNull(); }
    CPacketHeader(uint8_t nVersionIn, uint8_t nProtocolIn)
    {
        nVersion = nVersionIn;
        nProtocol = nProtocolIn;
        GenerateNewIdentifier();
    }

    void SetNull()
    {
        nVersion = 0;
        nTotalLength = 0;
        nIdenfitication = 0;
        nProtocol = 0;
        nDataChecksum.SetNull();
    }

    void CalculateTotalLength(uint64_t datasize) { nTotalLength = PACKET_HEADER_SIZE + datasize; }
public:
    void GenerateNewIdentifier()
    {
        uint64_t seed = GetTime();
        std::mt19937_64 rand(seed); // Standard mersenne_twister_engine seeded with rd()
        nIdenfitication = rand() % std::numeric_limits<uint16_t>();
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
    CPacketDataSegment() {}
public:
    CPacketDataSegment(uint8_t nFlagsIn, uint32_t nFragmentOffsetIn)
    {
        nFlags = nFlagsIn;
        nFragmentOffset = nFragmentOffsetIn;
        vData.clear();
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
};

class CPacket : public CPacketHeader
{
    /// Data members
private:
    std::vector<uint8_t> vData;

public:
    /// Methods
private:
    CPacket() {}
public:
    CPacket(uint8_t nVersionIn, uint8_t nProtocolIn) : CPacketHeader(nVersionIn, nProtocolIn) { vData.clear(); }
    void PushBackData(const std::vector<uint8_t> &data)
    {
        vData.insert(vData.end(), data.begin(), data.end());
        CalculateTotalLength(vData.size());
    }
    void ClearData()
    {
        vData.clear();
        CalculateTotalLength(0);
    }
};

#endif
