// This file is part of the Eccoin project
// Copyright (c) 2020 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_VERSIONMESSAGE_H
#define ECCOIN_VERSIONMESSAGE_H


#include "protocol.h"
#include "serialize.h"
#include "tinyformat.h"
#include "util/utilstrencodings.h"
#include <string>
#include <unordered_map>
#include <vector>

// clang-format off

enum VersionMsgCode
{
    VERSION                 = 0x0000000000000000UL,
    LOCAL_NODE_SERVICES     = 0x0000000000000001UL,
    TIME                    = 0x0000000000000002UL,
    ADDR_YOU                = 0x0000000000000003UL,
    ADDR_ME                 = 0x0000000000000004UL,
    NONCE                   = 0x0000000000000005UL,
    SUBVERSION              = 0x0000000000000006UL,
    NODE_START_HEIGHT       = 0x0000000000000007UL,
    RELAY_TXES              = 0x0000000000000008UL,
};

// clang-format on

/*
// not used. this is just for reference
static const std::unordered_map<VersionMsgCode, typename T> VersionMsgType (
{
    {VersionMsgCode::PROTOCOL_VERSION,      int         },
    {VersionMsgCode::LOCAL_NODE_SERVICES,   uint64_t    },
    {VersionMsgCode::ADDR_YOU,              CAddress    },
    {VersionMsgCode::TIME,                  int64_t     },
    {VersionMsgCode::ADDR_ME,               CAddress    },
    {VersionMsgCode::NONCE,                 uint64_t    },
    {VersionMsgCode::SUBVERSION,            std::string },
    {VersionMsgCode::NODE_START_HEIGHT,     int         },
    {VersionMsgCode::RELAY_TXES,            bool        },
);
*/

const size_t MAX_VERSION_MAP_SIZE = 100000;

class CDynamicVersionMessage
{
public:
    std::map<uint64_t, std::vector<uint8_t> > version_map;

    CDynamicVersionMessage() {}
    ADD_SERIALIZE_METHODS;

    void *read(const VersionMsgCode k) const
    {
        if (version_map.count(k) == 0)
        {
            return nullptr;
        }
        const std::vector<uint8_t> &vec = version_map.at(k);
        char* v = nullptr;
        try
        {
            CDataStream s(vec, SER_NETWORK, PROTOCOL_VERSION);
            v = (char *)malloc(s.size());
            s.read(v, s.size());
        }
        catch (...)
        {
            LogPrintf("Error reading version message key %016llx. Assuming zero.\n", k);
            v = nullptr;
        }
        return v;
    }

    template <typename T>
    void write(const VersionMsgCode key, const T &val)
    {
        CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
        s << val;

        std::vector<uint8_t> vec;
        vec.insert(vec.begin(), s.begin(), s.end());
        version_map[key] = vec;
    }

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(version_map);
        if (GetSerializeSize(version_map, SER_NETWORK, PROTOCOL_VERSION) > MAX_VERSION_MAP_SIZE)
        {
            throw std::ios_base::failure(
                strprintf("A version message version_map might at most be %d bytes.", MAX_VERSION_MAP_SIZE));
        }
    }
};

#endif
