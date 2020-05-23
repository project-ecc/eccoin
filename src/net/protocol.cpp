// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "net/protocol.h"

#include "util/logger.h"
#include "util/util.h"
#include "util/utilstrencodings.h"

#ifndef WIN32
#include <arpa/inet.h>
#endif

namespace NetMsgType
{
const char *VERSION = "version";
const char *DYNAMICVERSION = "dversion";
const char *VERACK = "verack";
const char *DYNAMICVERACK = "dverack";
const char *ADDR = "addr";
const char *INV = "inv";
const char *GETDATA = "getdata";
const char *MERKLEBLOCK = "merkleblock";
const char *GETHEADERS = "getheaders";
const char *TX = "tx";
const char *HEADERS = "headers";
const char *BLOCK = "block";
const char *GETADDR = "getaddr";
const char *PING = "ping";
const char *PONG = "pong";
const char *NOTFOUND = "notfound";
const char *FILTERLOAD = "filterload";
const char *FILTERADD = "filteradd";
const char *FILTERCLEAR = "filterclear";
const char *REJECT = "reject";
const char *SENDHEADERS = "sendheaders";
const char *RREQ = "rreq";
const char *RREP = "rrep";
const char *RERR = "rerr";
const char *SPH = "packetheader";
const char *SPD = "packetdata";
const char *NSVERSION = "nsversion";
const char *NSVERACK = "nsverack";
};

static const char *ppszTypeName[] = {
    "ERROR", // Should never occur
    NetMsgType::TX, NetMsgType::BLOCK,
    "filtered block", // Should never occur
};

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {NetMsgType::VERSION, NetMsgType::VERACK, NetMsgType::DYNAMICVERSION, NetMsgType::DYNAMICVERACK,
     NetMsgType::ADDR,
    NetMsgType::INV, NetMsgType::GETDATA, NetMsgType::MERKLEBLOCK, NetMsgType::GETHEADERS, NetMsgType::TX,
    NetMsgType::HEADERS, NetMsgType::BLOCK, NetMsgType::GETADDR, NetMsgType::PING, NetMsgType::PONG,
    NetMsgType::NOTFOUND, NetMsgType::FILTERLOAD, NetMsgType::FILTERADD, NetMsgType::FILTERCLEAR, NetMsgType::REJECT,
    NetMsgType::SENDHEADERS, NetMsgType::RREQ, NetMsgType::RREP, NetMsgType::RERR, NetMsgType::SPH, NetMsgType::SPD,
    NetMsgType::NSVERSION, NetMsgType::NSVERACK};

const static std::vector<std::string> allNetMessageTypesVec(allNetMessageTypes,
    allNetMessageTypes + ARRAYLEN(allNetMessageTypes));


CMessageHeader::CMessageHeader(const MessageMagic &pchMessageStartIn)
{
    memcpy(std::begin(pchMessageStart), std::begin(pchMessageStartIn), MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    nMessageSize = -1;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

CMessageHeader::CMessageHeader(const MessageMagic &pchMessageStartIn,
    const char *pszCommand,
    unsigned int nMessageSizeIn)
{
    memcpy(std::begin(pchMessageStart), std::begin(pchMessageStartIn), MESSAGE_START_SIZE);
    memset(pchCommand, 0, sizeof(pchCommand));
    strncpy(pchCommand, pszCommand, COMMAND_SIZE);
    nMessageSize = nMessageSizeIn;
    memset(pchChecksum, 0, CHECKSUM_SIZE);
}

std::string CMessageHeader::GetCommand() const
{
    return std::string(pchCommand, pchCommand + strnlen(pchCommand, COMMAND_SIZE));
}

bool CMessageHeader::IsValid(const MessageMagic &pchMessageStartIn) const
{
    // Check start string
    if (memcmp(std::begin(pchMessageStart), std::begin(pchMessageStartIn), MESSAGE_START_SIZE) != 0)
    {
        return false;
    }

    // Check the command string for errors
    for (const char *p1 = pchCommand; p1 < pchCommand + COMMAND_SIZE; p1++)
    {
        if (*p1 == 0)
        {
            // Must be all zeros after the first zero
            for (; p1 < pchCommand + COMMAND_SIZE; p1++)
            {
                if (*p1 != 0)
                {
                    return false;
                }
            }
        }
        else if (*p1 < ' ' || *p1 > 0x7E)
        {
            return false;
        }
    }

    // Message size
    if (nMessageSize > MAX_SIZE)
    {
        LogPrintf("CMessageHeader::IsValid(): (%s, %u bytes) nMessageSize > "
                  "MAX_SIZE\n",
            GetCommand(), nMessageSize);
        return false;
    }

    return true;
}

CAddress::CAddress() : CService() { Init(); }
CAddress::CAddress(CService ipIn, uint64_t nServicesIn) : CService(ipIn)
{
    Init();
    nServices = nServicesIn;
}

void CAddress::Init()
{
    nServices = NODE_NETWORK;
    nTime = 100000000;
}

CInv::CInv()
{
    type = 0;
    hash.SetNull();
}

CInv::CInv(int typeIn, const uint256 &hashIn)
{
    type = typeIn;
    hash = hashIn;
}

CInv::CInv(const std::string &strType, const uint256 &hashIn)
{
    unsigned int i;
    for (i = 1; i < ARRAYLEN(ppszTypeName); i++)
    {
        if (strType == ppszTypeName[i])
        {
            type = i;
            break;
        }
    }
    if (i == ARRAYLEN(ppszTypeName))
        throw std::out_of_range(strprintf("CInv::CInv(string, uint256): unknown type '%s'", strType));
    hash = hashIn;
}

bool operator<(const CInv &a, const CInv &b) { return (a.type < b.type || (a.type == b.type && a.hash < b.hash)); }
bool CInv::IsKnownType() const { return (type >= 1 && type < (int)ARRAYLEN(ppszTypeName)); }
const char *CInv::GetCommand() const
{
    if (!IsKnownType())
        throw std::out_of_range(strprintf("CInv::GetCommand(): type=%d unknown type", type));
    return ppszTypeName[type];
}

std::string CInv::ToString() const { return strprintf("%s %s", GetCommand(), hash.ToString()); }
const std::vector<std::string> &getAllNetMessageTypes() { return allNetMessageTypesVec; }
