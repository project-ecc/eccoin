/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

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
const char *VERACK = "verack";
const char *ADDR = "addr";
const char *INV = "inv";
const char *GETDATA = "getdata";
const char *MERKLEBLOCK = "merkleblock";
const char *GETBLOCKS = "getblocks";
const char *GETHEADERS = "getheaders";
const char *TX = "tx";
const char *HEADERS = "headers";
const char *BLOCK = "block";
const char *GETADDR = "getaddr";
const char *MEMPOOL = "mempool";
const char *PING = "ping";
const char *PONG = "pong";
const char *ALERT = "alert";
const char *NOTFOUND = "notfound";
const char *FILTERLOAD = "filterload";
const char *FILTERADD = "filteradd";
const char *FILTERCLEAR = "filterclear";
const char *REJECT = "reject";
const char *SENDHEADERS = "sendheaders";
};

static const char *ppszTypeName[] = {
    "ERROR", // Should never occur
    NetMsgType::TX, NetMsgType::BLOCK,
    "filtered block", // Should never occur
};

/** All known message types. Keep this in the same order as the list of
 * messages above and in protocol.h.
 */
const static std::string allNetMessageTypes[] = {NetMsgType::VERSION, NetMsgType::VERACK, NetMsgType::ADDR,
    NetMsgType::INV, NetMsgType::GETDATA, NetMsgType::MERKLEBLOCK, NetMsgType::GETBLOCKS, NetMsgType::GETHEADERS,
    NetMsgType::TX, NetMsgType::HEADERS, NetMsgType::BLOCK, NetMsgType::GETADDR, NetMsgType::MEMPOOL, NetMsgType::PING,
    NetMsgType::PONG, NetMsgType::ALERT, NetMsgType::NOTFOUND, NetMsgType::FILTERLOAD, NetMsgType::FILTERADD,
    NetMsgType::FILTERCLEAR, NetMsgType::REJECT, NetMsgType::SENDHEADERS};
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
