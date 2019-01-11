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

#ifndef BITCOIN_NETBASE_H
#define BITCOIN_NETBASE_H

#include "compat.h"
#include "netaddress.h"
#include "serialize.h"

#include <stdint.h>
#include <string>
#include <vector>

extern int nConnectTimeout;
extern bool fNameLookup;

//! -timeout default
static const int DEFAULT_CONNECT_TIMEOUT = 5000;
//! -dns default
static const int DEFAULT_NAME_LOOKUP = true;

class proxyType
{
public:
    proxyType() : randomize_credentials(false) {}
    proxyType(const CService &_proxy, bool _randomize_credentials = false)
        : proxy(_proxy), randomize_credentials(_randomize_credentials)
    {
    }

    bool IsValid() const { return proxy.IsValid(); }
    CService proxy;
    bool randomize_credentials;
};

enum Network ParseNetwork(std::string net);
std::string GetNetworkName(enum Network net);
bool SetProxy(enum Network net, const proxyType &addrProxy);
bool GetProxy(enum Network net, proxyType &proxyInfoOut);
bool IsProxy(const CNetAddr &addr);
bool SetNameProxy(const proxyType &addrProxy);
bool HaveNameProxy();
bool LookupHost(const char *pszName, std::vector<CNetAddr> &vIP, unsigned int nMaxSolutions, bool fAllowLookup);
bool LookupHost(const char *pszName, CNetAddr &addr, bool fAllowLookup);
bool Lookup(const char *pszName, CService &addr, int portDefault, bool fAllowLookup);
bool Lookup(const char *pszName,
    std::vector<CService> &vAddr,
    int portDefault,
    bool fAllowLookup,
    unsigned int nMaxSolutions);
CService LookupNumeric(const char *pszName, int portDefault = 0);
bool LookupSubNet(const char *pszName, CSubNet &subnet);
bool ConnectSocket(const CService &addr, SOCKET &hSocketRet, int nTimeout, bool *outProxyConnectionFailed = 0);
bool ConnectSocketByName(CService &addr,
    SOCKET &hSocketRet,
    const char *pszDest,
    int portDefault,
    int nTimeout,
    bool *outProxyConnectionFailed = 0);
/** Return readable error string for a network error code */
std::string NetworkErrorString(int err);
/** Close socket and set hSocket to INVALID_SOCKET */
bool CloseSocket(SOCKET &hSocket);
/** Disable or enable blocking-mode for a socket */
bool SetSocketNonBlocking(SOCKET &hSocket, bool fNonBlocking);
/**
 * Convert milliseconds to a struct timeval for e.g. select.
 */
struct timeval MillisToTimeval(int64_t nTimeout);
void InterruptSocks5(bool interrupt);

#endif // BITCOIN_NETBASE_H
