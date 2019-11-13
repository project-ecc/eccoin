// This file is part of the Eccoin project
// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_AODV_TABLE_H
#define ECCOIN_AODV_TABLE_H

#include <map>
#include <utility>
#include <vector>

#include "net.h"
#include "pubkey.h"
#include "sync.h"

// read https://www.ietf.org/rfc/rfc3561.txt for details on aodv
// the difference with this system is instead of trying to find
// and ip address, we are trying to find a peer with a specific
// pubkey

struct RREQRESPONSE
{
    uint64_t nonce;
    CPubKey source;
    CPubKey pubkey;
    bool found;

    RREQRESPONSE(uint64_t _nonce, CPubKey _source, CPubKey _pubkey, bool _found)
    {
        nonce = _nonce;
        source = _source;
        pubkey = _pubkey;
        found = _found;
    }

    friend inline bool operator < (const RREQRESPONSE &a, const RREQRESPONSE &b)
    {
        return (a.nonce < b.nonce);
    }

};

class CAodvRouteTable
{
private:
    // a set of known pubkey routes by the node ids that know about them
    std::map<NodeId, std::set<CPubKey> > mapRoutesByPeerId;
    // a map of what pubkeys have are known by which nodes
    std::map<CPubKey, NodeId> mapRoutesByPubKey;

    // nonce, GetTimeMillis
    std::map<uint64_t, uint64_t> mapRequestTime;
    // nonce, nodeId
    std::map<uint64_t, CPubKey> mapRequestSource;

public:
    mutable CRecursiveSharedCriticalSection cs_aodv;
    std::set<RREQRESPONSE>responseQueue;

private:
    bool HaveKeyRoute(const CPubKey &key);
    bool HaveIdRoute(const NodeId &node);

public:
    CAodvRouteTable()
    {
        mapRoutesByPeerId.clear();
        mapRoutesByPubKey.clear();
        mapRequestTime.clear();
        mapRequestSource.clear();
    }
    bool HaveRoute(const CPubKey &key);
    bool HaveRoute(const NodeId &node);
    void GetRoutingTables(std::map<NodeId, std::set<CPubKey> > &IdKey, std::map<CPubKey, NodeId> &KeyId);
    void AddRoute(const CPubKey &key, const NodeId &node);
    bool GetKeyNode(const CPubKey &key, NodeId &result);
    void AddNewRequestTimeData(const uint64_t &nonce);
    bool IsOldRequest(const uint64_t &nonce);
    void AddNewRequestSource(const uint64_t &nonce, const CPubKey &nodeId);
    bool GetRequestSource(const uint64_t &nonce, CPubKey &source);
};

void RecordRequestOrigin(const uint64_t &nonce, const CPubKey &source);
bool GetRequestOrigin(const uint64_t &nonce, CPubKey &source);
void RequestRouteToPeer(CConnman &connman, const CPubKey &source, const uint64_t &nonce, const CPubKey &searchKey);
void RequestRouteToPeer(CConnman *connman, const CPubKey &source, const uint64_t &nonce, const CPubKey &searchKey);
void RecordRouteToPeer(const CPubKey &searchKey, const NodeId &node);

void AddResponseToQueue(CPubKey source, uint64_t nonce, CPubKey pubkey);

extern CAodvRouteTable g_aodvtable;

#endif
