// This file is part of the Eccoin project
// Copyright (c) 2019 Greg Griffith
// Copyright (c) 2019 The Eccoin Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "aodv.h"
#include "net.h"


CAodvRouteTable g_aodvtable;


void CAodvRouteTable::GetRoutingTables(std::map<NodeId, CPubKey> &IdKey, std::map<CPubKey, NodeId> &KeyId)
{
    RECURSIVEREADLOCK(cs_aodv);
    IdKey = mapIdKey;
    KeyId = mapKeyId;
    return;
}

bool CAodvRouteTable::HaveKeyEntry(const CPubKey &key)
{
    RECURSIVEREADLOCK(cs_aodv);
    return (mapKeyId.find(key) != mapKeyId.end());
}

bool CAodvRouteTable::HaveIdEntry(const NodeId &node)
{
    RECURSIVEREADLOCK(cs_aodv);
    return (mapIdKey.find(node) != mapIdKey.end());
}

void CAodvRouteTable::AddPeerKeyId(const CPubKey &key, const NodeId &node, bool update)
{
    RECURSIVEWRITELOCK(cs_aodv);
    bool haveId = HaveIdEntry(node);
    bool haveKey = HaveKeyEntry(key);
    if (!update)
    {
        if (haveKey || haveId)
        {
            return;
        }
    }
    if (haveId)
    {
        mapIdKey[node] = key;
    }
    else
    {
        mapIdKey.emplace(node, key);
    }

    if (haveKey)
    {
        mapKeyId[key] = node;
    }
    else
    {
        mapKeyId.emplace(key, node);
    }
}

bool CAodvRouteTable::HaveKeyRoute(const CPubKey &key)
{
    RECURSIVEREADLOCK(cs_aodv);
    return (mapRoutesByPubKey.find(key) != mapRoutesByPubKey.end());
}

bool CAodvRouteTable::HaveIdRoute(const NodeId &node)
{
    RECURSIVEREADLOCK(cs_aodv);
    return (mapRoutesByPeerId.find(node) != mapRoutesByPeerId.end());
}

void CAodvRouteTable::AddRouteKeyId(const CPubKey &key, const NodeId &node)
{
    RECURSIVEWRITELOCK(cs_aodv);
    bool haveId = HaveIdRoute(node);
    bool haveKey = HaveKeyRoute(key);
    if (haveId)
    {
        std::set<CPubKey> keys = mapRoutesByPeerId[node];
        keys.emplace(key);
        mapRoutesByPeerId[node] = keys;
    }
    else
    {
        std::set<CPubKey> keys;
        keys.emplace(key);
        mapRoutesByPeerId.emplace(node, keys);
    }

    if (haveKey)
    {
        mapRoutesByPubKey[key] = node;
    }
    else
    {
        mapRoutesByPubKey.emplace(key, node);
    }
}

bool CAodvRouteTable::GetKeyNode(const CPubKey &key, NodeId &result)
{
    RECURSIVEREADLOCK(cs_aodv);
    if (!HaveKeyEntry(key))
    {
        result = mapKeyId[key];
        return true;
    }
    else if(HaveKeyRoute(key))
    {
        result = mapRoutesByPubKey[key];
        return true;
    }
    return false;
}

bool CAodvRouteTable::GetNodeKey(const NodeId &node, CPubKey &result)
{
    RECURSIVEREADLOCK(cs_aodv);
    if (!HaveIdEntry(node))
    {
        return false;
    }
    result = mapIdKey[node];
    return true;
}

void CAodvRouteTable::AddNewRequestTimeData(const uint64_t &nonce)
{
    RECURSIVEWRITELOCK(cs_aodv);
    mapRequestTime.emplace(nonce, GetTimeMillis());
}

bool CAodvRouteTable::IsOldRequest(const uint64_t &nonce)
{
    RECURSIVEREADLOCK(cs_aodv);
    return (mapRequestSource.find(nonce) != mapRequestSource.end());
}

void CAodvRouteTable::AddNewRequestSource(const uint64_t &nonce, const CPubKey &source)
{
    RECURSIVEWRITELOCK(cs_aodv);
    if (source.IsValid() == false)
    {
        return;
    }
    if (mapRequestSource.find(nonce) != mapRequestSource.end())
    {
        return;
    }
    mapRequestSource.emplace(nonce, source);
}

bool CAodvRouteTable::GetRequestSource(const uint64_t &nonce, CPubKey &source)
{
    RECURSIVEREADLOCK(cs_aodv);
    auto iter = mapRequestSource.find(nonce);
    if (iter == mapRequestSource.end())
    {
        return false;
    }
    source = iter->second;
    return true;
}

void RecordRequestOrigin(const uint64_t &nonce, const CPubKey &source)
{
    g_aodvtable.AddNewRequestSource(nonce, source);
}

bool GetRequestOrigin(const uint64_t &nonce, CPubKey &source)
{
    return g_aodvtable.GetRequestSource(nonce, source);
}

void _RequestRouteToPeer(CConnman &connman, const CPubKey &source, const uint64_t &nonce, const CPubKey &searchKey)
{
    if (g_aodvtable.IsOldRequest(nonce))
    {
        return;
    }
    g_aodvtable.AddNewRequestTimeData(nonce);
    connman.PushMessageAll(source, NetMsgType::RREQ, nonce, searchKey);
}

void RequestRouteToPeer(CConnman &connman, const CPubKey &source, const uint64_t &nonce, const CPubKey &searchKey)
{
    _RequestRouteToPeer(connman, source, nonce, searchKey);
}

void RequestRouteToPeer(CConnman *connman, const CPubKey &source, const uint64_t &nonce, const CPubKey &searchKey)
{
    _RequestRouteToPeer(*connman, source, nonce, searchKey);
}

void RecordRouteToPeer(const CPubKey &searchKey, const NodeId &node)
{
    g_aodvtable.AddRouteKeyId(searchKey, node);
}

void AddResponseToQueue(CPubKey source, uint64_t nonce, CPubKey pubkey)
{
    RECURSIVEWRITELOCK(g_aodvtable.cs_aodv);
    g_aodvtable.responseQueue.emplace(RREQRESPONSE(nonce, source, pubkey, true));
}
