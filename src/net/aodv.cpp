#include "aodv.h"
#include "net.h"


CAodvRouteTable g_aodvtable;


void CAodvRouteTable::GetRoutingTables(std::map<NodeId, CPubKey> &IdKey, std::map<CPubKey, NodeId> &KeyId)
{
    READLOCK_RECURSIVE(cs_aodv);
    IdKey = mapIdKey;
    KeyId = mapKeyId;
    return;
}

bool CAodvRouteTable::HaveKeyEntry(const CPubKey &key)
{
    READLOCK_RECURSIVE(cs_aodv);
    return (mapKeyId.find(key) != mapKeyId.end());
}

bool CAodvRouteTable::HaveIdEntry(const NodeId &node)
{
    READLOCK_RECURSIVE(cs_aodv);
    return (mapIdKey.find(node) != mapIdKey.end());
}

void CAodvRouteTable::AddPeerKeyId(const CPubKey &key, const NodeId &node, bool update)
{
    WRITELOCK_RECURSIVE(cs_aodv);
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
    READLOCK_RECURSIVE(cs_aodv);
    return (mapRoutesByPubKey.find(key) != mapRoutesByPubKey.end());
}

bool CAodvRouteTable::HaveIdRoute(const NodeId &node)
{
    READLOCK_RECURSIVE(cs_aodv);
    return (mapRoutesByPeerId.find(node) != mapRoutesByPeerId.end());
}

void CAodvRouteTable::AddRouteKeyId(const CPubKey &key, const NodeId &node)
{
    WRITELOCK_RECURSIVE(cs_aodv);
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
    READLOCK_RECURSIVE(cs_aodv);
    if (!HaveKeyEntry(key))
    {
        return false;
    }
    result = mapKeyId[key];
    return true;
}

bool CAodvRouteTable::GetNodeKey(const NodeId &node, CPubKey &result)
{
    READLOCK_RECURSIVE(cs_aodv);
    if (!HaveIdEntry(node))
    {
        return false;
    }
    result = mapIdKey[node];
    return true;
}

void CAodvRouteTable::AddNewRequestTimeData(const uint64_t &nonce)
{
    WRITELOCK_RECURSIVE(cs_aodv);
    mapRequestTime.emplace(nonce, GetTimeMillis());
}

bool CAodvRouteTable::IsOldRequest(const uint64_t &nonce)
{
    READLOCK_RECURSIVE(cs_aodv);
    return (mapRequestSource.find(nonce) != mapRequestSource.end());
}

void CAodvRouteTable::AddNewRequestSource(const uint64_t &nonce, const CPubKey &source)
{
    WRITELOCK_RECURSIVE(cs_aodv);
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
    READLOCK_RECURSIVE(cs_aodv);
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
    WRITELOCK_RECURSIVE(g_aodvtable.cs_aodv);
    g_aodvtable.responseQueue.emplace(RREQRESPONSE(nonce, source, pubkey, true));
}
