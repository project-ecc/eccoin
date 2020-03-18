// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2016 The Bitcoin Unlimited developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "nodestate.h"

CNodesStateManager nodestateman;

CNodeState *CNodesStateManager::_GetNodeState(const NodeId id)
{
    std::map<NodeId, CNodeState>::iterator it = mapNodeState.find(id);
    if (it == mapNodeState.end())
        return nullptr;
    return &it->second;
}

void CNodesStateManager::InitializeNodeState(const CNode *pnode)
{
    LOCK(cs_nodestateman);
    mapNodeState.emplace_hint(mapNodeState.end(), std::piecewise_construct, std::forward_as_tuple(pnode->GetId()),
        std::forward_as_tuple(pnode->addr, pnode->GetAddrName()));
}

void CNodesStateManager::RemoveNodeState(const NodeId id)
{
    LOCK(cs_nodestateman);
    mapNodeState.erase(id);
}
