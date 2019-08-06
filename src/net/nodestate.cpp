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
    LOCK(cs);
    mapNodeState.emplace_hint(mapNodeState.end(), std::piecewise_construct, std::forward_as_tuple(pnode->GetId()),
        std::forward_as_tuple(pnode->addr, pnode->GetAddrName()));
}

void CNodesStateManager::RemoveNodeState(const NodeId id)
{
    LOCK(cs);
    mapNodeState.erase(id);
}
