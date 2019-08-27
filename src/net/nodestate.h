// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2016 The Bitcoin Unlimited developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "messages.h"
#include "net.h"

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState
{
    //! The peer's address
    CService address;
    //! Whether we have a fully established connection.
    bool fCurrentlyConnected;
    //! Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    //! Whether this peer should be disconnected and banned (unless
    //! whitelisted).
    bool fShouldBan;
    //! String name of this peer (debugging/logging purposes).
    std::string name;
    //! The best known block we know this peer has announced.
    CBlockIndex *pindexBestKnownBlock;
    //! The hash of the last unknown block this peer has announced.
    uint256 hashLastUnknownBlock;
    //! The last full block we both have.
    CBlockIndex *pindexLastCommonBlock;
    //! The best header we have sent our peer.
    CBlockIndex *pindexBestHeaderSent;
    //! Length of current-streak of unconnecting headers announcements
    int nUnconnectingHeaders;
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted;

    std::list<QueuedBlock> vBlocksInFlight;
    //! When the first entry in vBlocksInFlight started downloading. Don't care
    //! when vBlocksInFlight is empty.
    int64_t nDownloadingSince;
    int nBlocksInFlight;
    int nBlocksInFlightValidHeaders;
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload;
    //! Whether this peer wants invs or headers (when possible) for block
    //! announcements.
    bool fPreferHeaders;
    /**
     * Whether this peer will send us cmpctblocks if we request them.
     * This is not used to gate request logic, as we really only care about
     * fSupportsDesiredCmpctVersion, but is used as a flag to "lock in" the
     * version of compact blocks we send.
     */
    bool fProvidesHeaderAndIDs;
    /**
     * If we've announced NODE_WITNESS to this peer: whether the peer sends
     * witnesses in cmpctblocks/blocktxns, otherwise: whether this peer sends
     * non-witnesses in cmpctblocks/blocktxns.
     */
    bool fSupportsDesiredCmpctVersion;

    CNodeState(CAddress addrIn, std::string addrNameIn) : address(addrIn), name(addrNameIn)
    {
        fCurrentlyConnected = false;
        nMisbehavior = 0;
        fShouldBan = false;
        pindexBestKnownBlock = nullptr;
        hashLastUnknownBlock.SetNull();
        pindexLastCommonBlock = nullptr;
        pindexBestHeaderSent = nullptr;
        nUnconnectingHeaders = 0;
        fSyncStarted = false;
        nDownloadingSince = 0;
        nBlocksInFlight = 0;
        nBlocksInFlightValidHeaders = 0;
        fPreferredDownload = false;
        fPreferHeaders = false;
        fProvidesHeaderAndIDs = false;
        fSupportsDesiredCmpctVersion = false;
    }
};

class CNodesStateManager
{
protected:
    CCriticalSection cs;
    std::map<NodeId, CNodeState> mapNodeState;
    friend class CNodeStateAccessor;

public:
    CNodeState *_GetNodeState(const NodeId id);

    /** Add a nodestate from the map */
    void InitializeNodeState(const CNode *pnode);

    /** Delete a nodestate from the map */
    void RemoveNodeState(const NodeId id);

    /** Clear the entire nodestate map */
    void Clear()
    {
        LOCK(cs);
        mapNodeState.clear();
    }

    /** Is mapNodestate empty */
    bool Empty()
    {
        LOCK(cs);
        return mapNodeState.empty();
    }
};

class CNodeStateAccessor
{
    CCriticalSection *cs;
    CNodeState *obj;

public:
    CNodeStateAccessor(CCriticalSection *_cs, CNodeState *_obj) : cs(_cs), obj(_obj)
    {
        EnterCritical("CNodeStateAccessor.cs", __FILE__, __LINE__, (void *)(&cs), LockType::RECURSIVE_MUTEX,
            OwnershipType::EXCLUSIVE);
    }
    CNodeStateAccessor(CNodesStateManager &ns, const NodeId id)
    {
        cs = &ns.cs;
        EnterCritical("CNodeStateAccessor.cs", __FILE__, __LINE__, (void *)(&cs), LockType::RECURSIVE_MUTEX,
            OwnershipType::EXCLUSIVE);
        obj = ns._GetNodeState(id);
    }

    CNodeState *operator->() { return obj; }
    CNodeState &operator*() { return *obj; }
    bool operator!=(void *ptr) { return obj != ptr; }
    bool operator==(void *ptr) { return obj == ptr; }
    bool IsNull() { return obj == nullptr; }
    CNodeState *Get() { return obj; }
    ~CNodeStateAccessor()
    {
        obj = nullptr;
        LeaveCritical(&cs);
    }
};

extern CNodesStateManager nodestateman;
