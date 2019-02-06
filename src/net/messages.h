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

#ifndef MESSAGES_H
#define MESSAGES_H

#include "chain/blockindex.h"
#include "net/net.h"
#include "validationinterface.h"


/** Average delay between trickled inventory transmissions in seconds.
 *  Blocks and whitelisted receivers bypass this, outbound peers get half this
 * delay. */
static const unsigned int INVENTORY_BROADCAST_INTERVAL = 5;

/** Maximum number of inventory items to send per transmission.
 *  Limits the impact of low-fee transaction floods. */
static const unsigned int INVENTORY_BROADCAST_MAX = 7 * INVENTORY_BROADCAST_INTERVAL;

/** Maximum number of unconnecting headers announcements before DoS score */
static const int MAX_UNCONNECTING_HEADERS = 10;

/** Average delay between feefilter broadcasts in seconds. */
static const unsigned int AVG_FEEFILTER_BROADCAST_INTERVAL = 10 * 60;

/** Default for using fee filter */
static const bool DEFAULT_FEEFILTER = true;

/** Maximum feefilter broadcast delay after significant change. */
static const unsigned int MAX_FEEFILTER_CHANGE_DELAY = 5 * 60;

// SHA256("main address relay")[0:8]
static const uint64_t RANDOMIZER_ID_ADDRESS_RELAY = 0x3cac0035b5866b90ULL;

extern std::unique_ptr<CRollingBloomFilter> recentRejects;

extern std::map<uint256, int64_t> pendingStx;
extern CCriticalSection cs_pendstx;

class PeerLogicValidation : public CValidationInterface
{
private:
    CConnman *connman;

public:
    PeerLogicValidation(CConnman *connmanIn);

    void BlockConnected(const std::shared_ptr<const CBlock> &pblock,
        const CBlockIndex *pindexConnected,
        const std::vector<CTransactionRef> &vtxConflicted) override;
    void UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) override;
    void BlockChecked(const CBlock &block, const CValidationState &state) override;
    void NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock> &pblock) override;
};

struct CNodeStateStats
{
    int nMisbehavior;
    int nSyncHeight;
    int nCommonHeight;
    std::vector<int> vHeightInFlight;
};


struct CBlockReject
{
    unsigned char chRejectCode;
    std::string strRejectReason;
    uint256 hashBlock;
};

/** Blocks that are in flight, and that are in the queue to be downloaded. Protected by cs_main. */
struct QueuedBlock
{
    uint256 hash;
    const CBlockIndex *pindex; //!< Optional.
    bool fValidatedHeaders; //!< Whether this block has validated headers at the time of request.
};

extern std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> > mapBlocksInFlight;
extern std::map<uint256, std::pair<NodeId, bool> > mapBlockSource;

/** Get statistics from node state */
bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats);
/** Increase a node's misbehavior score. */
void Misbehaving(NodeId nodeid, int howmuch, const std::string &reason);


/** Process protocol messages received from a given node */
bool ProcessMessages(CNode *pfrom, CConnman &connman);

/**Send queued protocol messages to be sent to a give node. */
bool SendMessages(CNode *pto, CConnman &connman);

/** Returns a bool indicating whether we requested this block. If we did request it, marks it as receieved and removes
 * block from in flight list*/
bool MarkBlockAsReceived(const uint256 &hash);

const CBlockIndex *LastCommonAncestor(const CBlockIndex *pa, const CBlockIndex *pb);

/** Register with a network node to receive its signals */
void RegisterNodeSignals(CNodeSignals &nodeSignals);
/** Unregister a network node */
void UnregisterNodeSignals(CNodeSignals &nodeSignals);


#endif // MESSAGES_H
