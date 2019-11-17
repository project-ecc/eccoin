// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "verifydb.h"

#include "blockstorage/blockstorage.h"
#include "init.h"
#include "main.h"
#include "processblock.h"


CVerifyDB::CVerifyDB() {}
CVerifyDB::~CVerifyDB() {}
bool CVerifyDB::VerifyDB(const CNetworkTemplate &chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    if (pnetMan->getChainActive()->chainActive.Tip() == nullptr ||
        pnetMan->getChainActive()->chainActive.Tip()->pprev == nullptr)
        return true;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > pnetMan->getChainActive()->chainActive.Height())
        nCheckDepth = pnetMan->getChainActive()->chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex *pindexState = pnetMan->getChainActive()->chainActive.Tip();
    CBlockIndex *pindexFailure = nullptr;
    int nGoodTransactions = 0;
    CValidationState state;
    LOCK(cs_main);
    for (CBlockIndex *pindex = pnetMan->getChainActive()->chainActive.Tip(); pindex && pindex->pprev;
         pindex = pindex->pprev)
    {
        if (shutdown_threads.load())
        {
            LogPrintf("VerifyDB(): Shutdown requested. Exiting.\n");
            return false;
        }
        if (pindex->nHeight < pnetMan->getChainActive()->chainActive.Height() - nCheckDepth)
            break;
        CBlock block;
        // check level 0: read from disk
        {
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight,
                    pindex->GetBlockHash().ToString());
        }
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state))
            return error(
                "VerifyDB(): *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex)
        {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull())
            {
                if (!UndoReadFromDisk(undo, pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB(): *** found bad undo data at %d, hash=%s\n", pindex->nHeight,
                        pindex->GetBlockHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState &&
            (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage)
        {
            DisconnectResult res = DisconnectBlock(block, pindex, coins);
            if (res == DISCONNECT_FAILED)
            {
                return error("VerifyDB(): *** irrecoverable inconsistency in block data at %d, hash=%s",
                    pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            pindexState = pindex->pprev;
            if (res == DISCONNECT_UNCLEAN)
            {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            }
            else
            {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error(
            "VerifyDB(): *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n",
            pnetMan->getChainActive()->chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4)
    {
        CBlockIndex *pindex = pindexState;
        while (pindex != pnetMan->getChainActive()->chainActive.Tip())
        {
            if (shutdown_threads.load())
            {
                LogPrintf("VerifyDB(): [lower] Shutdown requested. Exiting.\n");
                return false;
            }
            pindex = pnetMan->getChainActive()->chainActive.Next(pindex);
            CBlock block;
            {
                if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                    return error("VerifyDB(): *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight,
                        pindex->GetBlockHash().ToString());
            }
            if (!ConnectBlock(block, state, pindex, coins))
                return error("VerifyDB(): *** found unconnectable block at %d, hash=%s", pindex->nHeight,
                    pindex->GetBlockHash().ToString());
        }
    }

    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n",
        pnetMan->getChainActive()->chainActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}
