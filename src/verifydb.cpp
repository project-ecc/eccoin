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
            LOCK(cs_blockstorage);
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
                LOCK(cs_blockstorage);
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
