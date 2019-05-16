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

#include <atomic>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/foreach.hpp>
#include <boost/math/distributions/poisson.hpp>
#include <boost/range/adaptor/reversed.hpp>

#include <sstream>

#include "args.h"
#include "chain/checkpoints.h"
#include "checkqueue.h"
#include "crypto/hash.h"
#include "init.h"
#include "kernel.h"
#include "main.h"
#include "net/messages.h"
#include "net/net.h"
#include "networks/netman.h"
#include "networks/networktemplate.h"
#include "policy/policy.h"
#include "processblock.h"
#include "processheader.h"
#include "processtx.h"
#include "txmempool.h"

#include "undo.h"
#include "util/util.h"
#include "validationinterface.h"


bool fLargeWorkForkFound = false;
bool fLargeWorkInvalidChainFound = false;
CBlockIndex *pindexBestForkTip = nullptr;
CBlockIndex *pindexBestForkBase = nullptr;


/** Store block on disk. If dbp is non-NULL, the file is known to already reside on disk */
bool AcceptBlock(const CBlock *pblock,
    CValidationState &state,
    const CNetworkTemplate &chainparams,
    CBlockIndex **ppindex,
    bool fRequested,
    CDiskBlockPos *dbp)
{
    AssertLockHeld(cs_main);

    CBlockIndex *&pindex = *ppindex;

    if (!AcceptBlockHeader(*pblock, state, chainparams, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreWork = (pnetMan->getChainActive()->chainActive.Tip() ?
                             pindex->nChainWork > pnetMan->getChainActive()->chainActive.Tip()->nChainWork :
                             true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(pnetMan->getChainActive()->chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave)
        return true;
    if (!fRequested)
    { // If we didn't ask for it:
        if (pindex->nTx != 0)
            return true; // This is a previously-processed block that was pruned
        if (!fHasMoreWork)
            return true; // Don't process less-work chains
        if (fTooFarAhead)
            return true; // Block height is too high
    }

    if ((!CheckBlock(*pblock, state)) || !ContextualCheckBlock(*pblock, state, pindex->pprev))
    {
        if (state.IsInvalid() && !state.CorruptionPossible())
        {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return false;
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are
    // good...RELAY NOW (but if it does not build on our best tip, let the
    // SendMessages loop relay it)
    if (!pnetMan->getChainActive()->IsInitialBlockDownload() &&
        pnetMan->getChainActive()->chainActive.Tip() == pindex->pprev)
    {
        GetMainSignals().NewPoWValidBlock(pindex, pblock);
    }


    int nHeight = pindex->nHeight;

    // Write block to history file
    try
    {
        unsigned int nBlockSize = ::GetSerializeSize(*pblock, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != NULL)
            blockPos = *dbp;
        if (!FindBlockPos(state, blockPos, nBlockSize + 8, nHeight, (*pblock).GetBlockTime(), dbp != NULL))
            return error("AcceptBlock(): FindBlockPos failed");
        if (dbp == NULL)
            if (!WriteBlockToDisk(*pblock, blockPos, chainparams.MessageStart()))
                AbortNode(state, "Failed to write block");
        if (!ReceivedBlockTransactions(*pblock, state, pindex, blockPos))
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
    }
    catch (const std::runtime_error &e)
    {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    return true;
}

bool ProcessNewBlock(CValidationState &state,
    const CNetworkTemplate &chainparams,
    const CNode *pfrom,
    const CBlock *pblock,
    bool fForceProcessing,
    CDiskBlockPos *dbp)
{
    // Preliminary checks
    bool checked = CheckBlock(*pblock, state);

    {
        LOCK(cs_main);
        bool fRequested = MarkBlockAsReceived(pblock->GetHash());
        fRequested |= fForceProcessing;
        if (!checked)
        {
            LogPrintf("%s \n", state.GetRejectReason().c_str());
            return error("%s: CheckBlock FAILED", __func__);
        }

        // Store to disk
        CBlockIndex *pindex = NULL;
        bool ret = AcceptBlock(pblock, state, chainparams, &pindex, fRequested, dbp);
        CheckBlockIndex(chainparams.GetConsensus());
        if (!ret)
        {
            return error("%s: AcceptBlock FAILED", __func__);
        }
    }

    if (!ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed", __func__);

    return true;
}

/** Update chainActive and related internal data structures. */
void UpdateTip(CBlockIndex *pindexNew)
{
    const CNetworkTemplate &chainParams = pnetMan->getActivePaymentNetwork();
    pnetMan->getChainActive()->chainActive.SetTip(pindexNew);

    // New best block
    nTimeBestReceived = GetTime();
    mempool.AddTransactionsUpdated(1);

    LogPrintf("%s: new best=%s  height=%d  log2_work=%.8g  tx=%lu  date=%s progress=%f  cache=%.1fMiB(%utx)\n",
        __func__, pnetMan->getChainActive()->chainActive.Tip()->GetBlockHash().ToString(),
        pnetMan->getChainActive()->chainActive.Height(),
        log(pnetMan->getChainActive()->chainActive.Tip()->nChainWork.getdouble()) / log(2.0),
        (unsigned long)(pnetMan->getChainActive()->chainActive.Tip()->nChainTx),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pnetMan->getChainActive()->chainActive.Tip()->GetBlockTime()),
        Checkpoints::GuessVerificationProgress(chainParams.Checkpoints(), pnetMan->getChainActive()->chainActive.Tip()),
        pnetMan->getChainActive()->pcoinsTip->DynamicMemoryUsage() * (1.0 / (1 << 20)),
        pnetMan->getChainActive()->pcoinsTip->GetCacheSize());

    cvBlockChange.notify_all();
}

/** Disconnect chainActive's tip. You probably want to call mempool.removeForReorg and manually re-limit mempool size
 * after this, with cs_main held. */
bool DisconnectTip(CValidationState &state, const Consensus::Params &consensusParams)
{
    CBlockIndex *pindexDelete = pnetMan->getChainActive()->chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock &block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, consensusParams))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pnetMan->getChainActive()->pcoinsTip.get());
        if (!DisconnectBlock(block, state, pindexDelete, view))
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        assert(view.Flush());
    }
    LogPrint("bench", "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    // Resurrect mempool transactions from the disconnected block.
    std::vector<uint256> vHashUpdate;
    for (auto const &ptx : block.vtx)
    {
        const CTransaction &tx = *ptx;
        // ignore validation errors in resurrected transactions
        std::list<CTransactionRef> removed;
        CValidationState stateDummy;
        if (tx.IsCoinBase() || tx.IsCoinStake() || !AcceptToMemoryPool(mempool, stateDummy, ptx, false, NULL, true))
        {
            mempool.remove(tx, removed, true);
        }
        else if (mempool.exists(tx.GetHash()))
        {
            vHashUpdate.push_back(tx.GetHash());
        }
    }
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in this
    // block that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);
    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    for (const auto &ptx : block.vtx)
    {
        SyncWithWallets(ptx, nullptr, -1);
    }
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;
static int64_t nTimeTotal = 0;


/**
 * Connect a new block to chainActive. pblock is either NULL or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 */
bool ConnectTip(CValidationState &state,
    const CNetworkTemplate &chainparams,
    CBlockIndex *pindexNew,
    const CBlock *pblock)
{
    assert(pindexNew->pprev == pnetMan->getChainActive()->chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();

    CBlock block;
    if (!pblock)
    {
        if (!ReadBlockFromDisk(block, pindexNew, chainparams.GetConsensus()))
        {
            return AbortNode(state, "Failed to read block");
        }
        pblock = &block;
    }

    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros();
    nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(
        "bench", "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * 0.001, nTimeReadFromDisk * 0.000001);
    {
        CCoinsViewCache view(pnetMan->getChainActive()->pcoinsTip.get());
        bool rv = ConnectBlock(*pblock, state, pindexNew, view);
        if (!rv)
        {
            if (state.IsInvalid())
            {
                InvalidBlockFound(pindexNew, state);
            }
            return error("ConnectTip(): ConnectBlock %s failed", pindexNew->GetBlockHash().ToString().c_str());
        }
        nTime3 = GetTimeMicros();
        nTimeConnectTotal += nTime3 - nTime2;
        LogPrint(
            "bench", "  - Connect total: %.2fms [%.2fs]\n", (nTime3 - nTime2) * 0.001, nTimeConnectTotal * 0.000001);
        assert(view.Flush());
    }
    int64_t nTime4 = GetTimeMicros();
    nTimeFlush += nTime4 - nTime3;
    LogPrint("bench", "  - Flush: %.2fms [%.2fs]\n", (nTime4 - nTime3) * 0.001, nTimeFlush * 0.000001);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros();
    nTimeChainState += nTime5 - nTime4;
    LogPrint(
        "bench", "  - Writing chainstate: %.2fms [%.2fs]\n", (nTime5 - nTime4) * 0.001, nTimeChainState * 0.000001);
    // Remove conflicting transactions from the mempool.
    std::list<CTransactionRef> txConflicted;
    mempool.removeForBlock(
        pblock->vtx, pindexNew->nHeight, txConflicted, !pnetMan->getChainActive()->IsInitialBlockDownload());
    // Update chainActive & related variables.
    UpdateTip(pindexNew);

    // Tell wallet about transactions that went from mempool
    // to conflicted:
    for (const auto &ptx : txConflicted)
    {
        SyncWithWallets(ptx, nullptr, -1);
    }
    // ... and about transactions that got confirmed:
    int txIdx = 0;
    for (const auto &ptx : pblock->vtx)
    {
        SyncWithWallets(ptx, pblock, txIdx);
        txIdx++;
    }

    int64_t nTime6 = GetTimeMicros();
    nTimePostConnect += nTime6 - nTime5;
    nTimeTotal += nTime6 - nTime1;
    LogPrint(
        "bench", "  - Connect postprocess: %.2fms [%.2fs]\n", (nTime6 - nTime5) * 0.001, nTimePostConnect * 0.000001);
    LogPrint("bench", "- Connect block: %.2fms [%.2fs]\n", (nTime6 - nTime1) * 0.001, nTimeTotal * 0.000001);
    return true;
}


void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before the last checkpoint)
    if (pnetMan->getChainActive()->IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && pnetMan->getChainActive()->chainActive.Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = NULL;

    if (pindexBestForkTip ||
        (pindexBestInvalid &&
            pindexBestInvalid->nChainWork > pnetMan->getChainActive()->chainActive.Tip()->nChainWork +
                                                (GetBlockProof(*pnetMan->getChainActive()->chainActive.Tip()) * 6)))
    {
        if (!fLargeWorkForkFound && pindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                                  pindexBestForkBase->phashBlock->ToString() + std::string("'");
        }
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height "
                      "%d (%s).\nChain state database corruption likely.\n",
                __func__, pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            fLargeWorkForkFound = true;
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state "
                      "database corruption likely.\n",
                __func__);
            fLargeWorkInvalidChainFound = true;
        }
    }
    else
    {
        fLargeWorkForkFound = false;
        fLargeWorkInvalidChainFound = false;
    }
}

void CheckForkWarningConditionsOnNewFork(CBlockIndex *pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex *pfork = pindexNewForkTip;
    CBlockIndex *plonger = pnetMan->getChainActive()->chainActive.Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork &&
        (!pindexBestForkTip || (pindexBestForkTip && pindexNewForkTip->nHeight > pindexBestForkTip->nHeight)) &&
        pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
        pnetMan->getChainActive()->chainActive.Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either NULL or a pointer to a CBlock corresponding to pindexMostWork.
 */
bool ActivateBestChainStep(CValidationState &state,
    const CNetworkTemplate &chainparams,
    CBlockIndex *pindexMostWork,
    const CBlock *pblock)
{
    AssertLockHeld(cs_main);
    bool fInvalidFound = false;
    const CBlockIndex *pindexOldTip = pnetMan->getChainActive()->chainActive.Tip();
    const CBlockIndex *pindexFork = pnetMan->getChainActive()->chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    while (pnetMan->getChainActive()->chainActive.Tip() && pnetMan->getChainActive()->chainActive.Tip() != pindexFork)
    {
        if (!DisconnectTip(state, chainparams.GetConsensus()))
            return false;
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex *> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight)
    {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight)
        {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        BOOST_REVERSE_FOREACH (CBlockIndex *pindexConnect, vpindexToConnect)
        {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : nullptr))
            {
                if (state.IsInvalid())
                {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                }
                else
                {
                    // A system error occurred (disk space, database error, ...).
                    return false;
                }
            }
            else
            {
                PruneBlockIndexCandidates();
                if (!pindexOldTip ||
                    pnetMan->getChainActive()->chainActive.Tip()->nChainWork > pindexOldTip->nChainWork)
                {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected)
    {
        mempool.removeForReorg(pnetMan->getChainActive()->pcoinsTip.get(),
            pnetMan->getChainActive()->chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
        LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000,
            gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
    }
    mempool.check(pnetMan->getChainActive()->pcoinsTip.get());
    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();
    return true;
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either NULL or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool ActivateBestChain(CValidationState &state, const CNetworkTemplate &chainparams, const CBlock *pblock)
{
    CBlockIndex *pindexMostWork = NULL;
    do
    {
        if (shutdown_threads.load())
        {
            break;
        }

        if (ShutdownRequested())
            break;

        CBlockIndex *pindexNewTip = NULL;
        const CBlockIndex *pindexFork;
        bool fInitialDownload;
        {
            LOCK(cs_main);

            CBlockIndex *pindexOldTip = pnetMan->getChainActive()->chainActive.Tip();
            pindexMostWork = FindMostWorkChain();

            // Whether we have anything to do at all.
            if (pindexMostWork == nullptr || pindexMostWork == pnetMan->getChainActive()->chainActive.Tip())
                return true;

            if (!ActivateBestChainStep(state, chainparams, pindexMostWork,
                    pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullptr))
            {
                return false;
            }

            pindexNewTip = pnetMan->getChainActive()->chainActive.Tip();
            pindexFork = pnetMan->getChainActive()->chainActive.FindFork(pindexOldTip);
            fInitialDownload = pnetMan->getChainActive()->IsInitialBlockDownload();
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main
        // Always notify the UI if a new block tip was connected
        if (pindexFork != pindexNewTip)
        {
            BlockNotifyCallback(fInitialDownload, pindexNewTip);

            if (!fInitialDownload)
            {
                // Find the hashes of all blocks that weren't previously in the best chain.
                std::vector<uint256> vHashes;
                CBlockIndex *pindexToAnnounce = pindexNewTip;
                while (pindexToAnnounce != pindexFork)
                {
                    vHashes.push_back(pindexToAnnounce->GetBlockHash());
                    pindexToAnnounce = pindexToAnnounce->pprev;
                    if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE)
                    {
                        // Limit announcements in case of a huge reorganization.
                        // Rely on the peer's synchronization mechanism in that case.
                        break;
                    }
                }
                // Relay inventory, but don't relay old inventory during initial block
                // download.
                const int nNewHeight = pindexNewTip->nHeight;
                g_connman->ForEachNode([nNewHeight, &vHashes](CNode *pnode) {
                    if (nNewHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 0))
                    {
                        for (const uint256 &hash : boost::adaptors::reverse(vHashes))
                        {
                            pnode->PushBlockHash(hash);
                        }
                    }
                });
                // Notify external listeners about the new tip.
                if (!vHashes.empty())
                {
                    GetMainSignals().UpdatedBlockTip(pindexNewTip);
                }
            }
        }
    } while (pindexMostWork != pnetMan->getChainActive()->chainActive.Tip());
    CheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(state, FLUSH_STATE_PERIODIC))
    {
        return false;
    }
    return true;
}


void CheckBlockIndex(const Consensus::Params &consensusParams)
{
    if (!fCheckBlockIndex)
    {
        return;
    }

    LOCK(cs_main);
    READLOCK(pnetMan->getChainActive()->cs_mapBlockIndex);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (pnetMan->getChainActive()->chainActive.Height() < 0)
    {
        assert(pnetMan->getChainActive()->mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex *, CBlockIndex *> forward;
    for (BlockMap::iterator it = pnetMan->getChainActive()->mapBlockIndex.begin();
         it != pnetMan->getChainActive()->mapBlockIndex.end(); it++)
    {
        forward.insert(std::make_pair(it->second->pprev, it->second));
    }

    assert(forward.size() == pnetMan->getChainActive()->mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
        std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
        rangeGenesis = forward.equal_range(NULL);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent NULL.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex *pindexFirstInvalid = NULL; // Oldest ancestor of pindex which is invalid.
    CBlockIndex *pindexFirstMissing = NULL; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex *pindexFirstNeverProcessed = NULL; // Oldest ancestor of pindex for which nTx == 0.
    // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex *pindexFirstNotTreeValid = NULL;
    // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex *pindexFirstNotTransactionsValid = NULL;
    // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex *pindexFirstNotChainValid = NULL;
    // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    CBlockIndex *pindexFirstNotScriptsValid = NULL;
    while (pindex != NULL)
    {
        nNodes++;
        if (pindexFirstInvalid == NULL && pindex->nStatus & BLOCK_FAILED_VALID)
            pindexFirstInvalid = pindex;
        if (pindexFirstMissing == NULL && !(pindex->nStatus & BLOCK_HAVE_DATA))
            pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == NULL && pindex->nTx == 0)
            pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTreeValid == NULL &&
            (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE)
            pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotTransactionsValid == NULL &&
            (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS)
            pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotChainValid == NULL &&
            (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN)
            pindexFirstNotChainValid = pindex;
        if (pindex->pprev != NULL && pindexFirstNotScriptsValid == NULL &&
            (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS)
            pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == NULL)
        {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            // The current active chain's genesis block must be this block.
            assert(pindex == pnetMan->getChainActive()->chainActive.Genesis());
        }
        // nSequenceId can't be set for blocks that aren't linked
        if (pindex->nChainTx == 0)
            assert(pindex->nSequenceId == 0);
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.

        // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
        assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
        assert(pindexFirstMissing == pindexFirstNeverProcessed);

        if (pindex->nStatus & BLOCK_HAVE_UNDO)
            assert(pindex->nStatus & BLOCK_HAVE_DATA);
        // This is pruning-independent.
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0));
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is
        // equivalent to nChainTx being set.
        // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pindexFirstNeverProcessed != NULL) == (pindex->nChainTx == 0));
        assert((pindexFirstNotTransactionsValid != NULL) == (pindex->nChainTx == 0));
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(pindex->pprev == NULL || pindex->nChainWork >= pindex->pprev->nChainWork);
        // The pskip pointer must point back for all but the first 2 blocks.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight)));
        assert(pindexFirstNotTreeValid == NULL); // All mapBlockIndex entries must at least be TREE valid
        // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE)
            assert(pindexFirstNotTreeValid == NULL);
        // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN)
            assert(pindexFirstNotChainValid == NULL);
        // SCRIPTS valid implies all parents are SCRIPTS valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS)
            assert(pindexFirstNotScriptsValid == NULL);
        if (pindexFirstInvalid == NULL)
        {
            // Checks for not-invalid blocks.
            // The failed mask cannot be set for blocks without invalid parents.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0);
        }
        if (!CBlockIndexWorkComparator()(pindex, pnetMan->getChainActive()->chainActive.Tip()) &&
            pindexFirstNeverProcessed == NULL)
        {
            if (pindexFirstInvalid == NULL)
            {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == NULL || pindex == pnetMan->getChainActive()->chainActive.Tip())
                {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
            // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be
            // in setBlockIndexCandidates.
        }
        else
        {
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
            std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
            rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second)
        {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex)
            {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != NULL &&
            pindexFirstInvalid == NULL)
        {
            // If this block has block data available, some parent was never received, and has no invalid parents, it
            // must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (!(pindex->nStatus & BLOCK_HAVE_DATA))
            assert(!foundInUnlinked);
        // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindexFirstMissing == NULL)
            assert(!foundInUnlinked);
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == NULL &&
            pindexFirstMissing != NULL)
        {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently
            // missing data for some parent.
            assert(false); // We must have pruned but pruning was removed so something just went wrong.
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
            std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
            range = forward.equal_range(pindex);
        if (range.first != range.second)
        {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex)
        {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid)
                pindexFirstInvalid = NULL;
            if (pindex == pindexFirstMissing)
                pindexFirstMissing = NULL;
            if (pindex == pindexFirstNeverProcessed)
                pindexFirstNeverProcessed = NULL;
            if (pindex == pindexFirstNotTreeValid)
                pindexFirstNotTreeValid = NULL;
            if (pindex == pindexFirstNotTransactionsValid)
                pindexFirstNotTransactionsValid = NULL;
            if (pindex == pindexFirstNotChainValid)
                pindexFirstNotChainValid = NULL;
            if (pindex == pindexFirstNotScriptsValid)
                pindexFirstNotScriptsValid = NULL;
            // Find our parent.
            CBlockIndex *pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex *, CBlockIndex *>::iterator,
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator>
                rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex)
            {
                // Our parent must have at least the node we're coming from as child.
                assert(rangePar.first != rangePar.second);
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second)
            {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            }
            else
            {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}


/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex *FindMostWorkChain()
{
    do
    {
        CBlockIndex *pindexNew = NULL;

        // Find the best candidate header.
        {
            std::set<CBlockIndex *, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return NULL;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !pnetMan->getChainActive()->chainActive.Contains(pindexTest))
        {
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData)
            {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain &&
                    (pindexBestInvalid == NULL || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed)
                {
                    if (fFailedChain)
                    {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    }
                    else if (fMissingData)
                    {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
        {
            return pindexNew;
        }
    } while (true);
}

void InvalidChainFound(CBlockIndex *pindexNew)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
        pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, log(pindexNew->nChainWork.getdouble()) / log(2.0),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexNew->GetBlockTime()));
    CBlockIndex *tip = pnetMan->getChainActive()->chainActive.Tip();
    assert(tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__, tip->GetBlockHash().ToString(),
        pnetMan->getChainActive()->chainActive.Height(), log(tip->nChainWork.getdouble()) / log(2.0),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBlockTime()));
    CheckForkWarningConditions();
}

void InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state)
{
    if (!state.CorruptionPossible())
    {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}


bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks)
    {
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos))
        {
            FILE *file = OpenUndoFile(pos);
            if (file)
            {
                LogPrintf(
                    "Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

bool UndoWriteToDisk(const CBlockUndo &blockundo,
    CDiskBlockPos &pos,
    const uint256 &hashBlock,
    const CMessageHeader::MessageMagic &messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, blockundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

bool UndoReadFromDisk(CBlockUndo &blockundo, const CDiskBlockPos &pos, const uint256 &hashBlock)
{
    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenBlockFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein);
    try
    {
        verifier << hashBlock;
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception &e)
    {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck()
{
    RenameThread("bitcoin-scriptch");
    scriptcheckqueue.Thread();
}

void InterruptScriptCheck() { scriptcheckqueue.Stop(); }
static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;

bool ConnectBlock(const CBlock &block,
    CValidationState &state,
    CBlockIndex *pindex,
    CCoinsViewCache &view,
    bool fJustCheck)
{
    const CNetworkTemplate &chainparams = pnetMan->getActivePaymentNetwork();
    AssertLockHeld(cs_main);

    int64_t nTimeStart = GetTimeMicros();

    if (pindex->GetBlockHash() != chainparams.GetConsensus().hashGenesisBlock)
    {
        // once updateForPos runs the only flags that should be enabled are the ones that determine if PoS block or not
        // before this runs there should have been no flags set. so it is ok to reset the flags to 0
        pindex->updateForPos(block);
    }

    // Check it again in case a previous version let a bad block in
    if (!CheckBlock(block, state, !fJustCheck, !fJustCheck))
        return false;

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == NULL ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock)
    {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    bool fScriptChecks = true;
    if (fCheckpointsEnabled)
    {
        CBlockIndex *pindexLastCheckpoint = Checkpoints::GetLastCheckpoint(chainparams.Checkpoints());
        if (pindexLastCheckpoint && pindexLastCheckpoint->GetAncestor(pindex->nHeight) == pindex)
        {
            // This block is an ancestor of a checkpoint: disable script checks
            fScriptChecks = false;
        }
    }


    int64_t nTime1 = GetTimeMicros();
    nTimeCheck += nTime1 - nTimeStart;
    LogPrint("bench", "    - Sanity checks: %.2fms [%.2fs]\n", 0.001 * (nTime1 - nTimeStart), nTimeCheck * 0.000001);
    {
        for (auto const &tx : block.vtx)
        {
            for (size_t o = 0; o < tx->vout.size(); o++)
            {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o)))
                {
                    return state.DoS(
                        100, error("ConnectBlock(): tried to overwrite transaction"), REJECT_INVALID, "bad-txns-BIP30");
                }
            }
        }
    }

    unsigned int flags = SCRIPT_VERIFY_P2SH;

    // Start enforcing the DERSIG (BIP66) rules, for block.nVersion=3 blocks,
    // when 75% of the network has upgraded:
    if (block.nVersion >= 3 && IsSuperMajority(3, pindex->pprev,
                                   chainparams.GetConsensus().nMajorityEnforceBlockUpgrade, chainparams.GetConsensus()))
    {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY, (BIP65) for block.nVersion=4
    // blocks, when 75% of the network has upgraded:
    if (block.nVersion >= 4 && IsSuperMajority(4, pindex->pprev,
                                   chainparams.GetConsensus().nMajorityEnforceBlockUpgrade, chainparams.GetConsensus()))
    {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;

    int64_t nTime2 = GetTimeMicros();
    nTimeForks += nTime2 - nTime1;
    LogPrint("bench", "    - Fork checks: %.2fms [%.2fs]\n", 0.001 * (nTime2 - nTime1), nTimeForks * 0.000001);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    CAmount nValueIn = 0;
    CAmount nValueOut = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    if (block.IsProofOfStake())
    {
        blockundo.vtxundo.reserve(block.vtx.size());
    }
    else
    {
        blockundo.vtxundo.reserve(block.vtx.size() - 1);
    }
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();
        nSigOps += GetLegacySigOpCount(tx);
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return state.DoS(100, error("ConnectBlock(): too many sigops"), REJECT_INVALID, "bad-blk-sigops");

        if (tx.IsCoinBase())
        {
            nValueOut += tx.GetValueOut();
        }
        else
        {
            if (!view.HaveInputs(tx))
            {
                return state.DoS(100, error("ConnectBlock(): inputs missing/spent"), REJECT_INVALID,
                    "bad-txns-inputs-missingorspent");
            }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++)
            {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex))
            {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__), REJECT_INVALID,
                    "bad-txns-nonfinal");
            }

            {
                // Add in sigops done by pay-to-script-hash inputs;
                // this is to prevent a "rogue miner" from creating
                // an incredibly-expensive-to-validate block.
                nSigOps += GetP2SHSigOpCount(tx, view);
                if (nSigOps > MAX_BLOCK_SIGOPS)
                    return state.DoS(100, error("ConnectBlock(): too many sigops"), REJECT_INVALID, "bad-blk-sigops");
            }

            CAmount nTxValueIn = view.GetValueIn(tx);
            CAmount nTxValueOut = tx.GetValueOut();

            if (!tx.IsCoinStake())
            {
                nFees += nTxValueIn - nTxValueOut;
            }

            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;

            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult
                                                the cache, though) */
            if (!CheckInputs(
                    tx, state, view, fScriptChecks, flags, fCacheResults, nScriptCheckThreads ? &vChecks : NULL))
                return error("ConnectBlock(): CheckInputs on %s failed with %s", tx.GetHash().ToString(),
                    FormatStateMessage(state));
            control.Add(vChecks);
        }

        CTxUndo undoDummy;
        if (i > 0 || tx.IsCoinStake())
        {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, state, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight);

        vPos.push_back(std::make_pair(tx.GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }


    int64_t nTime3 = GetTimeMicros();
    nTimeConnect += nTime3 - nTime2;
    LogPrint("bench", "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs]\n",
        (unsigned)block.vtx.size(), 0.001 * (nTime3 - nTime2), 0.001 * (nTime3 - nTime2) / block.vtx.size(),
        nInputs <= 1 ? 0 : 0.001 * (nTime3 - nTime2) / (nInputs - 1), nTimeConnect * 0.000001);
    CAmount blockReward = 0;

    /// after 1504000 no Pow blocks are allowed
    if (block.IsProofOfWork() && pindex->nHeight >= 1504000)
    {
        return state.DoS(
            100, error("CheckBlock(): proof of work failed, invalid PoW height "), REJECT_INVALID, "Pow after cutoff");
    }

    // height >= 1504000 for legacy compatibility
    // someone made some blocks at 1493605 to roughly 1495000 that which didnt conform to the ideal blocks, but at the
    // time the client allowed it
    // that person didnt break any rules and no funds were stolen from other people.
    // but we need to have this check now to prevent future blocks from doing the same thing.
    if (block.IsProofOfWork() && pindex->nHeight >= 1504000)
    {
        blockReward = GetProofOfWorkReward(nFees, pindex->nHeight, block.hashPrevBlock);
        if (block.vtx[0]->GetValueOut() > blockReward)
        {
            return state.DoS(100, error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                                      block.vtx[0]->GetValueOut(), blockReward),
                REJECT_INVALID, "bad-cb-amount");
        }
    }
    else
    {
        for (auto tx : block.vtx)
        {
            if (tx->IsCoinStake())
            {
                uint64_t nCoinAge;
                if (!tx->GetCoinAge(nCoinAge))
                    return state.DoS(100, error("ConnectBlock() : %s unable to get coin age for coinstake",
                                              tx->GetHash().ToString().substr(0, 10).c_str()));
                blockReward = blockReward + GetProofOfStakeReward(tx->GetCoinAge(nCoinAge, true), pindex->nHeight);
            }
        }
        if (block.vtx[0]->GetValueOut() > blockReward && pindex->nHeight >= 1504000)
        {
            return state.DoS(100, error("ConnectBlock(): coinstake pays too much"), REJECT_INVALID, "bad-cb-amount");
        }
    }
    if (!control.Wait())
    {
        return state.DoS(100, error("%s: CheckQueue failed", __func__), REJECT_INVALID, "block-validation-failed");
    }
    int64_t nTime4 = GetTimeMicros();
    nTimeVerify += nTime4 - nTime2;
    LogPrint("bench", "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs]\n", nInputs - 1, 0.001 * (nTime4 - nTime2),
        nInputs <= 1 ? 0 : 0.001 * (nTime4 - nTime2) / (nInputs - 1), nTimeVerify * 0.000001);


    // ppcoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev ? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;


    /// put the following checks in this function due to lack of pindex when checkblock is called
    // Verify hash target and signature of coinstake tx
    uint256 hashProofOfStake;
    hashProofOfStake.SetNull();
    if (block.IsProofOfStake())
    {
        if (!CheckProofOfStake(pindex->nHeight, *(block.vtx[1]), hashProofOfStake))
        {
            return state.DoS(100, error("WARNING: ProcessBlock(): check proof-of-stake failed for block %s\n",
                                      block.GetHash().ToString().c_str()),
                REJECT_INVALID, "bad-proofofstake");
        }
    }

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindex->SetStakeEntropyBit(block.GetStakeEntropyBit()))
    {
        return error("ConnectBlock() : SetStakeEntropyBit() failed");
    }
    // ppcoin: record proof-of-stake hash value
    pindex->hashProofOfStake = hashProofOfStake;

    // ppcoin: compute stake modifier
    uint256 nStakeModifier;
    nStakeModifier.SetNull();
    if (block.IsProofOfStake())
    {
        if (!ComputeNextStakeModifier(pindex->pprev, *(block.vtx[1]), nStakeModifier))
            return state.DoS(100, error("ConnectBlock() : ComputeNextStakeModifier() failed"), REJECT_INVALID,
                "bad-stakemodifier-pos");
    }
    else
    {
        if (!ComputeNextStakeModifier(pindex->pprev, *(block.vtx[0]), nStakeModifier))
            return state.DoS(100, error("ConnectBlock() : ComputeNextStakeModifier() failed"), REJECT_INVALID,
                "bad-stakemodifier-pow");
    }
    pindex->SetStakeModifier(nStakeModifier);
    if (fJustCheck)
        return true;

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || !pindex->IsValid(BLOCK_VALID_SCRIPTS))
    {
        if (pindex->GetUndoPos().IsNull())
        {
            CDiskBlockPos _pos;
            if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock(): FindUndoPos failed");
            if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
                return AbortNode(state, "Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = _pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (!pnetMan->getChainActive()->pblocktree->WriteTxIndex(vPos))
    {
        return AbortNode(state, "Failed to write transaction index");
    }

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros();
    nTimeIndex += nTime5 - nTime4;
    LogPrint("bench", "    - Index writing: %.2fms [%.2fs]\n", 0.001 * (nTime5 - nTime4), nTimeIndex * 0.000001);
    int64_t nTime6 = GetTimeMicros();
    nTimeCallbacks += nTime6 - nTime5;
    LogPrint("bench", "    - Callbacks: %.2fms [%.2fs]\n", 0.001 * (nTime6 - nTime5), nTimeCallbacks * 0.000001);

    return true;
}

/**
 * Apply the undo operation of a CTxInUndo to the given chain state.
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return True on success.
 */
DisconnectResult ApplyTxInUndo(Coin &&undo, CCoinsViewCache &view, const COutPoint &out)
{
    bool fClean = true;
    if (view.HaveCoin(out))
    {
        fClean = false; // overwriting transaction output
    }
    if (undo.nHeight == 0)
    {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions

        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin &alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent())
        {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        }
        else
        {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }
    view.AddCoin(out, std::move(undo), undo.fCoinBase);
    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}


int DisconnectBlock(const CBlock &block,
    CValidationState &state,
    const CBlockIndex *pindex,
    CCoinsViewCache &view,
    bool *pfClean)
{
    assert(pindex->GetBlockHash() == view.GetBestBlock());

    if (pfClean)
        *pfClean = false;

    bool fClean = true;

    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull())
    {
        return error("DisconnectBlock(): no undo data available");
    }
    if (!UndoReadFromDisk(blockUndo, pos, pindex->pprev->GetBlockHash()))
    {
        return error("DisconnectBlock(): failure reading undo data");
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size())
    {
        return error("DisconnectBlock(): block and undo data inconsistent");
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--)
    {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();

        // Check that all outputs are available and match the outputs in the block itself exactly.
        for (size_t o = 0; o < tx.vout.size(); o++)
        {
            if (!tx.vout[o].scriptPubKey.IsUnspendable())
            {
                COutPoint out(hash, o);
                Coin coin;
                view.SpendCoin(out, &coin);
                if (tx.vout[o] != coin.out)
                {
                    fClean = false; // transaction output mismatch
                }
            }
        }
        // restore inputs
        if (!tx.IsCoinBase()) // not coinbases
        {
            CTxUndo &txundo = blockUndo.vtxundo[i - 1];
            if (txundo.vprevout.size() != tx.vin.size())
            {
                return error("DisconnectBlock(): transaction and undo data inconsistent");
            }
            for (unsigned int j = tx.vin.size(); j-- > 0;)
            {
                const COutPoint &out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED)
                    return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;
            }
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    if (pfClean)
    {
        *pfClean = fClean;
        return true;
    }

    return fClean;
}
