/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
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

#include "minter.h"

#include "args.h"
#include "blockgeneration.h"
#include "init.h"
#include "processblock.h"
#include "txmempool.h"
#include "util/utilmoneystr.h"

#include <queue>

extern CWallet *pwalletMain;
int64_t nLastCoinStakeSearchInterval = 0;

bool CheckStake(const std::shared_ptr<const CBlock> pblock,
    CWallet &wallet,
    boost::shared_ptr<CReserveScript> coinbaseScript)
{
    //// debug print
    LogPrintf("Minter:\n");
    LogPrintf("new block found  \n  hash: %s\n", pblock->GetHash().GetHex().c_str());
    for (auto tx : pblock->vtx)
    {
        LogPrintf("transaction: %s \n", tx->GetHash().GetHex().c_str());
        for (auto vout : tx->vout)
        {
            LogPrintf("generated %s\n", FormatMoney(vout.nValue).c_str());
        }
    }

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != pnetMan->getChainActive()->chainActive.Tip()->GetBlockHash())
        {
            return error("Minter : generated block is stale");
        }
        // Remove key from key pool
        coinbaseScript->KeepScript();
        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }
        // Process this block the same as if we had received it from another node
        CValidationState state;
        const CNetworkTemplate &chainparams = pnetMan->getActivePaymentNetwork();
        if (!ProcessNewBlock(state, chainparams, nullptr, pblock, true, nullptr))
        {
            return error("Minter : ProcessBlock, block not accepted");
        }
    }
    return true;
}

// CreateNewBlock:
std::unique_ptr<CBlockTemplate> CreateNewPoSBlock(CWallet *pwallet, const CScript &scriptPubKeyIn)
{
    // Create new block
    std::unique_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if (!pblocktemplate.get())
    {
        return nullptr;
    }
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    CPubKey vchPubKey;
    txNew.vout[0].scriptPubKey = scriptPubKeyIn;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(MakeTransactionRef(txNew));
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = gArgs.GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN / 2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE - 1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = gArgs.GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = gArgs.GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // ppcoin: if coinstake available add coinstake tx
    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime(); // only initialized at startup
    CBlockIndex *pindexPrev = pnetMan->getChainActive()->chainActive.Tip();


    // This vector will be sorted into a priority queue:
    std::vector<TxCoinAgePriority> vecPriority;
    TxCoinAgePriorityCompare pricomparer;
    std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash> waitPriMap;
    typedef std::map<CTxMemPool::txiter, double, CTxMemPool::CompareIteratorByHash>::iterator waitPriIter;
    double actualPriority = -1;
    std::priority_queue<CTxMemPool::txiter, std::vector<CTxMemPool::txiter>, ScoreCompare> clearedTxs;
    uint64_t nBlockSize = 1000;
    uint64_t nBlockTx = 0;
    unsigned int nBlockSigOps = 100;
    int lastFewTxs = 0;
    CAmount nFees = 0;

    pblock->nBits = GetNextTargetRequired(pindexPrev, true);
    int64_t nSearchTime = GetTime(); // search to current time
    while (true)
    {
        CTransaction txCoinStake;
        nSearchTime = GetTime(); // update search time
        if (nSearchTime > nLastCoinStakeSearchTime)
        {
            txCoinStake.nTime = nSearchTime;
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime - nLastCoinStakeSearchTime, txCoinStake))
            {
                if (txCoinStake.nTime >=
                    std::max(pindexPrev->GetMedianTimePast() + 1, pindexPrev->GetBlockTime() - nMaxClockDrift))
                { // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    (*pblock->vtx[0]).vout[0].SetEmpty();
                    (*pblock->vtx[0]).nTime = txCoinStake.nTime;
                    LogPrintf("PUSHING COINSTAKE TX ON TO BLOCK \N");
                    pblock->vtx.push_back(MakeTransactionRef(txCoinStake));
                    break;
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
        MilliSleep(100);
        if (fShutdown)
            return nullptr;
    }
    LogPrintf("CHECKPOINT \n");

    // Collect memory pool transactions into the block
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex *pindexPrev = pnetMan->getChainActive()->chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        pblock->nVersion = 4;

        int64_t nLockTimeCutoff =
            (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST) ? nMedianTimePast : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock)
        {
            vecPriority.reserve(mempool.mapTx.size());
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end();
                 ++mi)
            {
                double dPriority = mi->GetPriority(nHeight);
                CAmount dummy;
                mempool.ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
                vecPriority.push_back(TxCoinAgePriority(dPriority, mi));
            }
            std::make_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
        }

        CTxMemPool::indexed_transaction_set::nth_index<3>::type::iterator mi = mempool.mapTx.get<3>().begin();
        CTxMemPool::txiter iter;
        while (mi != mempool.mapTx.get<3>().end() || !clearedTxs.empty())
        {
            bool priorityTx = false;
            if (fPriorityBlock && !vecPriority.empty())
            { // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty())
            { // add tx with next highest score
                iter = mempool.mapTx.project<0>(mi);
                mi++;
            }
            else
            { // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter))
                continue; // could have been added to the priorityBlock

            const CTransaction &tx = iter->GetTx();

            bool fOrphan = false;
            for (auto parent : mempool.GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent))
                {
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan)
            {
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter, actualPriority));
                else
                    waitSet.insert(iter);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock && (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority)))
            {
                fPriorityBlock = false;
                waitPriMap.clear();
            }
            if (!priorityTx &&
                (iter->GetModifiedFee() < ::minRelayTxFee.GetFee(nTxSize) && nBlockSize >= nBlockMinSize))
            {
                break;
            }
            if (nBlockSize + nTxSize >= nBlockMaxSize)
            {
                if (nBlockSize > nBlockMaxSize - 100 || lastFewTxs > 50)
                {
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000)
                {
                    lastFewTxs++;
                }
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                continue;

            unsigned int nTxSigOps = iter->GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
            {
                if (nBlockSigOps > MAX_BLOCK_SIGOPS - 2)
                {
                    break;
                }
                continue;
            }

            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(MakeTransactionRef(tx));
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            for (auto child : mempool.GetMemPoolChildren(iter))
            {
                if (fPriorityBlock)
                {
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end())
                    {
                        vecPriority.push_back(TxCoinAgePriority(wpiter->second, child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else
                {
                    if (waitSet.count(child))
                    {
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }
        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        // Fill in header
        pblock->hashPrevBlock = pindexPrev->GetBlockHash();
        pblock->nTime = std::max(pindexPrev->GetMedianTimePast() + 1, pblock->GetMaxTransactionTime());
        pblock->nTime = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
        pblock->nNonce = 0;
        if (!pblock->IsProofOfStake())
        {
            LogPrintf("WARNING, RETURNING POW BLOCK IN POS BLOCK CREATION \n");
        }
    }

    return std::move(pblocktemplate);
}


void EccMinter(CWallet *pwallet)
{
    LogPrintf("CPUMiner started for proof-of-%s\n", "stake");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    // Make this thread recognisable as the mining thread
    RenameThread("ecc-minter");
    // Each thread has its own key and counter

    boost::shared_ptr<CReserveScript> coinbaseScript;
    GetMainSignals().ScriptForMining(coinbaseScript);

    // If the keypool is exhausted, no script is returned at all.  Catch this.
    if (!coinbaseScript)
        return;

    // throw an error if no script was provided
    if (coinbaseScript->reserveScript.empty())
        return;

    unsigned int nExtraNonce = 0;
    while (true)
    {
        if (fShutdown)
            return;
        if (!g_connman)
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }
        while (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) < 6 ||
               pnetMan->getChainActive()->IsInitialBlockDownload() || pwallet->IsLocked())
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }
        CBlockIndex *pindexPrev = pnetMan->getChainActive()->chainActive.Tip();
        std::unique_ptr<CBlockTemplate> pblocktemplate(CreateNewPoSBlock(pwallet, coinbaseScript->reserveScript));
        if (!pblocktemplate.get())
        {
            LogPrintf(
                "Error in Miner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
            return;
        }
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
        if (!pblock->SignScryptBlock(*pwalletMain))
        {
            continue;
        }
        LogPrintf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString().c_str());
        SetThreadPriority(THREAD_PRIORITY_NORMAL);
        const std::shared_ptr<const CBlock> spblock = std::make_shared<const CBlock>(*pblock);
        CheckStake(spblock, *pwalletMain, coinbaseScript);
        SetThreadPriority(THREAD_PRIORITY_LOWEST);
        MilliSleep(1000); // 1 second delay
        continue;
    }
}
