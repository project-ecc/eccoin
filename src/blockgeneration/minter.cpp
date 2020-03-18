// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "minter.h"

#include "args.h"
#include "blockgeneration.h"
#include "consensus/tx_verify.h"
#include "init.h"
#include "processblock.h"
#include "txmempool.h"
#include "util/utilmoneystr.h"

#include <queue>

extern CWallet *pwalletMain;
int64_t nLastCoinStakeSearchInterval = 0;

bool CheckStake(const CBlock *pblock, CWallet &wallet, boost::shared_ptr<CReserveScript> coinbaseScript)
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
        CBlockIndex *ptip = pnetMan->getChainActive()->chainActive.Tip();
        if (ptip == nullptr)
        {
            return false;
        }
        if (pblock->hashPrevBlock != ptip->GetBlockHash())
        {
            return error("BMiner : generated block is stale");
        }
        // Remove key from key pool
        coinbaseScript->KeepScript();
        // Track how many getdata requests this block gets
        {
            LOCK2(cs_main, wallet.cs_wallet);
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

    uint64_t nBlockMaxSize = MAX_BLOCK_SIZE - 1000;
    uint64_t nBlockPrioritySize = DEFTAUL_BLOCK_PRIORITY_SIZE;
    uint64_t nBlockMinSize = 0;

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
                    pblock->vtx.push_back(MakeTransactionRef(txCoinStake));
                    break;
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
        MilliSleep(50);
        if (shutdown_threads.load() || shutdown_minter_threads.load())
            return nullptr;
    }

    // Collect memory pool transactions into the block
    {
        LOCK(cs_main);
        READLOCK(mempool.cs_txmempool);
        CBlockIndex *_pindexPrev = pnetMan->getChainActive()->chainActive.Tip();
        const int nHeight = _pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = _pindexPrev->GetMedianTimePast();

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
                mempool._ApplyDeltas(mi->GetTx().GetHash(), dPriority, dummy);
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
        pblock->hashPrevBlock = _pindexPrev->GetBlockHash();
        pblock->nTime = std::max(_pindexPrev->GetMedianTimePast() + 1, pblock->GetMaxTransactionTime());
        pblock->nTime = std::max(pblock->GetBlockTime(), _pindexPrev->GetBlockTime() - nMaxClockDrift);
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
    LogPrintf("CPUMiner started for proof-of-stake\n");
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
        if (shutdown_threads.load() || shutdown_minter_threads.load())
            return;
        if (!g_connman)
        {
            MilliSleep(1000);
            if (shutdown_threads.load() || shutdown_minter_threads.load())
                return;
        }
        while (pnetMan->getChainActive()->IsInitialBlockDownload() || pwallet->IsLocked())
        {
            MilliSleep(1000);
            if (shutdown_threads.load() || shutdown_minter_threads.load())
                return;
        }
        while (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) < DEFAULT_MIN_BLOCK_GEN_PEERS)
        {
            MilliSleep(1000);
            if (shutdown_threads.load() || shutdown_minter_threads.load())
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
        CheckStake(pblock, *pwalletMain, coinbaseScript);
        SetThreadPriority(THREAD_PRIORITY_LOWEST);
        MilliSleep(1000); // 1 second delay
        continue;
    }
}
