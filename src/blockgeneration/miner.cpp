// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"
#include "args.h"
#include "blockgeneration.h"
#include "compare.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/validation.h"
#include "crypto/scrypt.h"
#include "init.h"
#include "kernel.h"
#include "net/net.h"
#include "networks/netman.h"
#include "networks/networktemplate.h"
#include "policy/policy.h"
#include "processblock.h"
#include "timedata.h"
#include "txdb.h"
#include "txmempool.h"
#include "txmempool.h"
#include "util/util.h"
#include "util/utilmoneystr.h"

#include <memory>
#include <openssl/sha.h>
#include <queue>

extern CWallet *pwalletMain;

typedef boost::tuple<double, double, CTransaction *> TxPriority;

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
double dHashesPerSec;
int64_t nHPSTimerStart;


//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

template <size_t nBytes, typename T>
T *alignup(T *p)
{
    union {
        T *ptr;
        size_t n;
    } u;
    u.ptr = p;
    u.n = (u.n + (nBytes - 1)) & ~(nBytes - 1);
    return u.ptr;
}


int static FormatHashBlocks(void *pbuffer, unsigned int len)
{
    unsigned char *pdata = (unsigned char *)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char *pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void *pstate, void *pinput, const void *pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t *)data)[i] = ByteReverse(((uint32_t *)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t *)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t *)pstate)[i] = ctx.h[i];
}

// CreateNewBlock:
std::unique_ptr<CBlockTemplate> CreateNewPoWBlock(CWallet *pwallet, const CScript &scriptPubKeyIn)
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
    // Commented out unused variable assuming no side effect within GetAdjustedTime()
    // static int64_t nLastCoinStakeSearchTime = GetAdjustedTime(); // only initialized at startup
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

    pblock->nBits = GetNextTargetRequired(pindexPrev, false);
    // Collect memory pool transactions into the block
    {
        LOCK(cs_main);
        READLOCK(mempool.cs);
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
        UpdateTime(pblock, pnetMan->getActivePaymentNetwork()->GetConsensus(), _pindexPrev);
        pblock->vtx[0]->vout[0].nValue =
            GetProofOfWorkReward(nFees, _pindexPrev->nHeight + 1, _pindexPrev->GetBlockHash());
        pblock->nNonce = 0;
    }

    return std::move(pblocktemplate);
}

void FormatHashBuffers(CBlock *pblock, char *pmidstate, char *pdata, char *phash1)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
        } block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    } tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion = pblock->nVersion;
    tmp.block.hashPrevBlock = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime = pblock->nTime;
    tmp.block.nBits = pblock->nBits;
    tmp.block.nNonce = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp) / 4; i++)
        ((unsigned int *)&tmp)[i] = ByteReverse(((unsigned int *)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(const CBlock *pblock, CWallet &wallet, boost::shared_ptr<CReserveScript> coinbaseScript)
{
    arith_uint256 hash = UintToArith256(pblock->GetHash());
    arith_uint256 hashTarget = arith_uint256(pblock->nBits);

    if (hash > hashTarget && pblock->IsProofOfWork())
        return error("Miner : proof-of-work not meeting target");

    //// debug print
    LogPrintf("Miner:\n");
    LogPrintf("new block found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue).c_str());

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
        if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL))
            return error("Miner : ProcessBlock, block not accepted");
    }

    return true;
}

void EccMiner(CWallet *pwallet)
{
    void *scratchbuf = scrypt_buffer_alloc();
    LogPrintf("CPUMiner started for proof-of-work\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    // Make this thread recognisable as the mining thread
    RenameThread("ecc-miner");
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
        if (shutdown_threads.load() || shutdown_miner_threads.load())
            return;
        if (!g_connman)
        {
            MilliSleep(1000);
            if (shutdown_threads.load() || shutdown_miner_threads.load())
                return;
        }
        while (pnetMan->getChainActive()->IsInitialBlockDownload() || pwallet->IsLocked())
        {
            MilliSleep(1000);
            if (shutdown_threads.load() || shutdown_miner_threads.load())
                return;
        }
        while (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL) < DEFAULT_MIN_BLOCK_GEN_PEERS)
        {
            MilliSleep(1000);
            if (shutdown_threads.load() || shutdown_miner_threads.load())
                return;
        }
        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex *pindexPrev = pnetMan->getChainActive()->chainActive.Tip();
        std::unique_ptr<CBlockTemplate> pblocktemplate(CreateNewPoWBlock(pwallet, coinbaseScript->reserveScript));
        if (!pblocktemplate.get())
        {
            LogPrintf(
                "Error in Miner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
            return;
        }
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);
        LogPrintf("Running Miner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
            ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));
        //
        // Pre-build hash buffers
        //
        char pmidstatebuf[32 + 16];
        char *pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128 + 16];
        char *pdata = alignup<16>(pdatabuf);
        char phash1buf[64 + 16];
        char *phash1 = alignup<16>(phash1buf);
        FormatHashBuffers(pblock, pmidstate, pdata, phash1);
        unsigned int &nBlockTime = *(unsigned int *)(pdata + 64 + 4);
        unsigned int &nBlockNonce = *(unsigned int *)(pdata + 64 + 12);
        //
        // Search
        //
        int64_t nStart = GetTime();
        arith_uint256 hashTarget = arith_uint256(pblock->nBits);
        unsigned int max_nonce = 0xffff0000;
        CBlockHeader res_header;
        arith_uint256 result;
        while (true)
        {
            unsigned int nHashesDone = 0;
            unsigned int nNonceFound;

            nNonceFound = scanhash_scrypt(
                (CBlockHeader *)&pblock->nVersion, scratchbuf, max_nonce, nHashesDone, UBEGIN(result), &res_header);

            // Check if something found
            if (nNonceFound != (unsigned int)-1)
            {
                if (result <= hashTarget)
                {
                    // Found a solution
                    pblock->nNonce = nNonceFound;
                    assert(result == UintToArith256(pblock->GetHash()));
                    if (!pblock->SignScryptBlock(*pwalletMain))
                    {
                        break;
                    }
                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock, *pwalletMain, coinbaseScript);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);
                    break;
                }
            }
            // Meter hashes/sec
            static int64_t nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                    }
                }
            }
            // Check for stop or if block needs to be rebuilt
            if (shutdown_threads.load() || shutdown_miner_threads.load())
                return;
            if (g_connman->GetNodeCount(CConnman::CONNECTIONS_ALL))
                break;
            if (nBlockNonce >= 0xffff0000)
                break;
            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pnetMan->getChainActive()->chainActive.Tip())
                break;
            // Update nTime every few seconds
            pblock->nTime = std::max(pindexPrev->GetMedianTimePast() + 1, pblock->GetMaxTransactionTime());
            pblock->nTime = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
            UpdateTime(pblock, pnetMan->getActivePaymentNetwork()->GetConsensus(), pindexPrev);
            nBlockTime = ByteReverse(pblock->nTime);
            if (pblock->GetBlockTime() >= (int64_t)pblock->vtx[0]->nTime + nMaxClockDrift)
                break; // need to update coinbase timestamp
        }
    }
    scrypt_buffer_free(scratchbuf);
}
