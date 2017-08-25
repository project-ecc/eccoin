// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "txdb.h"
#include "miner.h"
#include "kernel.h"
#include "crypto/scrypt.h"
#include "txmempool.h"
#include "util.h"
#include "init.h"
#include "consensus/consensus.h"
#include "txmempool.h"
#include "utilmoneystr.h"
#include "timedata.h"
#include "bignum.h"
#include "coins.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "consensus/merkle.h"
#include "processblock.h"

#include <boost/thread.hpp>
#include <openssl/sha.h>
#include <queue>

extern CWallet* pwalletMain;

typedef boost::tuple<double, double, CTransaction*> TxPriority;

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;
int64_t nLastCoinStakeSearchInterval = 0;
double dHashesPerSec;
int64_t nHPSTimerStart;

static std::string strMintMessage = "Info: Minting suspended due to locked wallet.";
static std::string strMintWarning;



//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

template <size_t nBytes, typename T>
T* alignup(T* p)
{
    union
    {
        T* ptr;
        size_t n;
    } u;
    u.ptr = p;
    u.n = (u.n + (nBytes-1)) & ~(nBytes-1);
    return u.ptr;
}


int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

static const unsigned int pSHA256InitState[8] =
{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

void SHA256Transform(void* pstate, void* pinput, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    for (int i = 0; i < 8; i++)
        ctx.h[i] = ((uint32_t*)pinit)[i];

    SHA256_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    std::set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        LogPrintf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().substr(0,10).c_str(), dPriority, dFeePerKb);
        for (auto hash: setDependsOn)
            LogPrintf("   setDependsOn %s\n", hash.ToString().substr(0,10).c_str());
    }
};

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

class ScoreCompare
{
public:
    ScoreCompare() {}

    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b,*a); // Convert to less than
    }
};


/** Used as the flags parameter to sequence and nLocktime checks in non-consensus code. */
static const unsigned int STANDARD_LOCKTIME_VERIFY_FLAGS = LOCKTIME_VERIFY_SEQUENCE |
                                                           LOCKTIME_MEDIAN_TIME_PAST;

// CreateNewBlock:
//   fProofOfStake: try (best effort) to make a proof-of-stake block
CBlockTemplate* CreateNewBlock(CWallet* pwallet, bool fProofOfStake)
{
    CReserveKey reservekey(pwallet);

    // Create new block
    std::auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    CPubKey vchPubKey;
    reservekey.GetReservedKey(vchPubKey);
    txNew.vout[0].scriptPubKey << vchPubKey << OP_CHECKSIG;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    CTxMemPool::setEntries inBlock;
    CTxMemPool::setEntries waitSet;

    // Fee-per-kilobyte amount considered the same as "free"
    // Be careful setting this: if you set it to zero then
    // a transaction spammer can cheaply fill blocks using
    // 1-satoshi-fee transactions. It should be set above the real
    // cost to you of processing a transaction.
    int64_t nMinTxFee = MIN_TX_FEE(txNew.nTime);
    if (IsArgSet("-mintxfee"))
        ParseMoney(GetArg("-mintxfee", "0"), nMinTxFee);

    // ppcoin: if coinstake available add coinstake tx
    static int64_t nLastCoinStakeSearchTime = GetAdjustedTime();  // only initialized at startup
    CBlockIndex* pindexPrev = chainActive.Tip();


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


    if (fProofOfStake)  // attempt to find a coinstake
    {
        pblock->nBits = GetNextTargetRequired(pindexPrev, true);


        CTransaction txCoinStake;
        txCoinStake.nTime = GetTime();
        int64_t nSearchTime = txCoinStake.nTime; // search to current time


        if (nSearchTime > nLastCoinStakeSearchTime)
        {
            // LogPrintf(">>> OK1\n");
            if (pwallet->CreateCoinStake(*pwallet, pblock->nBits, nSearchTime-nLastCoinStakeSearchTime, txCoinStake))
            {
                if (txCoinStake.nTime >= std::max(pindexPrev->GetMedianTimePast()+1, pindexPrev->GetBlockTime() - nMaxClockDrift))
                {   // make sure coinstake would meet timestamp protocol
                    // as it would be the same as the block timestamp
                    pblock->vtx[0].vout[0].SetEmpty();
                    pblock->vtx[0].nTime = txCoinStake.nTime;
                    pblock->vtx.push_back(txCoinStake);
                }
            }
            nLastCoinStakeSearchInterval = nSearchTime - nLastCoinStakeSearchTime;
            nLastCoinStakeSearchTime = nSearchTime;
        }
    }
    else
    {
        pblock->nBits = GetNextTargetRequired(pindexPrev, false);
    }
    // Collect memory pool transactions into the block
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();
        const int nHeight = pindexPrev->nHeight + 1;
        pblock->nTime = GetAdjustedTime();
        const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

        pblock->nVersion = 4;

        int64_t nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                                ? nMedianTimePast
                                : pblock->GetBlockTime();

        bool fPriorityBlock = nBlockPrioritySize > 0;
        if (fPriorityBlock) {
            vecPriority.reserve(mempool.mapTx.size());
            for (CTxMemPool::indexed_transaction_set::iterator mi = mempool.mapTx.begin();
                 mi != mempool.mapTx.end(); ++mi)
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
            if (fPriorityBlock && !vecPriority.empty()) { // add a tx from priority queue to fill the blockprioritysize
                priorityTx = true;
                iter = vecPriority.front().second;
                actualPriority = vecPriority.front().first;
                std::pop_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                vecPriority.pop_back();
            }
            else if (clearedTxs.empty()) { // add tx with next highest score
                iter = mempool.mapTx.project<0>(mi);
                mi++;
            }
            else {  // try to add a previously postponed child tx
                iter = clearedTxs.top();
                clearedTxs.pop();
            }

            if (inBlock.count(iter))
                continue; // could have been added to the priorityBlock

            const CTransaction& tx = iter->GetTx();

            bool fOrphan = false;
            for (auto parent: mempool.GetMemPoolParents(iter))
            {
                if (!inBlock.count(parent)) {
                    fOrphan = true;
                    break;
                }
            }
            if (fOrphan) {
                if (priorityTx)
                    waitPriMap.insert(std::make_pair(iter,actualPriority));
                else
                    waitSet.insert(iter);
                continue;
            }

            unsigned int nTxSize = iter->GetTxSize();
            if (fPriorityBlock &&
                (nBlockSize + nTxSize >= nBlockPrioritySize || !AllowFree(actualPriority))) {
                fPriorityBlock = false;
                waitPriMap.clear();
            }
            if (!priorityTx &&
                (iter->GetModifiedFee() < ::minRelayTxFee.GetFee(nTxSize) && nBlockSize >= nBlockMinSize)) {
                break;
            }
            if (nBlockSize + nTxSize >= nBlockMaxSize) {
                if (nBlockSize >  nBlockMaxSize - 100 || lastFewTxs > 50) {
                    break;
                }
                // Once we're within 1000 bytes of a full block, only look at 50 more txs
                // to try to fill the remaining space.
                if (nBlockSize > nBlockMaxSize - 1000) {
                    lastFewTxs++;
                }
                continue;
            }

            if (!IsFinalTx(tx, nHeight, nLockTimeCutoff))
                continue;

            unsigned int nTxSigOps = iter->GetSigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS) {
                if (nBlockSigOps > MAX_BLOCK_SIGOPS - 2) {
                    break;
                }
                continue;
            }

            CAmount nTxFees = iter->GetFee();
            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            inBlock.insert(iter);

            // Add transactions that depend on this one to the priority queue
            for (auto child: mempool.GetMemPoolChildren(iter))
            {
                if (fPriorityBlock) {
                    waitPriIter wpiter = waitPriMap.find(child);
                    if (wpiter != waitPriMap.end()) {
                        vecPriority.push_back(TxCoinAgePriority(wpiter->second,child));
                        std::push_heap(vecPriority.begin(), vecPriority.end(), pricomparer);
                        waitPriMap.erase(wpiter);
                    }
                }
                else {
                    if (waitSet.count(child)) {
                        clearedTxs.push(child);
                        waitSet.erase(child);
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        if (pblock->IsProofOfStake())
        {
            pblock->nTime      = pblock->vtx[1].nTime; //same as coinstake timestamp
            pblock->nTime      = std::max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime      = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);

        }
        else
        {
            pblock->nTime          = std::max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime          = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
        }
        if (pblock->IsProofOfWork())
            pblock->UpdateTime();
        pblock->nNonce         = 0;
    }

    return pblocktemplate.release();
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}


void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1)
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
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    // Byte swap all the input buffer
    for (unsigned int i = 0; i < sizeof(tmp)/4; i++)
        ((unsigned int*)&tmp)[i] = ByteReverse(((unsigned int*)&tmp)[i]);

    // Precalc the first half of the first hash, which stays constant
    SHA256Transform(pmidstate, &tmp.block, pSHA256InitState);

    memcpy(pdata, &tmp.block, 128);
    memcpy(phash1, &tmp.hash1, 64);
}


bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    arith_uint256 hash = UintToArith256(pblock->GetHash());
    arith_uint256 hashTarget = UintToArith256(CBigNum().SetCompact(pblock->nBits).getuint256());

    if (hash > hashTarget && pblock->IsProofOfWork())
        return error("BitcoinMiner : proof-of-work not meeting target");

    //// debug print
    LogPrintf("BitcoinMiner:\n");
    LogPrintf("new block found  \n  hash: %s  \ntarget: %s\n", hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("BitcoinMiner : generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        CValidationState state;
        const CChainParams& chainparams = Params();
        if (!ProcessNewBlock(state, chainparams, NULL, pblock, true, NULL))
            return error("BitcoinMiner : ProcessBlock, block not accepted");
    }

    return true;
}

void ThreadBitcoinMiner(void* parg);

static bool fGenerateBitcoins = false;

void ScryptMiner(CWallet *pwallet)
{
    void *scratchbuf = scrypt_buffer_alloc();

    LogPrintf("CPUMiner started for proof-of-%s\n", "stake");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);

    // Make this thread recognisable as the mining thread
    RenameThread("bitcoin-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    while (true)
    {
        if (fShutdown)
            return;
        while (vNodes.empty() || vNodes.size() < 6 || IsInitialBlockDownload())
        {
            MilliSleep(1000);
            if (fShutdown)
                return;
        }

        while (pwallet->IsLocked())
        {
            strMintWarning = strMintMessage;
            MilliSleep(1000);
        }
        strMintWarning = "";

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrev = chainActive.Tip();

        std::auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(pwallet, true));
        if (!pblocktemplate.get())
        {
            LogPrintf("Error in BitcoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
            return;
        }
        CBlock *pblock = &pblocktemplate->block;

        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        {
            // ppcoin: if proof-of-stake block found then process block
            if (pblock->IsProofOfStake())
            {
                if (!pblock->SignScryptBlock(*pwalletMain))
                {
                    strMintWarning = strMintMessage;
                    continue;
                }
                strMintWarning = "";
                LogPrintf("CPUMiner : proof-of-stake block found %s\n", pblock->GetHash().ToString().c_str());
                SetThreadPriority(THREAD_PRIORITY_NORMAL);
                CheckWork(pblock, *pwalletMain, reservekey);
                SetThreadPriority(THREAD_PRIORITY_LOWEST);
            }
            MilliSleep(1000); // 1 second delay
            continue;
        }

        LogPrintf("Running BitcoinMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Pre-build hash buffers
        //
        char pmidstatebuf[32+16]; char* pmidstate = alignup<16>(pmidstatebuf);
        char pdatabuf[128+16];    char* pdata     = alignup<16>(pdatabuf);
        char phash1buf[64+16];    char* phash1    = alignup<16>(phash1buf);

        FormatHashBuffers(pblock, pmidstate, pdata, phash1);

        unsigned int& nBlockTime = *(unsigned int*)(pdata + 64 + 4);
        unsigned int& nBlockNonce = *(unsigned int*)(pdata + 64 + 12);


        //
        // Search
        //
        int64_t nStart = GetTime();
        arith_uint256 hashTarget = UintToArith256(CBigNum().SetCompact(pblock->nBits).getuint256());

        unsigned int max_nonce = 0xffff0000;
        CBlockHeader res_header;
        arith_uint256 result;

        while(true)
        {
            unsigned int nHashesDone = 0;
            unsigned int nNonceFound;

            nNonceFound = scanhash_scrypt(
                        (CBlockHeader *)&pblock->nVersion,
                        scratchbuf,
                        max_nonce,
                        nHashesDone,
                        UBEGIN(result),
                        &res_header
            );

            // Check if something found
            if (nNonceFound != (unsigned int) -1)
            {
                if (result <= hashTarget)
                {
                    // Found a solution
                    pblock->nNonce = nNonceFound;
                    assert(result == UintToArith256(pblock->GetHash()));
                    if (!pblock->SignScryptBlock(*pwalletMain))
                    {
//                        strMintWarning = strMintMessage;
                        break;
                    }
                    strMintWarning = "";

                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock, *pwalletMain, reservekey);
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
            if (fShutdown)
                return;
            if (!fGenerateBitcoins)
                return;
            if (vNodes.empty())
                break;
            if (nBlockNonce >= 0xffff0000)
                break;
            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != chainActive.Tip())
                break;

            // Update nTime every few seconds
            pblock->nTime = std::max(pindexPrev->GetMedianTimePast()+1, pblock->GetMaxTransactionTime());
            pblock->nTime = std::max(pblock->GetBlockTime(), pindexPrev->GetBlockTime() - nMaxClockDrift);
            pblock->UpdateTime();
            nBlockTime = ByteReverse(pblock->nTime);

            if (pblock->GetBlockTime() >= (int64_t)pblock->vtx[0].nTime + nMaxClockDrift)
                break;  // need to update coinbase timestamp
        }
    }

    scrypt_buffer_free(scratchbuf);
}

void ThreadScryptMiner(void* parg)
{
    static boost::thread_group* minerThreads = NULL;

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    minerThreads = new boost::thread_group();

    CWallet* pwallet = (CWallet*)parg;
    try
    {
        minerThreads->create_thread(boost::bind(&ScryptMiner, pwallet));
    }
    catch (std::exception& e) {
        PrintException(&e, "ThreadBitcoinMiner()");
    } catch (...) {
        PrintException(NULL, "ThreadBitcoinMiner()");
    }
    nHPSTimerStart = 0;
        dHashesPerSec = 0;
    LogPrintf("ThreadBitcoinMiner exiting \n");
}
