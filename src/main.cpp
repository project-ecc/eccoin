// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "checkpoints.h"
#include "db.h"
#include "txdb-leveldb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "kernel.h"
#include "crypto/scrypt.h"
#include "mempool.h"
#include "global.h"
#include <boost/algorithm/string/replace.hpp>
#include <boost/random/mersenne_twister.hpp>
#include <boost/random/uniform_int_distribution.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <stdlib.h>
#include "random.h"
#include "util/utilstrencodings.h"
#include "messages.h"
#include "rpc/bitcoinrpc.h"

using namespace std;
using namespace boost;

//
// Global state
//

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CMedianFilter<int> cPeerBlockCounts(8, 0); // Amount of blocks that other nodes claim to have

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "ECCoin Signed Message:\n";

// Settings
int64_t nTransactionFee = MIN_TX_FEE(GetTime());
int64_t nMinimumInputValue = 0;

extern MapCheckpoints mapCheckpoints;
// 

int64_t getMinFee(int64_t nTime)
{
    if(nTime >= 1478822400) //Fri, 11 Nov 2016 00:00:00 GMT
    {
        return 1;
    }
    return 0.1;
}

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets


void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}

// get the wallet transaction with the given hash (if it exists)
bool GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->WGetTransaction(hashTx,wtx))
            return true;
    return false;
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const CTransaction& tx, const CBlock* pblock, bool fUpdate, bool fConnect)
{
    if (!fConnect)
    {
        // ppcoin: wallets need to refund inputs when disconnecting coinstake
        if (tx.IsCoinStake())
        {
            BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
                if (pwallet->IsFromMe(tx))
                    pwallet->DisableTransaction(tx);
        }
        return;
    }

    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(tx, pblock, fUpdate);
}


// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void ResendWalletTransactions(bool fForce)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions(fForce);
}



//! Guess how far we are in the verification process at the given block index
double GuessVerificationProgress(const ChainTxData& data, CBlockIndex *pindex) {
    if (pindex == NULL)
        return 0.0;

    int64_t nNow = time(NULL);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockIndexTime()) * data.dTxRate;
    }

    return pindex->nChainTx / fTxTotal;
}


//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CTransaction& tx)
{
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:

    size_t nSize = tx.GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);

    if (nSize > 5000)
    {
        LogPrintf("ignoring large orphan tx (size: %u, hash: %s)\n", nSize, hash.ToString().substr(0,10).c_str());
        return false;
    }

    mapOrphanTransactions[hash] = tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(hash);

    LogPrintf("stored orphan tx %s (mapsz %u)\n", hash.ToString().substr(0,10).c_str(), mapOrphanTransactions.size());
    return true;
}

void EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CTransaction& tx = mapOrphanTransactions[hash];
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CTransaction>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}







//////////////////////////////////////////////////////////////////////////////
//
// CTransaction and CTxIndex
//

int CTxIndex::GetDepthInMainChain() const
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(pos.nFile, pos.nBlockPos, false))
        return 0;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;
    return 1 + pindexBest->nHeight - pindex->nHeight;
}

// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &tx, uint256 &hashBlock)
{
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                tx = mempool.lookup(hash);
                return true;
            }
        }
        CTxDB txdb("r");
        CTxIndex txindex;
        if (tx.ReadFromDisk(txdb, COutPoint(hash, 0), txindex))
        {
            CBlock block;
            if (block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
                hashBlock = block.GetHash();
            return true;
        }
    }
    return false;
}








//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

uint256 GetOrphanRoot(const CBlock* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

int generateMTRandom(unsigned int s, int range)
{
    random::mt19937 gen(s);
    random::uniform_int_distribution<> dist(0, range);
    return dist(gen);
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}

static const int64_t nMinSubsidy = 1 * COIN;
// miner's coin base reward
int64_t GetProofOfWorkReward(int64_t nFees, const int nHeight, uint256 prevHash)
{
    int64_t nSubsidy = 100000 * COIN;

    if(nHeight == 1)
    {
        nSubsidy = 0.0099 * MAX_MONEY;
        return nSubsidy + nFees;
    }
    else if(nHeight > 86400)	// will be blocked all the pow after CUTOFF_HEIGHT
    {
        return nMinSubsidy + nFees;
    }

    std::string cseed_str = prevHash.ToString().substr(15,7);
    const char* cseed = cseed_str.c_str();
    long seed = hex2long(cseed);
    nSubsidy += generateMTRandom(seed, 200000) * COIN;

    return nSubsidy + nFees;
}

const int YEARLY_BLOCKCOUNT = 700800;
// miner's coin stake reward based on coin age spent (coin-days)
int64_t GetProofOfStakeReward(int64_t nCoinAge, int nHeight)
{
    int64_t nRewardCoinYear = 2.5 * MAX_MINT_PROOF_OF_STAKE;
    int64_t CMS = pindexBest->nMoneySupply;
    if (nHeight > 500000 && nHeight < 1005000)
    {
        int64_t nextMoney = (ValueFromAmountAsDouble(CMS) + nRewardCoinYear) ;
        if(nextMoney > (MAX_MONEY / 2))
        {
            int64_t difference = (nextMoney - (MAX_MONEY / 2));
            nRewardCoinYear = nextMoney - difference;
        }
        if(nextMoney == (MAX_MONEY / 2))
        {
            nRewardCoinYear = 0;
        }
        int64_t nSubsidy = nCoinAge * nRewardCoinYear / 365;
        return nSubsidy;
    }
    nRewardCoinYear = 25 * CENT; // 25%
    int64_t nSubsidy = nCoinAge * nRewardCoinYear / 365;
    if(nHeight >= 1005000)
    {
        int64_t nextMoney = CMS + nSubsidy;
        if(nextMoney > (MAX_MONEY / 2))
        {
            int64_t difference = (nextMoney - (MAX_MONEY / 2));
            nSubsidy = nextMoney - difference;
        }
        if(nextMoney == (MAX_MONEY / 2))
        {
            nSubsidy = 0;
        }
    }
    if (fDebug && GetBoolArg("-printcreation", false))
    {
        LogPrintf("GetProofOfStakeReward(): create=%s nCoinAge=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge);
    }
    return nSubsidy;
}

//
// maximum nBits value could possible be required nTime after
//
unsigned int ComputeMaxBits(CBigNum bnTargetLimit, unsigned int nBase, int64_t nTime)
{
    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    bnResult *= 2;
    while (nTime > 0 && bnResult < bnTargetLimit)
    {
        // Maximum 200% adjustment per day...
        bnResult *= 2;
        nTime -= 24 * 60 * 60;
    }
    if (bnResult > bnTargetLimit)
        bnResult = bnTargetLimit;
    return bnResult.GetCompact();
}

//
// minimum amount of work that could possibly be required nTime after
// minimum proof-of-work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime)
{
    return ComputeMaxBits(bnProofOfWorkLimit, nBase, nTime);
}

//
// minimum amount of stake that could possibly be required nTime after
// minimum proof-of-stake required was nBase
//
unsigned int ComputeMinStake(unsigned int nBase, int64_t nTime, unsigned int nBlockTime)
{
    return ComputeMaxBits(bnProofOfStakeLimit, nBase, nTime);
}


// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake)
{
        CBigNum bnTargetLimit = bnProofOfWorkLimit;

        if(fProofOfStake)
        {
            // Proof-of-Stake blocks has own target limit since nVersion=3 supermajority on mainNet and always on testNet
            bnTargetLimit = bnProofOfStakeLimit;
        }

        if (pindexLast == NULL)
            return bnTargetLimit.GetCompact(); // genesis block

        const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
        if (pindexPrev->pprev == NULL)
            return bnTargetLimit.GetCompact(); // first block
        const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
        if (pindexPrevPrev->pprev == NULL)
            return bnTargetLimit.GetCompact(); // second block

        int64_t nActualSpacing = pindexPrev->GetBlockIndexTime() - pindexPrevPrev->GetBlockIndexTime();
        if(nActualSpacing < 0)
        {
            nActualSpacing = 1;
        }
        else if(nActualSpacing > nTargetTimespan)
        {
            nActualSpacing = nTargetTimespan;
        }

        // ppcoin: target change every block
        // ppcoin: retarget with exponential moving toward target spacing
        CBigNum bnNew;
        bnNew.SetCompact(pindexPrev->nBits);
        int64_t spacing;
        if (fProofOfStake)
        {
            spacing = nStakeTargetSpacing;
        }
        else
        {
            spacing =  min( (3 * (int64_t) nStakeTargetSpacing), ((int64_t) nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight)) );
        }
        int64_t nTargetSpacing = spacing;
        int64_t nInterval = nTargetTimespan / nTargetSpacing;
        bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
        bnNew /= ((nInterval + 1) * nTargetSpacing);

        if (bnNew > bnTargetLimit)
        {
            bnNew = bnTargetLimit;
        }

        return bnNew.GetCompact();

}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    if (hash == hashGenesisBlock || hash == hashGenesisBlockTestNet)
    {
        return true;
    }
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
        return error("CheckProofOfWork() : nBits below minimum work");

    //Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), pcheckpointMain->GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    if (pindexBest == NULL || pindexBest->nHeight < pcheckpointMain->GetTotalBlocksEstimate())
        return true;
    static int64_t nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }
    return (GetTime() - nLastUpdate < 10 && pindexBest->GetBlockIndexTime() < GetTime() - 24 * 60 * 60);
}

bool ProcessBlock(CNode* pfrom, CBlock* pblock)
{
    // Check for duplicate
    const uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().substr(0,20).c_str());

    // ppcoin: check proof-of-stake
    // Limited duplicity on stake: prevents block flood attack
    // Duplicate stake allowed only when there is orphan child block
    if (pblock->IsProofOfStake() && setStakeSeen.count(pblock->GetProofOfStake()) && !mapOrphanBlocksByPrev.count(hash))
    {
            return error("ProcessBlock() : duplicate proof-of-stake (%s, %d) for block %s", pblock->GetProofOfStake().first.ToString().c_str(), pblock->GetProofOfStake().second, hash.ToString().c_str());
    }

    // Preliminary checks
    if (!pblock->CheckBlock())
        return error("ProcessBlock() : CheckBlock FAILED");

    CBlockIndex* pcheckpoint = pcheckpointMain->GetLastCheckpoint(mapBlockIndex);
    if (pcheckpoint && pblock->hashPrevBlock != pindexBest->GetBlockHash())
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64_t deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;

        if (pblock->IsProofOfStake())
            bnRequired.SetCompact(ComputeMinStake(GetLastBlockIndex(pcheckpoint, true)->nBits, deltaTime, pblock->nTime));
        else
            bnRequired.SetCompact(ComputeMinWork(GetLastBlockIndex(pcheckpoint, false)->nBits, deltaTime));

        if (bnNewBlock > bnRequired)
        {
            if(!IsInitialBlockDownload()) // if it is in the initial download could be a mistake so no need to disconnect peer just reject block
            {
                return false;
            }
            else
            {
                LOCK(pfrom->cs_vSend);
                pfrom->PushGetBlocks(pindexBest, uint256(0));
            }
            return error("ProcessBlock() : block with too little %s", pblock->IsProofOfStake()? "proof-of-stake" : "proof-of-work");
        }
    }

    // If we don't already have its previous block, shunt it off to holding area until we get it
    if (pblock->hashPrevBlock != 0 && !mapBlockIndex.count(pblock->hashPrevBlock))
    {
        LogPrintf("ProcessBlock: ORPHAN BLOCK with hash = %s, prevHash=%s\n", pblock->GetHash().ToString().substr(0,20).c_str() ,pblock->hashPrevBlock.ToString().substr(0,20).c_str());
        // Accept orphans as long as there is a node to request its parents from
        if (pfrom)
        {
            CBlock* pblock2 = new CBlock(*pblock);
            if (pblock2->IsProofOfStake())
            {
                if (setStakeSeenOrphan.count(pblock2->GetProofOfStake()))
                    return error("ProcessBlock() :  proof-of-stake (%s, %d) for orphan block %s", pblock2->GetProofOfStake().first.ToString().c_str(), pblock2->GetProofOfStake().second, hash.ToString().c_str());
                else
                    setStakeSeenOrphan.insert(pblock2->GetProofOfStake());
            }
            if (mapOrphanBlocks.count(hash) == 0) // saves memory
            {
                mapOrphanBlocks.insert(make_pair(hash, pblock2));
                mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));
            }
            // Ask this guy to fill in what we're missing
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
        }
        return true;
    }

    // Store to disk
    if (pblock->AcceptBlock(pblock) != true)
    {
        return error("ProcessBlock() : AcceptBlock FAILED");

        // Recursively process any orphan blocks that depended on this one
        vector<uint256> vWorkQueue;
        vWorkQueue.push_back(hash);
        for (unsigned int i = 0; i < vWorkQueue.size(); i++)
        {
            uint256 hashPrev = vWorkQueue[i];
            for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev); mi != mapOrphanBlocksByPrev.upper_bound(hashPrev); ++mi)
            {
                CBlock* pblockOrphan = (*mi).second;
                if (pblockOrphan->AcceptBlock(pblockOrphan))
                {
                    vWorkQueue.push_back(pblockOrphan->GetHash());
                }
                mapOrphanBlocks.erase(pblockOrphan->GetHash());
                setStakeSeenOrphan.erase(pblockOrphan->GetProofOfStake());
                delete pblockOrphan;
            }
            mapOrphanBlocksByPrev.erase(hashPrev);
        }
    }
    LogPrintf("ProcessBlock: ACCEPTED\n");
    return true;
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
    {
        fShutdown = true;
        string strMessage = _("Warning: Disk space is low!");
        strMiscWarning = strMessage;
        LogPrintf("*** %s\n", strMessage.c_str());
        uiInterface.ThreadSafeMessageBox(strMessage, "ECCoin", CClientUIInterface::BTN_OK | CClientUIInterface::ICON_WARNING | CClientUIInterface::MODAL);
        StartShutdown();
        return false;
    }
    return true;
}

static filesystem::path BlockFilePath(unsigned int nFile)
{
    string strBlockFn = strprintf("blk%04u.dat", nFile);
    return GetDataDir() / strBlockFn;
}

FILE* OpenBlockFile(unsigned int nFile, unsigned int nBlockPos, const char* pszMode)
{
    if ((nFile < 1) || (nFile == (unsigned int) -1))
        return NULL;
    FILE* file = fopen(BlockFilePath(nFile).string().c_str(), pszMode);
    if (!file)
        return NULL;
    if (nBlockPos != 0 && !strchr(pszMode, 'a') && !strchr(pszMode, 'w'))
    {
        if (fseek(file, nBlockPos, SEEK_SET) != 0)
        {
            fclose(file);
            return NULL;
        }
    }
    return file;
}

static unsigned int nCurrentBlockFile = 1;

FILE* AppendBlockFile(unsigned int& nFileRet)
{
    nFileRet = 0;
    while (true)
    {
        FILE* file = OpenBlockFile(nCurrentBlockFile, 0, "ab");
        if (!file)
            return NULL;
        if (fseek(file, 0, SEEK_END) != 0)
            return NULL;
        // FAT32 file size max 4GB, fseek and ftell max 2GB, so we must stay under 2GB
        if (ftell(file) < (long)(0x7F000000 - MAX_SIZE))
        {
            nFileRet = nCurrentBlockFile;
            return file;
        }
        fclose(file);
        nCurrentBlockFile++;
    }
}

bool LoadBlockIndex(bool fAllowNew)
{
    if (fTestNet)
     {
         pchMessageStart[0] = 0xcd;
         pchMessageStart[1] = 0xf1;
         pchMessageStart[2] = 0xc0;
         pchMessageStart[3] = 0xef;

         bnProofOfStakeLimit = bnProofOfStakeLimitTestNet; // 0x00000fff PoS base target is fixed in testnet
         bnProofOfWorkLimit = bnProofOfWorkLimitTestNet; // 0x0000ffff PoW base target is fixed in testnet
         nStakeMinAge = 20 * 60; // test net min age is 20 min
         nStakeMaxAge = 60 * 60; // test net min age is 60 min
         nModifierInterval = 60; // test modifier interval is 2 minutes
         nCoinbaseMaturity = 10; // test maturity is 10 blocks
         nStakeTargetSpacing = 3 * 60; // test block spacing is 3 minutes
     }

    //
    // Load block index
    //
    CTxDB txdb("cr+");
    if (!LoadBlockIndexInternal())
        return false;

    //
    // Init with genesis block
    //
    if (mapBlockIndex.empty())
    {
        if (!fAllowNew)
            return false;

        const char* pszTimestamp = "AP | Mar 2, 2014, 10.35 AM IST: China blames Uighur separatists for knife attack; 33 dead";
        CTransaction txNew;
        txNew.nTime = nChainStartTime;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig =  CScript() << 486604799 << CBigNum(9999) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].SetEmpty();
        txNew.vout[0].SetEmpty();
        CBlock block;

        block.vtx.push_back(txNew);
        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.nVersion = 1;
        block.nTime    = 1393744307;
        block.nBits    = bnProofOfWorkLimit.GetCompact();
        block.nNonce   = 12799721;
		    if(fTestNet)
        {
           // block.nNonce   = 37018887;
        }
        LogPrintf("/////////////////////////// GENESIS BLOCK ///////////////////////////////// \n");
        block.printScrypt();
        LogPrintf("/////////////////////////// END GENESIS BLOCK ///////////////////////////// \n");
        LogPrintf("block.GetHash() == %s\n", block.GetHash().ToString().c_str());
        LogPrintf("block.hashMerkleRoot == %s\n", block.hashMerkleRoot.ToString().c_str());
        LogPrintf("block.nTime = %u \n", block.nTime);
        LogPrintf("block.nNonce = %u \n", block.nNonce);
        LogPrintf("block.nBits = %u \n", block.nBits);

        //// debug print
        assert(block.hashMerkleRoot == uint256("0x4db82fe8b45f3dae2b7c7b8be5ec4c37e72e25eaf989b9db24ce1d0fd37eed8b")); // if false program aborts
        assert(block.GetHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet));
        assert(block.CheckBlock());
        // Verify hash target and signature of coinstake tx
        uint256 hashProofOfStake = 0;

        // Start new block file
        unsigned int nFile;
        unsigned int nBlockPos;
        if (!block.WriteToDisk(nFile, nBlockPos))
            return error("LoadBlockIndex() : writing genesis block to disk failed");

        if (!block.AddToBlockIndex(nFile, nBlockPos, hashProofOfStake))
            return error("LoadBlockIndex() : genesis block not accepted");
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                LogPrintf("| ");
            LogPrintf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                LogPrintf("| ");
            LogPrintf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            LogPrintf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        LogPrintf("%d (%u,%u) %s  %08x  %s  mint %7s  tx %u",
            pindex->nHeight,
            pindex->nFile,
            pindex->nBlockPos,
            block.GetHash().ToString().c_str(),
            block.nBits,
            DateTimeStrFormat("%x %H:%M:%S", block.GetBlockTime()).c_str(),
            FormatMoney(pindex->nMint).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn)
{
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    {
        LOCK(cs_main);
        try
        {
            CAutoFile blkdat(fileIn, SER_DISK, CLIENT_VERSION);
            unsigned int nPos = 0;
            while (nPos != (unsigned int)-1 && blkdat.good() && !fRequestShutdown)
            {
                unsigned char pchData[65536];
                do {
                    fseek(blkdat, nPos, SEEK_SET);
                    int nRead = fread(pchData, 1, sizeof(pchData), blkdat);
                    if (nRead <= 8)
                    {
                        nPos = (unsigned int)-1;
                        break;
                    }
                    void* nFind = memchr(pchData, pchMessageStart[0], nRead+1-sizeof(pchMessageStart));
                    if (nFind)
                    {
                        if (memcmp(nFind, pchMessageStart, sizeof(pchMessageStart))==0)
                        {
                            nPos += ((unsigned char*)nFind - pchData) + sizeof(pchMessageStart);
                            break;
                        }
                        nPos += ((unsigned char*)nFind - pchData) + 1;
                    }
                    else
                        nPos += sizeof(pchData) - sizeof(pchMessageStart) + 1;
                } while(!fRequestShutdown);
                if (nPos == (unsigned int)-1)
                    break;
                fseek(blkdat, nPos, SEEK_SET);
                unsigned int nSize;
                blkdat >> nSize;
                if (nSize > 0 && nSize <= MAX_BLOCK_SIZE)
                {
                    CBlock block;
                    blkdat >> block;
                    if (ProcessBlock(NULL,&block))
                    {
                        nLoaded++;
                        nPos += 4 + nSize;
                    }
                }
            }
        }
        catch (std::exception &e) {
            LogPrintf("%s() : Deserialize or I/O error caught during load\n",
                   BOOST_CURRENT_FUNCTION);
        }
    }
    LogPrintf("Loaded %i blocks from external file in %d ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

CCriticalSection cs_warnings;

std::string GetWarnings(const std::string& strFor)
{
    std::string strStatusBar = "";
    std::string strRPC = "";
    std::string strGUI = "";
    const std::string uiAlertSeperator = "<hr />";

    LOCK(cs_warnings);

//    if (!CLIENT_VERSION_IS_RELEASE) {
//        strStatusBar = "This is a pre-release test build - use at your own risk - do not use for mining or merchant applications";
//        strGUI = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");
//    }

    if (GetBoolArg("-testsafemode", false))
        strStatusBar = strRPC = strGUI = "testsafemode enabled";

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        strStatusBar = strMiscWarning;
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + strMiscWarning;
    }
/*
    if (fLargeWorkForkFound)
    {
        strStatusBar = strRPC = "Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.";
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.");
    }
    else if (fLargeWorkInvalidChainFound)
    {
        strStatusBar = strRPC = "Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.";
        strGUI += (strGUI.empty() ? "" : uiAlertSeperator) + _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.");
    }
*/
    if (strFor == "gui")
        return strGUI;
    else if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings(): invalid parameter");
    return "error";
}
