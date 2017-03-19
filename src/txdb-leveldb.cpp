// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file license.txt or http://www.opensource.org/licenses/mit-license.php.

#include <map>

#include <boost/version.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

#include <leveldb/env.h>
#include <leveldb/cache.h>
#include <leveldb/filter_policy.h>
#include <memenv/memenv.h>

#include "checkpoints.h"
#include "kernel.h"
#include "main.h"
#include "scrypt.h"
#include "txdb-leveldb.h"
#include "util.h"
#include "init.h"
#include "wallet.h"
#include "global.h"
#include "batchscanner.h"
#include "chain.h"



using namespace std;
using namespace boost;

extern CWallet* pwalletMain;
extern std::map<int, unsigned int> mapStakeModifierCheckpoints;
extern void scrypt_hash_mine(const void* input, size_t inputlen, uint32_t *res, void *scratchpad);
leveldb::DB *txdb; // global pointer for LevelDB object instance

static leveldb::Options GetOptions() {
    leveldb::Options options;
    int nCacheSizeMB = GetArg("-dbcache", 25);
    options.block_cache = leveldb::NewLRUCache(nCacheSizeMB * 1048576);
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);
    return options;
}

void init_blockindex(leveldb::Options& options, bool fRemoveOld = false)
{
    // First time init.
    filesystem::path directory = GetDataDir() / "txleveldb";

    if (fRemoveOld)
    {
        filesystem::remove_all(directory); // remove directory
        unsigned int nFile = 1;
        while (true)
        {
            filesystem::path strBlockFile = GetDataDir() / strprintf("blk%04u.dat", nFile);
            // Break if no such file
            if( !filesystem::exists( strBlockFile ) )
                break;
            filesystem::remove(strBlockFile);
            nFile++;
        }
    }
    filesystem::create_directory(directory);
    leveldb::Status status = leveldb::DB::Open(options, directory.string(), &txdb);
    if (!status.ok())
    {
        throw runtime_error(strprintf("init_blockindex(): error opening database environment %s", status.ToString().c_str()));
    }
}

// CDB subclasses are created and destroyed VERY OFTEN. That's why
// we shouldn't treat this as a free operations.
CTxDB::CTxDB(const char* pszMode)
{
    assert(pszMode);
    activeBatch = NULL;
    fReadOnly = (!strchr(pszMode, '+') && !strchr(pszMode, 'w'));

    if (txdb) {
        pdb = txdb;
        return;
    }

    bool fCreate = strchr(pszMode, 'c');

    options = GetOptions();
    options.create_if_missing = fCreate;
    options.filter_policy = leveldb::NewBloomFilterPolicy(10);

    init_blockindex(options); // Init directory
    pdb = txdb;

    if (Exists(string("version")))
    {
        ReadVersion(nVersion);
        if (nVersion < DATABASE_VERSION)
        {
            printf("Required index version is %d, current version %d, removing old database\n", DATABASE_VERSION, nVersion);

            // Leveldb instance destruction
            delete txdb;
            txdb = pdb = NULL;
            delete activeBatch;
            activeBatch = NULL;
            init_blockindex(options, true); // Remove directory and create new database
            pdb = txdb;
            bool fTmp = fReadOnly;
            fReadOnly = false;
            WriteVersion(DATABASE_VERSION); // Save transaction index version
            fReadOnly = fTmp;
        }
    }
    else if (fCreate)
    {
        bool fTmp = fReadOnly;
        fReadOnly = false;
        WriteVersion(DATABASE_VERSION);
        fReadOnly = fTmp;
    }
}

void CTxDB::Close()
{
    delete txdb;
    txdb = pdb = NULL;
    delete options.filter_policy;
    options.filter_policy = NULL;
    delete options.block_cache;
    options.block_cache = NULL;
    delete activeBatch;
    activeBatch = NULL;
}

bool CTxDB::TxnBegin()
{
    assert(!activeBatch);
    activeBatch = new leveldb::WriteBatch();
    return true;
}

bool CTxDB::TxnCommit()
{
    assert(activeBatch);
    leveldb::Status status = pdb->Write(leveldb::WriteOptions(), activeBatch);
    delete activeBatch;
    activeBatch = NULL;
    if (!status.ok())
    {
        printf("LevelDB batch commit failure: %s\n", status.ToString().c_str());
        return false;
    }
    return true;
}

// When performing a read, if we have an active batch we need to check it first
// before reading from the database, as the rest of the code assumes that once
// a database transaction begins reads are consistent with it. It would be good
// to change that assumption in future and avoid the performance hit, though in
// practice it does not appear to be large.
bool CTxDB::ScanBatch(const CDataStream &key, string *value, bool *deleted) const {
    assert(activeBatch);
    *deleted = false;
    CBatchScanner scanner;
    scanner.needle = key.str();
    scanner.deleted = deleted;
    scanner.foundValue = value;
    leveldb::Status status = activeBatch->Iterate(&scanner);
    if (!status.ok())
    {
        throw runtime_error(status.ToString());
    }
    return scanner.foundEntry;
}

bool CTxDB::ReadTxIndex(uint256 hash, CTxIndex& txindex)
{
    assert(!fClient);
    txindex.SetNull();
    return Read(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::UpdateTxIndex(uint256 hash, const CTxIndex& txindex)
{
    assert(!fClient);
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::AddTxIndex(const CTransaction& tx, const CDiskTxPos& pos, int nHeight)
{
    assert(!fClient);

    // Add to tx index
    uint256 hash = tx.GetHash();
    CTxIndex txindex(pos, tx.vout.size());
    return Write(make_pair(string("tx"), hash), txindex);
}

bool CTxDB::EraseTxIndex(const CTransaction& tx)
{
    assert(!fClient);
    uint256 hash = tx.GetHash();

    return Erase(make_pair(string("tx"), hash));
}

bool CTxDB::ContainsTx(uint256 hash)
{
    assert(!fClient);
    return Exists(make_pair(string("tx"), hash));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx, CTxIndex& txindex)
{
    assert(!fClient);
    tx.SetNull();
    if (!ReadTxIndex(hash, txindex))
        return false;
    return (tx.ReadFromDisk(txindex.pos));
}

bool CTxDB::ReadDiskTx(uint256 hash, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx, CTxIndex& txindex)
{
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::ReadDiskTx(COutPoint outpoint, CTransaction& tx)
{
    CTxIndex txindex;
    return ReadDiskTx(outpoint.hash, tx, txindex);
}

bool CTxDB::WriteBlockIndex(const CDiskBlockIndex& blockindex)
{
    return Write(make_pair(string("blockindex"), blockindex.GetBlockHash()), blockindex);
}

bool CTxDB::WriteUpgrade(string& upgraded)
{
    return Write(string("databaseUpgraded"), upgraded);
}

bool CTxDB::ReadUpgrade(string& upgraded)
{
    return Read(string("databaseUpgraded"), upgraded);
}

bool CTxDB::ReadHashBestChain(uint256& hashBestChain)
{
    return Read(string("hashBestChain"), hashBestChain);
}

bool CTxDB::WriteHashBestChain(uint256 hashBestChain)
{
    return Write(string("hashBestChain"), hashBestChain);
}

bool CTxDB::ReadBestInvalidTrust(CBigNum& bnBestInvalidTrust)
{
    return Read(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::WriteBestInvalidTrust(CBigNum bnBestInvalidTrust)
{
    return Write(string("bnBestInvalidTrust"), bnBestInvalidTrust);
}

bool CTxDB::ReadSyncCheckpoint(uint256& hashCheckpoint)
{
    return Read(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::WriteSyncCheckpoint(uint256 hashCheckpoint)
{
    return Write(string("hashSyncCheckpoint"), hashCheckpoint);
}

bool CTxDB::ReadCheckpointPubKey(string& strPubKey)
{
    return Read(string("strCheckpointPubKey"), strPubKey);
}

bool CTxDB::WriteCheckpointPubKey(const string& strPubKey)
{
    return Write(string("strCheckpointPubKey"), strPubKey);
}

CBlockIndex *InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool LoadBlockIndexInternal()
{

    CTxDB itxdb("cr+");
    CHeaderChainDB hcdb("cr+");

    // The block index is an in-memory structure that maps hashes to on-disk
    // locations where the contents of the block can be found. Here, we scan it
    // out of the DB and into mapBlockIndex.
    leveldb::Iterator *SmallIterator = itxdb.getInternalPointer()->NewIterator(leveldb::ReadOptions());
    // Seek to start key.
    CDataStream smallStartKey(SER_DISK, CLIENT_VERSION);
    smallStartKey << make_pair(string("blockindex"), uint256(0));
    SmallIterator->Seek(smallStartKey.str());

    //get the total number of blocks we have on the disk
    unsigned int TotalNumBlocks = 0;
    while (SmallIterator->Valid())
    {
        TotalNumBlocks = TotalNumBlocks + 1;
        //this is a check to see if we hit the end of the data, dont load values because it doesnt matter
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        ssKey.write(SmallIterator->key().data(), SmallIterator->key().size());
        string strType;
        ssKey >> strType;
        if (fRequestShutdown || strType != "blockindex")
            break;
        SmallIterator->Next();
    }
    delete SmallIterator;

    printf("total number of blocks = %d \n", TotalNumBlocks);
    ///this code reduces rescan time

    unsigned int bestCheckpoint = 0;
    typedef std::map<int, uint256>::iterator it_type;
    for(it_type CheckpointIterator = mapCheckpoints.begin(); CheckpointIterator != mapCheckpoints.end(); CheckpointIterator++)
    {
        unsigned int currentBest = CheckpointIterator->first;
        if (TotalNumBlocks - 250 <= 0)
        {
            TotalNumBlocks = 0;
        }
        if(currentBest < (TotalNumBlocks))
        {
            bestCheckpoint = currentBest;
        }
    }
    int64_t nStartMapping = GetTimeMillis();
    std::string upgraded;
    bool readUpgrade = itxdb.ReadUpgrade(upgraded);
    if(upgraded == "true" && readUpgrade == true)
    {
        leveldb::Iterator *iterator = hcdb.getInternalPointer()->NewIterator(leveldb::ReadOptions());
        CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
        ssStartKey << make_pair(string("indexheader"), uint256(0));
        iterator->Seek(ssStartKey.str());
        while (iterator->Valid())
        {
            // Unpack keys and values.
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey.write(iterator->key().data(), iterator->key().size());
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            ssValue.write(iterator->value().data(), iterator->value().size());
            string strType;
            ssKey >> strType;
            // Did we reach the end of the data to read?
            if (fRequestShutdown || strType != "indexheader")
                break;
            CDiskBlockIndex diskindex;
            ssValue >> diskindex;

            uint256 blockHash = diskindex.GetBlockHash();

            // Construct block index object
            CBlockIndex* pindexNew      = InsertBlockIndex(blockHash);
            pindexNew->pprev            = InsertBlockIndex(diskindex.hashPrev);
            pindexNew->pnext            = InsertBlockIndex(diskindex.hashNext);
            pindexNew->nFile            = diskindex.nFile;
            pindexNew->nBlockPos        = diskindex.nBlockPos;
            pindexNew->nHeight          = diskindex.nHeight;
            pindexNew->nMint            = diskindex.nMint;
            pindexNew->nMoneySupply     = diskindex.nMoneySupply;
            pindexNew->nFlags           = diskindex.nFlags;
            pindexNew->nStakeModifier   = diskindex.nStakeModifier;
            pindexNew->prevoutStake     = diskindex.prevoutStake;
            pindexNew->nStakeTime       = diskindex.nStakeTime;
            pindexNew->hashProofOfStake = diskindex.hashProofOfStake;
            pindexNew->nVersion         = diskindex.nVersion;
            pindexNew->hashMerkleRoot   = diskindex.hashMerkleRoot;
            pindexNew->nTime            = diskindex.nTime;
            pindexNew->nBits            = diskindex.nBits;
            pindexNew->nNonce           = diskindex.nNonce;

            // Watch for genesis block
            if (pindexGenesisBlock == NULL && blockHash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
                pindexGenesisBlock = pindexNew;

            // NovaCoin: build setStakeSeen
            if (pindexNew->IsProofOfStake())
                setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));

            iterator->Next();
        }
        delete iterator;
    }
    else
    {
        leveldb::Iterator *iterator = itxdb.getInternalPointer()->NewIterator(leveldb::ReadOptions());
        CDataStream ssStartKey(SER_DISK, CLIENT_VERSION);
        ssStartKey << make_pair(string("blockindex"), uint256(0));
        iterator->Seek(ssStartKey.str());
        while (iterator->Valid())
        {
            // Unpack keys and values.
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            ssKey.write(iterator->key().data(), iterator->key().size());
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            ssValue.write(iterator->value().data(), iterator->value().size());
            string strType;
            ssKey >> strType;
            // Did we reach the end of the data to read?
            if (fRequestShutdown || strType != "blockindex")
                break;
            CDiskBlockIndex diskindex;
            ssValue >> diskindex;

            uint256 blockHash = diskindex.GetBlockHash();

            // Construct block index object
            CBlockIndex* pindexNew      = InsertBlockIndex(blockHash);
            pindexNew->pprev            = InsertBlockIndex(diskindex.hashPrev);
            pindexNew->pnext            = InsertBlockIndex(diskindex.hashNext);
            pindexNew->nFile            = diskindex.nFile;
            pindexNew->nBlockPos        = diskindex.nBlockPos;
            pindexNew->nHeight          = diskindex.nHeight;
            pindexNew->nMint            = diskindex.nMint;
            pindexNew->nMoneySupply     = diskindex.nMoneySupply;
            pindexNew->nFlags           = diskindex.nFlags;
            pindexNew->nStakeModifier   = diskindex.nStakeModifier;
            pindexNew->prevoutStake     = diskindex.prevoutStake;
            pindexNew->nStakeTime       = diskindex.nStakeTime;
            pindexNew->hashProofOfStake = diskindex.hashProofOfStake;
            pindexNew->nVersion         = diskindex.nVersion;
            pindexNew->hashMerkleRoot   = diskindex.hashMerkleRoot;
            pindexNew->nTime            = diskindex.nTime;
            pindexNew->nBits            = diskindex.nBits;
            pindexNew->nNonce           = diskindex.nNonce;

            // Watch for genesis block
            if (pindexGenesisBlock == NULL && blockHash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
                pindexGenesisBlock = pindexNew;

            // NovaCoin: build setStakeSeen
            if (pindexNew->IsProofOfStake())
                setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));

            iterator->Next();

        }
        delete iterator;
        int rewritten = 0;
        /// need to create the new index so this one isnt used next time
        {
            printf("running update to move block index loading to the new metachain folder \n");
            BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
            {
                CBlockIndex* pindex = item.second;
                hcdb.WriteIndexHeader(CDiskBlockIndex(pindex));
                rewritten = rewritten + 1;
            }
        }
        std::string completed = "true";
        itxdb.WriteUpgrade(completed);
        printf("total blocks moved in upgrade = %d \n", rewritten);
        if(!hcdb.TxnCommit())
        {
            printf("UPGRADE FAILED, CRITICAL ERROR! \n");
            assert(false);
        }
    }
    printf("Time To Map Block Index: %I64d ms\n", GetTimeMillis() - nStartMapping);






    if (fRequestShutdown)
        return true;

    // Calculate nChainTrust
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());

    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());

    int64_t nStartChecksums = GetTimeMillis();

    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainTrust = (pindex->pprev ? pindex->pprev->nChainTrust : 0) + pindex->GetBlockTrust();
        // NovaCoin: calculate stake modifier checksum
        pindex->nStakeModifierChecksum = GetStakeModifierChecksum(pindex);
        if (!CheckStakeModifierCheckpoints(pindex->nHeight, pindex))
         return error("CTxDB::LoadBlockIndex() : Failed stake modifier checkpoint height=%d, checksum=%08x, correct checksum=%08x, nflags = %i, modifier=0x%016I64x  hashproofofstake = %s", pindex->nHeight, pindex->nStakeModifierChecksum, mapStakeModifierCheckpoints[pindex->nHeight], pindex->nFile, pindex->nStakeModifier, pindex->hashProofOfStake.ToString().c_str());
    }

    printf("Time To Makechecksums: %I64d ms\n", GetTimeMillis() - nStartChecksums);


    // Load hashBestChain pointer to end of best chain
    if (!itxdb.ReadHashBestChain(hashBestChain))
    {
        if (pindexGenesisBlock == NULL)
            return true;
        return error("CTxDB::LoadBlockIndex() : hashBestChain not loaded");
    }
    if (!mapBlockIndex.count(hashBestChain))
        return error("CTxDB::LoadBlockIndex() : hashBestChain not found in the block index");

    pindexBest = mapBlockIndex[hashBestChain];
    nBestHeight = pindexBest->nHeight;
    nBestChainTrust = pindexBest->nChainTrust;

    // ECCoin: write checkpoint we loaded from
    if( bestCheckpoint != 0 )
    {
        uint256 CheckpointBlock = mapCheckpoints.find(bestCheckpoint)->second;
        if (!WriteSyncCheckpoint(CheckpointBlock))
            return error("LoadBlockIndex() : failed to init sync checkpoint");
    }
    else
    {
        if (!WriteSyncCheckpoint((!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet)))
            return error("LoadBlockIndex() : failed to init sync checkpoint");
    }
    // NovaCoin: load hashSyncCheckpoint
    if (!itxdb.ReadSyncCheckpoint(hashSyncCheckpoint))
        return error("CTxDB::LoadBlockIndex() : hashSyncCheckpoint not loaded");
    printf("LoadBlockIndex(): synchronized checkpoint %s\n", hashSyncCheckpoint.ToString().c_str());

    // Load bnBestInvalidTrust, OK if it doesn't exist
    CBigNum bnBestInvalidTrust;
    itxdb.ReadBestInvalidTrust(bnBestInvalidTrust);
    nBestInvalidTrust = bnBestInvalidTrust.getuint256();

    // Verify blocks in the best chain
    int nCheckLevel = GetArg("-checklevel", 1);
    int nCheckDepth = GetArg( "-checkblocks", 2500);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > nBestHeight)
        nCheckDepth = nBestHeight;
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex* pindexFork = NULL;
    map<pair<unsigned int, unsigned int>, CBlockIndex*> mapBlockPos;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        if (fRequestShutdown || pindex->nHeight < nBestHeight-nCheckDepth)
            break;
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        // check level 1: verify block validity
        // check level 7: verify block signature too
        if (nCheckLevel>0 && !block.CheckBlock(true, true, (nCheckLevel>6)))
        {
            printf("LoadBlockIndex() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexFork = pindex->pprev;
        }
        // check level 2: verify transaction index validity
        if (nCheckLevel>1)
        {
            pair<unsigned int, unsigned int> pos = make_pair(pindex->nFile, pindex->nBlockPos);
            mapBlockPos[pos] = pindex;
            BOOST_FOREACH(const CTransaction &tx, block.vtx)
            {
                uint256 hashTx = tx.GetHash();
                CTxIndex txindex;
                if (itxdb.ReadTxIndex(hashTx, txindex))
                {
                    // check level 3: checker transaction hashes
                    if (nCheckLevel>2 || pindex->nFile != txindex.pos.nFile || pindex->nBlockPos != txindex.pos.nBlockPos)
                    {
                        // either an error or a duplicate transaction
                        CTransaction txFound;
                        if (!txFound.ReadFromDisk(txindex.pos))
                        {
                            printf("LoadBlockIndex() : *** cannot read mislocated transaction %s\n", hashTx.ToString().c_str());
                            pindexFork = pindex->pprev;
                        }
                        else
                            if (txFound.GetHash() != hashTx) // not a duplicate tx
                            {
                                printf("LoadBlockIndex(): *** invalid tx position for %s\n", hashTx.ToString().c_str());
                                pindexFork = pindex->pprev;
                            }
                    }
                    // check level 4: check whether spent txouts were spent within the main chain
                    unsigned int nOutput = 0;
                    if (nCheckLevel>3)
                    {
                        BOOST_FOREACH(const CDiskTxPos &txpos, txindex.vSpent)
                        {
                            if (!txpos.IsNull())
                            {
                                pair<unsigned int, unsigned int> posFind = make_pair(txpos.nFile, txpos.nBlockPos);
                                if (!mapBlockPos.count(posFind))
                                {
                                    printf("LoadBlockIndex(): *** found bad spend at %d, hashBlock=%s, hashTx=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str(), hashTx.ToString().c_str());
                                    pindexFork = pindex->pprev;
                                }
                                // check level 6: check whether spent txouts were spent by a valid transaction that consume them
                                if (nCheckLevel>5)
                                {
                                    CTransaction txSpend;
                                    if (!txSpend.ReadFromDisk(txpos))
                                    {
                                        printf("LoadBlockIndex(): *** cannot read spending transaction of %s:%i from disk\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else if (!txSpend.CheckTransaction())
                                    {
                                        printf("LoadBlockIndex(): *** spending transaction of %s:%i is invalid\n", hashTx.ToString().c_str(), nOutput);
                                        pindexFork = pindex->pprev;
                                    }
                                    else
                                    {
                                        bool fFound = false;
                                        BOOST_FOREACH(const CTxIn &txin, txSpend.vin)
                                            if (txin.prevout.hash == hashTx && txin.prevout.n == nOutput)
                                                fFound = true;
                                        if (!fFound)
                                        {
                                            printf("LoadBlockIndex(): *** spending transaction of %s:%i does not spend it\n", hashTx.ToString().c_str(), nOutput);
                                            pindexFork = pindex->pprev;
                                        }
                                    }
                                }
                            }
                            nOutput++;
                        }
                    }
                }
                // check level 5: check whether all prevouts are marked spent
                if (nCheckLevel>4)
                {
                     BOOST_FOREACH(const CTxIn &txin, tx.vin)
                     {
                          CTxIndex txindex;
                          if (itxdb.ReadTxIndex(txin.prevout.hash, txindex))
                          {
                              if (txindex.vSpent.size()-1 < txin.prevout.n || txindex.vSpent[txin.prevout.n].IsNull())
                              {
                                  printf("LoadBlockIndex(): *** found unspent prevout %s:%i in %s\n", txin.prevout.hash.ToString().c_str(), txin.prevout.n, hashTx.ToString().c_str());
                                  pindexFork = pindex->pprev;
                              }
                          }
                     }
                }
            }
        }
     }
    if (pindexFork && !fRequestShutdown)
    {
        // Reorg back to the fork
        printf("LoadBlockIndex() : *** moving best chain pointer back to block %d\n", pindexFork->nHeight);
        CBlock block;
        if (!block.ReadFromDisk(pindexFork))
            return error("LoadBlockIndex() : block.ReadFromDisk failed");
        CTxDB txdb;
        block.SetBestChain(txdb, hcdb, pindexFork);
    }

    printf("best block loaded: %s\n", pindexBest->ToString().c_str());

    return true;
}
