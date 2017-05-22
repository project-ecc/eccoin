#include "blockindex.h"
#include "block.h"
#include "txdb-leveldb.h"
#include "checkpoints.h"
#include "key.h"
#include "mempool.h"
#include "kernel.h"
#include "wallet.h"
#include "points.h"
#include "global.h"
#include "chain.h"


#include <boost/algorithm/string/replace.hpp>

static const int CUTOFF_HEIGHT = 86400;
static CBlockIndex* pblockindexFBBHLast;
extern Checkpoints* pcheckpointMain;


// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < pindexBest->nHeight / 2)
    {
        pblockindex = pindexGenesisBlock;
    }
    else
    {
        pblockindex = pindexBest;
    }
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
    {
        pblockindex = pblockindexFBBHLast;
    }
    while (pblockindex->nHeight > nHeight)
    {
        pblockindex = pblockindex->pprev;
    }
    while (pblockindex->nHeight < nHeight)
    {
        pblockindex = pblockindex->pnext;
    }
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}



// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainTrust > nBestInvalidTrust)
    {
        nBestInvalidTrust = pindexNew->nChainTrust;
        CTxDB().WriteBestInvalidTrust(CBigNum(nBestInvalidTrust));
        uiInterface.NotifyBlocksChanged();
    }

    uint256 nBestInvalidBlockTrust = pindexNew->nChainTrust - pindexNew->pprev->nChainTrust;
    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    LogPrintf("InvalidChainFound: invalid block=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      pindexNew->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->nHeight,
      CBigNum(pindexNew->nChainTrust).ToString().c_str(), nBestInvalidBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexNew->GetBlockIndexTime()).c_str());
    LogPrintf("InvalidChainFound:  current best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      pindexBest->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->nHeight,
      CBigNum(pindexBest->nChainTrust).ToString().c_str(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockIndexTime()).c_str());
}



bool static Reorganize(CTxDB& txdb, CHeaderChainDB& hcdb, CBlockIndex* pindexNew)
{
    LogPrintf("REORGANIZE\n");

    // Find the fork
    CBlockIndex* pfork = pindexBest;
    CBlockIndex* plonger = pindexNew;
    while (pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight)
            if (!(plonger = plonger->pprev))
                return error("Reorganize() : plonger->pprev is null");
        if (pfork == plonger)
            break;
        if (!(pfork = pfork->pprev))
            return error("Reorganize() : pfork->pprev is null");
    }

    // List of what to disconnect
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = pindexBest; pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    LogPrintf("REORGANIZE: Disconnect %" PRIszu " blocks; %s..%s\n", vDisconnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->GetBlockHash().ToString().substr(0,20).c_str());
    LogPrintf("REORGANIZE: Connect %" PRIszu " blocks; %s..%s\n", vConnect.size(), pfork->GetBlockHash().ToString().substr(0,20).c_str(), pindexNew->GetBlockHash().ToString().substr(0,20).c_str());

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
    {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for disconnect failed");
        if (!block.DisconnectBlock(txdb, hcdb, pindex))
            return error("Reorganize() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());

        // Queue memory transactions to resurrect
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!(tx.IsCoinBase() || tx.IsCoinStake()))
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    for (unsigned int i = 0; i < vConnect.size(); i++)
    {
        CBlockIndex* pindex = vConnect[i];
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return error("Reorganize() : ReadFromDisk for connect failed");
        if (!block.ConnectBlock(txdb, hcdb, pindex))
        {
            // Invalid block
            return error("Reorganize() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().substr(0,20).c_str());
        }

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }
    if (!txdb.WriteHashBestChain(pindexNew->GetBlockHash()))
        return error("Reorganize() : WriteHashBestChain failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!txdb.TxnCommit())
        return error("Reorganize() : TxnCommit failed");

    // Make sure it's successfully written to disk before changing memory structure
    if (!hcdb.TxnCommit())
        return error("Reorganize() : hcbd.TxnCommit failed");

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect)
        tx.AcceptToMemoryPool(txdb, false);

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete) {
        mempool.remove(tx);
        mempool.removeConflicts(tx);
    }

    LogPrintf("REORGANIZE: done\n");

    return true;
}


uint256 CBlockHeader::GetHash() const
{
    uint256 thash;
    void * scratchbuff = scrypt_buffer_alloc();

    scrypt_hash_mine(CVOIDBEGIN(nVersion), sizeof(CBlockHeader), UINTBEGIN(thash), scratchbuff);

    scrypt_buffer_free(scratchbuff);

    return thash;
}

CBlockIndex* CBlockHeader::AddHeaderToBlockIndex()
{
    // Check for duplicate
    uint256 hash = this->GetHash();
    std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(*this);
    assert(pindexNew);
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    std::map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(this->hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }
    pindexNew->nTime = (pindexNew->pprev ? std::max(pindexNew->pprev->nTime, pindexNew->nTime) : pindexNew->nTime);
    if (pindexBestHeader == NULL)
        pindexBestHeader = pindexNew;

    return pindexNew;
}


void CBlock::SetNull()
{
    CBlockHeader::SetNull();
    vtx.clear();
    vchBlockSig.clear();
    vMerkleTree.clear();
    nDoS = 0;
}

bool CBlock::IsNull() const
{
    return (nBits == 0);
}

int64_t CBlock::GetBlockTime() const
{
    return (int64_t)nTime;
}

// entropy bit for stake modifier if chosen by modifier
unsigned int CBlock::GetStakeEntropyBit(unsigned int nHeight) const
{
    // Take last bit of block hash as entropy bit
    unsigned int nEntropyBit = static_cast<unsigned int>((GetHash().Get64()) & uint64_t(1));
    if (fDebug && GetBoolArg("-printstakemodifier"))
        LogPrintf("GetStakeEntropyBit: nHeight=%u, hashBlock=%s nEntropyBit=%u\n",nHeight, GetHash().ToString().c_str(), nEntropyBit);
    return nEntropyBit;
}

// ppcoin: two types of block: proof-of-work or proof-of-stake
bool CBlock::IsProofOfStake() const
{
    return (vtx.size() > 1 && vtx[1].IsCoinStake());
}

bool CBlock::IsProofOfWork() const
{
    return !IsProofOfStake();
}

std::pair<COutPoint, unsigned int> CBlock::GetProofOfStake() const
{
    return IsProofOfStake()? std::make_pair(vtx[1].vin[0].prevout, vtx[1].nTime) : std::make_pair(COutPoint(), (unsigned int)0);
}

// ppcoin: get max transaction timestamp
int64_t CBlock::GetMaxTransactionTime() const
{
    int64_t maxTransactionTime = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
        maxTransactionTime = std::max(maxTransactionTime, (int64_t)tx.nTime);
    return maxTransactionTime;
}

uint256 CBlock::BuildMerkleTree() const
{
    vMerkleTree.clear();
    BOOST_FOREACH(const CTransaction& tx, vtx)
        vMerkleTree.push_back(tx.GetHash());
    int j = 0;
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
    {
        for (int i = 0; i < nSize; i += 2)
        {
            int i2 = std::min(i+1, nSize-1);
            vMerkleTree.push_back(Hash(BEGIN(vMerkleTree[j+i]),  END(vMerkleTree[j+i]),
                                       BEGIN(vMerkleTree[j+i2]), END(vMerkleTree[j+i2])));
        }
        j += nSize;
    }
    if (vMerkleTree.empty())
    {
        return 0;
    }
    else
    {
        return vMerkleTree.back();
    }
}

std::vector<uint256> CBlock::GetMerkleBranch(int nIndex) const
{
    if (vMerkleTree.empty())
        BuildMerkleTree();
    std::vector<uint256> vMerkleBranch;
    int j = 0;
    for (int nSize = vtx.size(); nSize > 1; nSize = (nSize + 1) / 2)
    {
        int i = std::min(nIndex^1, nSize-1);
        vMerkleBranch.push_back(vMerkleTree[j+i]);
        nIndex >>= 1;
        j += nSize;
    }
    return vMerkleBranch;
}

uint256 CBlock::CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
{
    if (nIndex == -1)
        return 0;
    BOOST_FOREACH(const uint256& otherside, vMerkleBranch)
    {
        if (nIndex & 1)
            hash = Hash(BEGIN(otherside), END(otherside), BEGIN(hash), END(hash));
        else
            hash = Hash(BEGIN(hash), END(hash), BEGIN(otherside), END(otherside));
        nIndex >>= 1;
    }
    return hash;
}


bool CBlock::WriteToDisk(unsigned int& nFileRet, unsigned int& nBlockPosRet)
{
    // Open history file to append
    CAutoFile fileout = CAutoFile(AppendBlockFile(nFileRet), SER_DISK, CLIENT_VERSION);
    if (!fileout)
        return error("CBlock::WriteToDisk() : AppendBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(*this);
    fileout << FLATDATA(pchMessageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout);
    if (fileOutPos < 0)
        return error("CBlock::WriteToDisk() : ftell failed");
    nBlockPosRet = fileOutPos;
    fileout << *this;

    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    int compareHeight = -1;
    if(pindexBest != NULL)
    {
        compareHeight = pindexBest->nHeight;
    }
    if (!IsInitialBlockDownload() || (compareHeight + 1) % 500 == 0)
        FileCommit(fileout);
    return true;
}

bool CBlock::ReadFromDisk(unsigned int nFile, unsigned int nBlockPos, bool fReadTransactions)
{
    SetNull();

    // Open history file to read
    CAutoFile filein = CAutoFile(OpenBlockFile(nFile, nBlockPos, "rb"), SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CBlock::ReadFromDisk() : OpenBlockFile failed");
    if (!fReadTransactions)
        filein.nType |= SER_BLOCKHEADERONLY;

    // Read block
    try {
        filein >> *this;
    }
    catch (std::exception &e) {
        return error("%s() : deserialize or I/O error", BOOST_CURRENT_FUNCTION);
    }

    return true;
}



void CBlock::print() const
{
    LogPrintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%" PRIszu ", vchBlockSig=%s)\n",
        GetHash().ToString().c_str(),
        nVersion,
        hashPrevBlock.ToString().c_str(),
        hashMerkleRoot.ToString().c_str(),
        nTime, nBits, nNonce,
        vtx.size(),
        HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        LogPrintf("  ");
        vtx[i].print();
    }
    LogPrintf("  vMerkleTree: ");
    for (unsigned int i = 0; i < vMerkleTree.size(); i++)
        LogPrintf("%s ", vMerkleTree[i].ToString().substr(0,10).c_str());
    LogPrintf("\n");
}

void CBlock::printScrypt() const
{
    LogPrintf("CBlock(hash=%s, ver=%d, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%" PRIszu ", vchBlockSig=%s)\n",
        GetHash().ToString().c_str(),
        nVersion,
        hashPrevBlock.ToString().c_str(),
        hashMerkleRoot.ToString().c_str(),
        nTime, nBits, nNonce,
        vtx.size(),
        HexStr(vchBlockSig.begin(), vchBlockSig.end()).c_str());
    for (unsigned int i = 0; i < vtx.size(); i++)
    {
        LogPrintf("  ");
        vtx[i].print();
    }
    LogPrintf("  vMerkleTree: ");
    for (unsigned int i = 0; i < vMerkleTree.size(); i++)
        LogPrintf("%s ", vMerkleTree[i].ToString().substr(0,10).c_str());
    LogPrintf("\n");
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex, bool fReadTransactions)
{
    if (!fReadTransactions)
    {
        *this = pindex->GetBlockHeader();
        return true;
    }
    if (!ReadFromDisk(pindex->nFile, pindex->nBlockPos, fReadTransactions))
        return false;
    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}


void CBlock::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(GetBlockTime(), GetAdjustedTime());
}

bool CBlock::DisconnectBlock(CTxDB& txdb, CHeaderChainDB& hcdb, CBlockIndex* pindex)
{
    // Disconnect in reverse order
    for (int i = vtx.size()-1; i >= 0; i--)
        if (!vtx[i].DisconnectInputs(txdb))
            return false;

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        if(!hcdb.EraseIndexHeader(CDiskBlockIndex(pindex)))
        {
            return error("DisconnectBlock() : EraseIndexHeader failed");
        }
        /// need to do this to update the key/value pair of that block with a hashNext of 0 so it doesnt think the block that was
        /// just deleted is still the next block in the chain
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = 0;
        if (!hcdb.WriteIndexHeader(blockindexPrev))
        {
            return error("DisconnectBlock() : WriteIndexHeader failed");
        }
    }

    // ppcoin: clean up wallet after disconnecting coinstake
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, false, false);

    return true;
}

bool CBlock::ConnectBlock(CTxDB& txdb, CHeaderChainDB& hcdb, CBlockIndex* pindex, bool fJustCheck)
{
    // Check it again in case a previous version let a bad block in, but skip BlockSig checking
    if (!CheckBlock(!fJustCheck, !fJustCheck, false))
        return false;

    //// issue here: it doesn't know the version
    unsigned int nTxPos;
    if (fJustCheck)
        // FetchInputs treats CDiskTxPos(1,1,1) as a special "refer to memorypool" indicator
        // Since we're just checking the block and not actually connecting it, it might not (and probably shouldn't) be on the disk to get the transaction from
        nTxPos = 1;
    else
        nTxPos = pindex->nBlockPos + ::GetSerializeSize(CBlock(), SER_DISK, CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(vtx.size());

    map<uint256, CTxIndex> mapQueuedChanges;
    int64_t nFees = 0;
    int64_t nValueIn = 0;
    int64_t nValueOut = 0;
    unsigned int nSigOps = 0;
    BOOST_FOREACH(CTransaction& tx, vtx)
    {
        uint256 hashTx = tx.GetHash();

        // Do not allow blocks that contain transactions which 'overwrite' older transactions,
        // unless those are already completely spent.
        // If such overwrites are allowed, coinbases and transactions depending upon those
        // can be duplicated to remove the ability to spend the first instance -- even after
        // being sent to another address.
        // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
        // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
        // already refuses previously-known transaction ids entirely.
        // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
        // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
        // two in the chain that violate it. This prevents exploiting the issue against nodes in their
        // initial block download.
        CTxIndex txindexOld;
        if (txdb.ReadTxIndex(hashTx, txindexOld)) {
            BOOST_FOREACH(CDiskTxPos &pos, txindexOld.vSpent)
                if (pos.IsNull())
                    return false;
        }

        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("ConnectBlock() : too many sigops"));

        CDiskTxPos posThisTx(pindex->nFile, pindex->nBlockPos, nTxPos);
        if (!fJustCheck)
            nTxPos += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        MapPrevTx mapInputs;
        if (tx.IsCoinBase())
            nValueOut += tx.GetValueOut();
        else
        {
            bool fInvalid;
            if (!tx.FetchInputs(txdb, mapQueuedChanges, true, false, mapInputs, fInvalid))
                return false;

            // Add in sigops done by pay-to-script-hash inputs;
            // this is to prevent a "rogue miner" from creating
            // an incredibly-expensive-to-validate block.
            nSigOps += tx.GetP2SHSigOpCount(mapInputs);
            if (nSigOps > MAX_BLOCK_SIGOPS)
                return DoS(100, error("ConnectBlock() : too many sigops"));

            int64_t nTxValueIn = tx.GetValueIn(mapInputs);
            int64_t nTxValueOut = tx.GetValueOut();
            nValueIn += nTxValueIn;
            nValueOut += nTxValueOut;
            if (!tx.IsCoinStake())
                nFees += nTxValueIn - nTxValueOut;

            if (!tx.ConnectInputs(txdb, mapInputs, mapQueuedChanges, posThisTx, pindex, true, false))
                return false;
        }

        mapQueuedChanges[hashTx] = CTxIndex(posThisTx, tx.vout.size());
    }

    uint256 prevHash = 0;
    if(pindex->pprev)
    {
        prevHash = pindex->pprev->GetBlockHash();
        // LogPrintf("==> Got prevHash = %s\n", prevHash.ToString().c_str());
    }

    // ppcoin: track money supply and mint amount info
    pindex->nMint = nValueOut - nValueIn + nFees;
    pindex->nMoneySupply = (pindex->pprev? pindex->pprev->nMoneySupply : 0) + nValueOut - nValueIn;
    if (!hcdb.WriteIndexHeader(CDiskBlockIndex(pindex)))
        return error("Connect() : WriteIndexHeader for pindex failed");

    if (fJustCheck)
        return true;

    // Write queued txindex changes
    for (map<uint256, CTxIndex>::iterator mi = mapQueuedChanges.begin(); mi != mapQueuedChanges.end(); ++mi)
    {
        if (!txdb.UpdateTxIndex((*mi).first, (*mi).second))
            return error("ConnectBlock() : UpdateTxIndex failed");
    }

    // Update block index on disk without changing it in memory.
    // The memory index structure will be changed after the db commits.
    if (pindex->pprev)
    {
        CDiskBlockIndex blockindexPrev(pindex->pprev);
        blockindexPrev.hashNext = pindex->GetBlockHash();
        if (!hcdb.WriteIndexHeader(blockindexPrev))
            return error("ConnectBlock() : WriteIndexHeader failed");
    }

    // Watch for transactions paying to me
    BOOST_FOREACH(CTransaction& tx, vtx)
        SyncWithWallets(tx, this, true);

    return true;
}


// Called from inside SetBestChain: attaches a block to the new best chain being built
bool CBlock::SetBestChainInner(CTxDB& txdb, CHeaderChainDB& hcdb, CBlockIndex *pindexNew)
{
    uint256 hash = GetHash();

    // Adding to current best branch
    if (!ConnectBlock(txdb, hcdb, pindexNew) || !txdb.WriteHashBestChain(hash))
    {
        txdb.TxnAbort();
        InvalidChainFound(pindexNew);
        return false;
    }
    if (!txdb.TxnCommit())
        return error("SetBestChain() : txdb.TxnCommit failed");

    if (!hcdb.TxnCommit())
        return error("SetBestChain() : hcdb.TxnCommit failed");

    // Add to current best branch
    pindexNew->pprev->pnext = pindexNew;

    // Delete redundant memory transactions
    BOOST_FOREACH(CTransaction& tx, vtx)
        mempool.remove(tx);

    return true;
}

bool CBlock::SetBestChain(CTxDB& txdb, CHeaderChainDB& hcdb, CBlockIndex* pindexNew)
{
    uint256 hash = GetHash();

    if (!txdb.TxnBegin())
        return error("SetBestChain() : TxnBegin failed");

    if (!hcdb.TxnBegin())
        return error("SetBestChain() : hcdb.TxnBegin failed");

    if (pindexGenesisBlock == NULL && hash == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
    {
        if(!txdb.WriteHashBestChain(hash))
            return error("SetBestChain() : WriteHashBestChain failed\n");
        if (!txdb.TxnCommit())
            return error("SetBestChain() : TxnCommit failed");
        pindexGenesisBlock = pindexNew;
    }
    else if (hashPrevBlock == pindexBest->GetBlockHash())
    {
        if (!SetBestChainInner(txdb, hcdb, pindexNew))
            return error("SetBestChain() : SetBestChainInner failed");
    }
    else
    {
        // the first block in the new chain that will cause it to become the new best chain
        CBlockIndex *pindexIntermediate = pindexNew;

        // list of blocks that need to be connected afterwards
        std::vector<CBlockIndex*> vpindexSecondary;

        // Reorganize is costly in terms of db load, as it works in a single db transaction.
        // Try to limit how much needs to be done inside
        while (pindexIntermediate->pprev && pindexIntermediate->pprev->nChainTrust > pindexBest->nChainTrust)
        {
            vpindexSecondary.push_back(pindexIntermediate);
            pindexIntermediate = pindexIntermediate->pprev;
        }

        if (!vpindexSecondary.empty())
            LogPrintf("Postponing %" PRIszu " reconnects\n", vpindexSecondary.size());

        // Switch to new best branch
        if (!Reorganize(txdb, hcdb, pindexIntermediate))
        {
            txdb.TxnAbort();
            hcdb.TxnAbort();
            InvalidChainFound(pindexNew);
            return error("SetBestChain() : Reorganize failed");
        }

        // Connect further blocks
        BOOST_REVERSE_FOREACH(CBlockIndex *pindex, vpindexSecondary)
        {
            CBlock block;
            if (!block.ReadFromDisk(pindex))
            {
                LogPrintf("SetBestChain() : ReadFromDisk failed\n");
                break;
            }
            if (!txdb.TxnBegin()) {
                LogPrintf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }

            if (!hcdb.TxnBegin()) {
                LogPrintf("SetBestChain() : TxnBegin 2 failed\n");
                break;
            }

            // errors now are not fatal, we still did a reorganisation to a new chain in a valid way
            if (!block.SetBestChainInner(txdb, hcdb, pindex))
                break;
        }
    }

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload)
    {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }
    // New best block
    if(pindexBest != NULL)
    {
        pindexBest->print();
    }
    pindexBest = pindexNew;
    pindexBest->print();
    pblockindexFBBHLast = NULL;
    nBestChainTrust = pindexNew->nChainTrust;
    nBestTimeReceived = GetTime();
    nTransactionsUpdated++;

    uint256 nBestBlockTrust = pindexBest->nHeight != 0 ? (pindexBest->nChainTrust - pindexBest->pprev->nChainTrust) : pindexBest->nChainTrust;

    LogPrintf("SetBestChain: new best=%s  height=%d  trust=%s  blocktrust=%" PRId64 "  date=%s\n",
      pindexBest->GetBlockHash().ToString().substr(0,20).c_str(), pindexBest->nHeight,
      CBigNum(nBestChainTrust).ToString().c_str(),
      nBestBlockTrust.Get64(),
      DateTimeStrFormat("%x %H:%M:%S", pindexBest->GetBlockIndexTime()).c_str());

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", pindexBest->GetBlockHash().GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        uint64_t nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        LogPrintf("block coin age total nCoinDays=%" PRId64 "\n", nCoinAge);
    return true;
}

bool CBlock::AddToBlockIndex(unsigned int nFile, unsigned int nBlockPos, const uint256& hashProofOfStake)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return error("AddToBlockIndex() : %s already exists", hash.ToString().substr(0,20).c_str());

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(nFile, nBlockPos, *this);
    if (!pindexNew)
        return error("AddToBlockIndex() : new CBlockIndex failed");
    pindexNew->phashBlock = &hash;
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }
    else if( pindexNew->GetBlockHash() == hashGenesisBlock)
    {
        pindexNew->pprev = NULL;
        pindexNew->nHeight = 0;
    }
    else
    {
        LogPrintf("Previous hash could not be found in block index, asserting false \n"); /// currently failing here
        assert(false);
    }

    // ppcoin: compute chain trust score
    pindexNew->nChainTrust = (pindexNew->pprev ? pindexNew->pprev->nChainTrust : 0) + pindexNew->GetBlockTrust();

    // ppcoin: compute stake entropy bit for stake modifier
    if (!pindexNew->SetStakeEntropyBit(GetStakeEntropyBit(pindexNew->nHeight)))
        return error("AddToBlockIndex() : SetStakeEntropyBit() failed");
    // ppcoin: record proof-of-stake hash value
    pindexNew->hashProofOfStake = hashProofOfStake;

    // ppcoin: compute stake modifier
    uint64_t nStakeModifier = 0;
    bool fGeneratedStakeModifier = false;
    if (!ComputeNextStakeModifier(pindexNew->pprev, nStakeModifier, fGeneratedStakeModifier))
        return error("AddToBlockIndex() : ComputeNextStakeModifier() failed");
    pindexNew->SetStakeModifier(nStakeModifier, fGeneratedStakeModifier);
    pindexNew->nStakeModifierChecksum = GetStakeModifierChecksum(pindexNew);
    if (!CheckStakeModifierCheckpoints(pindexNew->nHeight,pindexNew))
        return error("AddToBlockIndex() : Rejected by stake modifier checkpoint height=%d, checksum=%08x, correct checksum=%08x,"
                     " nflags = %i, modifier=0x%016I64x  hashproofofstake = %s",
                     pindexNew->nHeight, pindexNew->nStakeModifierChecksum, mapStakeModifierCheckpoints[pindexNew->nHeight],
                     pindexNew->nFile, pindexNew->nStakeModifier, pindexNew->hashProofOfStake.ToString().c_str());


    // Add to mapBlockIndex
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    if (pindexNew->IsProofOfStake())
    {
        setStakeSeen.insert(make_pair(pindexNew->prevoutStake, pindexNew->nStakeTime));
    }
    pindexNew->phashBlock = &((*mi).first);

    // Write to disk block index
    CTxDB txdb;
    CHeaderChainDB hcdb;
    if (!hcdb.TxnBegin())
    {
        LogPrintf("tx begin failed \n");
        return false;
    }
    hcdb.WriteIndexHeader(CDiskBlockIndex(pindexNew));
    if (!hcdb.TxnCommit())
    {
        LogPrintf("failed to commit index header \n");
        return false;
    }
    // New best
    if (pindexNew->nChainTrust > nBestChainTrust)
    {
        if (!SetBestChain(txdb, hcdb, pindexNew))
        {
            LogPrintf("failed to set best chain \n");
            return false;
        }
    }
    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = vtx[0].GetHash();
    }

    uiInterface.NotifyBlocksChanged();
    return true;
}


bool CBlock::CheckBlock(bool fCheckPOW, bool fCheckMerkleRoot, bool fCheckSig) const
{
        // Size limits
        if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
            return DoS(100, error("CheckBlock() : size limits failed"));

         //Check proof of work matches claimed amount
        if (fCheckPOW && IsProofOfWork() && !CheckProofOfWork(GetHash(), nBits))
            return DoS(50, error("CheckBlock() : proof of work failed"));

        // Check timestamp
        if (GetBlockTime() > GetAdjustedTime() + nMaxClockDrift)
            return error("CheckBlock() : block timestamp too far in the future");

        // First transaction must be coinbase, the rest must not be
        if (vtx.empty() || !vtx[0].IsCoinBase())
            return DoS(100, error("CheckBlock() : first tx is not coinbase"));
        for (unsigned int i = 1; i < vtx.size(); i++)
            if (vtx[i].IsCoinBase())
                return DoS(100, error("CheckBlock() : more than one coinbase"));

        // ppcoin: only the second transaction can be the optional coinstake
        for (unsigned int i = 2; i < vtx.size(); i++)
            if (vtx[i].IsCoinStake())
                return DoS(100, error("CheckBlock() : coinstake in wrong position"));

        // ppcoin: coinbase output should be empty if proof-of-stake block
        if (IsProofOfStake() && (vtx[0].vout.size() != 1 || !vtx[0].vout[0].IsEmpty()))
            return error("CheckBlock() : coinbase output not empty for proof-of-stake block");

        // Check coinbase timestamp
        if (GetBlockTime() > (int64_t)vtx[0].nTime + nMaxClockDrift)
            return DoS(50, error("CheckBlock() : coinbase timestamp is too early"));

        // Check coinstake timestamp
        if (IsProofOfStake() && !CheckCoinStakeTimestamp(GetBlockTime(), (int64_t)vtx[1].nTime))
            return DoS(50, error("CheckBlock() : coinstake timestamp violation nTimeBlock=%" PRId64 " nTimeTx=%u", GetBlockTime(), vtx[1].nTime));

        // Check transactions
        BOOST_FOREACH(const CTransaction& tx, vtx)
        {
            if (!tx.CheckTransaction())
                return DoS(tx.nDoS, error("CheckBlock() : CheckTransaction failed"));

            // ppcoin: check transaction timestamp
            if (GetBlockTime() < (int64_t)tx.nTime)
                return DoS(50, error("CheckBlock() : block timestamp earlier than transaction timestamp"));
        }

        // Check for duplicate txids. This is caught by ConnectInputs(),
        // but catching it earlier avoids a potential DoS attack:
        set<uint256> uniqueTx;
        BOOST_FOREACH(const CTransaction& tx, vtx)
        {
            uniqueTx.insert(tx.GetHash());
        }
        if (uniqueTx.size() != vtx.size())
            return DoS(100, error("CheckBlock() : duplicate transaction"));

        unsigned int nSigOps = 0;
        BOOST_FOREACH(const CTransaction& tx, vtx)
        {
            nSigOps += tx.GetLegacySigOpCount();
        }
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

        // Check merkle root
        if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
            return DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));

        // ppcoin: check block signature
        if (!CheckBlockSignature())
            return DoS(100, error("CheckBlock() : bad block signature"));

    return true;
}

bool CBlock::AcceptBlock(CBlock* pblock)
{
    uint256 hash = GetHash();
    // Check for duplicate
    if (mapBlockIndex.count(hash))
        return error("AcceptBlock() : block already in mapBlockIndex");

    // Get prev block index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
    if (mi == mapBlockIndex.end())
    {
        return DoS(10, error("AcceptBlock() : prev block not found"));
    }
    CBlockIndex* pindexPrev = (*mi).second;
    int nHeight = pindexPrev->nHeight +1 ;

    bool IsPoS = (nBits != GetNextTargetRequired(pindexPrev, true) && nHeight > CUTOFF_HEIGHT);
    //bool IsPoW = ( (nBits != GetNextTargetRequired(pindexPrev, false)) && nHeight <= CUTOFF_HEIGHT ); //not used by ECC
    //if ( (IsPoS | IsPoW) == true)
    if(IsPoS == true)
    {
        //LogPrintf("nBits = %i , GetNextTarget = %i \n", nBits, GetNextTargetRequired(pindexPrev, true));
        LogPrintf("AcceptBlock() : Block is not Correct PoW or Pos. hash: %s, prevhash: %s \n",hash.ToString().substr(0,20).c_str(), pblock->hashPrevBlock.ToString().substr(0,20).c_str());
        return DoS(100, error("error"));
    }

    // Check timestamp against prev
    if (GetBlockTime() <= pindexPrev->GetMedianTimePast() || GetBlockTime() + nMaxClockDrift < pindexPrev->GetBlockIndexTime())
        return error("AcceptBlock() : block's timestamp is too early");

    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.IsFinal(nHeight, GetBlockTime()))
            return DoS(10, error("AcceptBlock() : contains a non-final transaction"));

    // Check that the block chain matches the known block chain up to a checkpoint
    if (!pcheckpointMain->CheckHardened(nHeight, hash))
        return DoS(100, error("AcceptBlock() : rejected by hardened checkpoint lock-in at %d", nHeight));

    // ppcoin: check that the block satisfies synchronized checkpoint
    if (!pcheckpointMain->CheckSync(hash, pindexPrev))
    {
        if(!GetBoolArg("-nosynccheckpoints", false))
        {
            return error("AcceptBlock() : rejected by synchronized checkpoint");
        }
        else
        {
            strMiscWarning = ("WARNING: syncronized checkpoint violation detected, but skipped!");
        }
    }

    // Verify hash target and signature of coinstake tx
    uint256 hashProofOfStake = 0;
    if (IsProofOfStake())
    {
        if (!CheckProofOfStake(vtx[1], nBits, hashProofOfStake))
        {
            LogPrintf("WARNING: ProcessBlock(): check proof-of-stake failed for block %s\n", hash.ToString().c_str());
            return false; // do not error here as we expect this during initial block download
        }
    }

    // Reject block.nVersion < 3 blocks since 95% threshold on mainNet and always on testNet:
    if (nVersion < 3 && ((!fTestNet && nHeight > 14060) || (fTestNet && nHeight > 0)))
        return error("CheckBlock() : rejected nVersion < 3 block");

    // Enforce rule that the coinbase starts with serialized block height
    CScript expect = CScript() << nHeight;
    if (!std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
        return DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));

    // Write block to history file
    if (!CheckDiskSpace(::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION)))
        return error("AcceptBlock() : out of disk space");
    unsigned int nFile = -1;
    unsigned int nBlockPos = 0;
    if (!WriteToDisk(nFile, nBlockPos))
        return error("AcceptBlock() : WriteToDisk failed");
    if (!AddToBlockIndex(nFile, nBlockPos, hashProofOfStake))
        return error("AcceptBlock() : AddToBlockIndex failed");

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = pcheckpointMain->GetTotalBlocksEstimate();
    if (pindexBest->GetBlockHash() == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
        {
            if (pindexBest->nHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
            {
                std::vector<CInv> vInv;
                vInv.push_back(CInv(MSG_BLOCK, hash));
                pnode->PushMessage("inv", vInv);
            }
        }
    }

    // ppcoin: check pending sync-checkpoint
    pcheckpointMain->AcceptPendingSyncCheckpoint();

    return true;
}


bool CBlock::SignScryptBlock(const CKeyStore& keystore)
{
    vector<valtype> vSolutions;
    txnouttype whichType;

    if(!IsProofOfStake())
    {
        for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
        {
            const CTxOut& txout = vtx[0].vout[i];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                continue;

            if (whichType == TX_PUBKEY)
            {
                // Sign
                valtype& vchPubKey = vSolutions[0];
                CKey key;

                if (!keystore.GetKey(Hash160(vchPubKey), key))
                    continue;
                if (key.GetPubKey() != vchPubKey)
                    continue;
                if(!key.Sign(GetHash(), vchBlockSig))
                    continue;

                return true;
            }
        }
    }
    else
    {
        const CTxOut& txout = vtx[1].vout[1];

        if (!Solver(txout.scriptPubKey, whichType, vSolutions))
            return false;

        if (whichType == TX_PUBKEY)
        {
            // Sign
            valtype& vchPubKey = vSolutions[0];
            CKey key;

            if (!keystore.GetKey(Hash160(vchPubKey), key))
                return false;
            if (key.GetPubKey() != vchPubKey)
                return false;

            return key.Sign(GetHash(), vchBlockSig);
        }
    }

    LogPrintf("Sign failed\n");
    return false;
}

bool CBlock::CheckBlockSignature() const
{
        if (GetHash() == (!fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet))
            return vchBlockSig.empty();

        vector<valtype> vSolutions;
        txnouttype whichType;

        if(IsProofOfStake())
        {
            const CTxOut& txout = vtx[1].vout[1];

            if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                return false;
            if (whichType == TX_PUBKEY)
            {
                valtype& vchPubKey = vSolutions[0];
                CKey key;
                if (!key.SetPubKey(vchPubKey))
                    return false;
                if (vchBlockSig.empty())
                    return false;
                return key.Verify(GetHash(), vchBlockSig);
            }
        }
        else
        {
            for(unsigned int i = 0; i < vtx[0].vout.size(); i++)
            {
                const CTxOut& txout = vtx[0].vout[i];

                if (!Solver(txout.scriptPubKey, whichType, vSolutions))
                    return false;

                if (whichType == TX_PUBKEY)
                {
                    // Verify
                    valtype& vchPubKey = vSolutions[0];
                    CKey key;
                    if (!key.SetPubKey(vchPubKey))
                        continue;
                    if (vchBlockSig.empty())
                        continue;
                    if(!key.Verify(GetHash(), vchBlockSig))
                        continue;

                    return true;
                }
            }
        }
        return false;
}

CBlockHeader CBlock::GetBlockHeader() const
{
    CBlockHeader block;
    block.nVersion       = nVersion;
    block.hashPrevBlock  = hashPrevBlock;
    block.hashMerkleRoot = hashMerkleRoot;
    block.nTime          = nTime;
    block.nBits          = nBits;
    block.nNonce         = nNonce;
    return block;
}


