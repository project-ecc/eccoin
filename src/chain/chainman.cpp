/*
 * This file is part of the Eccoin project
 * Copyright (c) 2017-2018 Greg Griffith
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

#include "chainman.h"
#include "checkpoints.h"
#include "consensus/consensus.h"
#include "init.h"
#include "kernel.h"
#include "main.h"
#include "messages.h"
#include "networks/netman.h"
#include "processblock.h"
#include "processheader.h"
#include "txmempool.h"
#include "undo.h"

CBlockIndex *CChainManager::AddToBlockIndex(const CBlockHeader &block)
{
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex *pindexNew = new CBlockIndex(block);
    assert(pindexNew);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == NULL || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

CBlockIndex *CChainManager::FindForkInGlobalIndex(const CChain &chain, const CBlockLocator &locator)
{
    // Find the first block the caller has in the main chain
    for (auto const &hash : locator.vHave)
    {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex *pindex = (*mi).second;
            if (chain.Contains(pindex))
                return pindex;
        }
    }
    return chain.Genesis();
}

bool CChainManager::IsInitialBlockDownload()
{
    const CNetworkTemplate &chainParams = pnetMan->getActivePaymentNetwork();
    LOCK(cs_main);
    if (fImporting || fReindex)
        return true;
    if (fCheckpointsEnabled && chainActive.Height() < Checkpoints::GetTotalBlocksEstimate(chainParams.Checkpoints()))
        return true;
    static bool lockIBDState = false;
    if (lockIBDState)
        return false;
    bool state = (chainActive.Height() < pindexBestHeader->nHeight - 24 * 6 ||
                  pindexBestHeader->GetBlockTime() < GetTime() - chainParams.MaxTipAge());
    if (!state)
        lockIBDState = true;
    return state;
}

CBlockIndex *CChainManager::InsertBlockIndex(uint256 hash)
{
    if (hash.IsNull())
        return NULL;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex *pindexNew = new CBlockIndex();
    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CChainManager::InitBlockIndex(const CNetworkTemplate &chainparams)
{
    LOCK(cs_main);

    // Initialize global variables that cannot be constructed at startup.
    recentRejects.reset(new CRollingBloomFilter(120000, 0.000001));

    // Check whether we're already initialized
    if (chainActive.Genesis() != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    pblocktree->WriteFlag("txindex", true);
    LogPrintf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex)
    {
        try
        {
            std::shared_ptr<CBlock> spblock = std::make_shared<CBlock>();
            CBlock &block = *spblock;
            block = chainparams.GenesisBlock();
            // Start new block file
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!FindBlockPos(state, blockPos, nBlockSize + 8, 0, block.GetBlockTime()))
                return error("InitBlockIndex(): FindBlockPos failed");
            if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart()))
                return error("InitBlockIndex(): writing genesis block to disk failed");
            CBlockIndex *pindex = AddToBlockIndex(block);

            // ppcoin: compute stake entropy bit for stake modifier
            if (!pindex->SetStakeEntropyBit(block.GetStakeEntropyBit()))
            {
                return error("InitBlockIndex() : SetStakeEntropyBit() failed");
            }
            // ppcoin: compute stake modifier
            uint256 nStakeModifier;
            nStakeModifier.SetNull();
            CTransaction nullTx;
            if (!ComputeNextStakeModifier(pindex->pprev, nullTx, nStakeModifier))
                return error("InitBlockIndex() : ComputeNextStakeModifier() failed");
            pindex->SetStakeModifier(nStakeModifier);
            if (!ReceivedBlockTransactions(block, state, pindex, blockPos))
                return error("InitBlockIndex(): genesis block not accepted");
            if (!ActivateBestChain(state, chainparams, spblock))
                return error("InitBlockIndex(): genesis block cannot be activated");
            // Force a chainstate write so that when we VerifyDB in a moment, it doesn't check stale data
            return FlushStateToDisk(state, FLUSH_STATE_ALWAYS);
        }
        catch (const std::runtime_error &e)
        {
            return error("InitBlockIndex(): failed to initialize block database: %s", e.what());
        }
    }

    return true;
}

bool CChainManager::LoadBlockIndex()
{
    // Load block index from databases
    if (!fReindex && !LoadBlockIndexDB())
        return false;
    return true;
}

bool CChainManager::LoadBlockIndexDB()
{
    int64_t nStart = GetTimeMillis();
    if (!pblocktree->LoadBlockIndexGuts())
    {
        return false;
    }

    LogPrintf("LoadBlockIndexGuts %15dms\n", GetTimeMillis() - nStart);

    if (shutdown_threads.load())
    {
        LogPrintf("LoadBlockIndexDB(): Shutdown requested. returning...\n");
        return false;
    }

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex *> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const std::pair<uint256, CBlockIndex *> &item : mapBlockIndex)
    {
        CBlockIndex *pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }
    std::sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, CBlockIndex *> &item : vSortedByHeight)
    {
        CBlockIndex *pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0)
        {
            if (pindex->pprev)
            {
                if (pindex->pprev->nChainTx)
                {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                }
                else
                {
                    pindex->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            }
            else
            {
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == NULL))
        {
            setBlockIndexCandidates.insert(pindex);
        }
        if (pindex->nStatus & BLOCK_FAILED_MASK &&
            (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
        {
            pindexBestInvalid = pindex;
        }
        if (pindex->pprev)
        {
            pindex->BuildSkip();
        }
        if (pindex->IsValid(BLOCK_VALID_TREE) &&
            (pindexBestHeader == NULL || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
        {
            pindexBestHeader = pindex;
        }
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++)
    {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++)
    {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info))
        {
            vinfoBlockFile.push_back(info);
        }
        else
        {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (auto const &item : mapBlockIndex)
    {
        CBlockIndex *pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA)
        {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull())
        {
            return false;
        }
    }

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if (fReindexing)
        fReindex = true;

    // Load pointer to end of best chain
    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    if (it == mapBlockIndex.end())
    {
        return true;
    }
    chainActive.SetTip(it->second);

    PruneBlockIndexCandidates();

    return true;
}


bool CChainManager::LoadExternalBlockFile(const CNetworkTemplate &chainparams, FILE *fileIn, CDiskBlockPos *dbp)
{
    // std::map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try
    {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2 * MAX_BLOCK_SIZE, MAX_BLOCK_SIZE + 8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof())
        {
            if (shutdown_threads.load())
            {
                break;
            }

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try
            {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos() + 1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, std::begin(chainparams.MessageStart()), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SIZE)
                    continue;
            }
            catch (const std::exception &)
            {
                // no valid block header found; don't complain
                break;
            }
            try
            {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> spblock = std::make_shared<CBlock>();
                CBlock &block = *spblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.GetHash();
                if (hash != chainparams.GetConsensus().hashGenesisBlock &&
                    mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end())
                {
                    LogPrint("reindex", "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                        block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0)
                {
                    CValidationState state;
                    if (ProcessNewBlock(state, chainparams, NULL, spblock, true, dbp))
                        nLoaded++;
                    if (state.IsError())
                        break;
                }
                else if (hash != chainparams.GetConsensus().hashGenesisBlock &&
                         mapBlockIndex[hash]->nHeight % 1000 == 0)
                {
                    LogPrintf("Block Import: already had block %s at height %d\n", hash.ToString(),
                        mapBlockIndex[hash]->nHeight);
                }
                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty())
                {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator,
                        std::multimap<uint256, CDiskBlockPos>::iterator>
                        range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second)
                    {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        if (ReadBlockFromDisk(block, it->second, chainparams.GetConsensus()))
                        {
                            LogPrintf("%s: Processing out of order child %s of %s\n", __func__,
                                block.GetHash().ToString(), head.ToString());
                            CValidationState dummy;
                            if (ProcessNewBlock(dummy, chainparams, NULL, spblock, true, &it->second))
                            {
                                nLoaded++;
                                queue.push_back(block.GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                    }
                }
            }
            catch (const std::exception &e)
            {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    }
    catch (const std::runtime_error &e)
    {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void CChainManager::UnloadBlockIndex()
{
    LOCK(cs_main);
    setBlockIndexCandidates.clear();
    chainActive.SetTip(NULL);
    pindexBestInvalid = NULL;
    pindexBestHeader = NULL;
    mempool.clear();
    mapOrphanTransactions.clear();
    mapOrphanTransactionsByPrev.clear();
    nSyncStarted = 0;
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    nBlockSequenceId = 1;
    mapBlockSource.clear();
    mapBlocksInFlight.clear();
    nPreferredDownload = 0;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    mapNodeState.clear();
    recentRejects.reset(NULL);
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++)
    {
        warningcache[b].clear();
    }

    for (auto &entry : mapBlockIndex)
    {
        delete entry.second;
    }
    mapBlockIndex.clear();
}
