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

#ifndef CHAINMAN_H
#define CHAINMAN_H

#include <unordered_map>

#include "chain.h"
#include "networks/networktemplate.h"
#include "txdb.h"


struct BlockHasher
{
    size_t operator()(const uint256 &hash) const { return hash.GetCheapHash(); }
};
typedef std::unordered_map<uint256, CBlockIndex *, BlockHasher> BlockMap;


/** Manages the BlockMap and CChain's for a given protocol. */
class CChainManager
{
public:
    CRecursiveSharedCriticalSection cs_mapBlockIndex;

    /** map containing all block indexs ever seen for this chain */
    BlockMap mapBlockIndex GUARDED_BY(cs_mapBlockIndex);

    /** The currently-connected chain of blocks (protected by cs_mapBlockIndex). */
    CChain chainActive;

    /** Best header we've seen so far (used for getheaders queries' starting points). */
    std::atomic<CBlockIndex *> pindexBestHeader;

private:
    bool LoadBlockIndexDB();

public:
    CChainManager()
    {
        mapBlockIndex.clear();
        chainActive = CChain();
        pindexBestHeader = nullptr;
    }

    ~CChainManager()
    {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
        {
            delete (*it1).second;
        }
        mapBlockIndex.clear();
        pindexBestHeader = nullptr;
    }

    void operator=(const CChainManager &oldMan)
    {
        RECURSIVEWRITELOCK(cs_mapBlockIndex);
        mapBlockIndex = oldMan.mapBlockIndex;
        chainActive = oldMan.chainActive;
        pindexBestHeader.store(oldMan.pindexBestHeader.load());
    }

    /** Look up the block index entry for a given block hash. returns nullptr if it does not exist */
    CBlockIndex *LookupBlockIndex(const uint256 &hash);

    /** Add a new block index entry for a given block recieved from the network */
    CBlockIndex *AddToBlockIndex(const CBlockHeader &block);

    /** Find the last common block between the parameter chain and a locator. */
    CBlockIndex *FindForkInGlobalIndex(const CChain &chain, const CBlockLocator &locator);

    /** Check whether we are doing an initial block download (synchronizing from disk or network) */
    bool IsInitialBlockDownload();

    /** Initialize a new block tree database + block data on disk */
    bool InitBlockIndex(const CNetworkTemplate &chainparams);

    /** Create a new block index entry for a given block hash loaded from disk*/
    CBlockIndex *InsertBlockIndex(uint256 hash);

    /** Load the block tree and coins database from disk */
    bool LoadBlockIndex();

    /** Import blocks from an external file */
    bool LoadExternalBlockFile(const CNetworkTemplate &chainparams, FILE *fileIn, CDiskBlockPos *dbp = NULL);

    /** Unload database information */
    void UnloadBlockIndex();
};

#endif // CHAINMAN_H
