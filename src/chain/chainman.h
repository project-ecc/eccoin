// Copyright (c) 2017 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CHAINMAN_H
#define CHAINMAN_H

#include <unordered_map>

#include "networks/networktemplate.h"
#include "chain.h"
#include "txdb.h"


struct BlockHasher
{
    size_t operator()(const uint256& hash) const { return hash.GetCheapHash(); }
};
typedef std::unordered_map<uint256, CBlockIndex*, BlockHasher> BlockMap;


/** Manages the BlockMap and CChain's for a given protocol. */
class CChainManager {

public:
    /** map containing all block indexs ever seen for this chain */
    BlockMap mapBlockIndex;

    /** The currently-connected chain of blocks (protected by cs_main). */
    CChain chainActive;

    /** Best header we've seen so far (used for getheaders queries' starting points). */
    CBlockIndex *pindexBestHeader;

    /** Global variable that points to the active CCoinsView (protected by cs_main) */
    std::unique_ptr<CCoinsViewCache> pcoinsTip;

    /** Global variable that points to the active block tree (protected by cs_main) */
    std::unique_ptr<CBlockTreeDB> pblocktree;

private:
    bool LoadBlockIndexDB();

public:

    CChainManager(){
        mapBlockIndex.clear();
        chainActive = CChain();
        pindexBestHeader = NULL;
        pcoinsTip.reset();
        pblocktree.reset();
    }

    ~CChainManager()
    {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
        delete pindexBestHeader;
        pcoinsTip.reset();
        pblocktree.reset();
    }

    void operator=(const CChainManager& oldMan)
    {
        mapBlockIndex = oldMan.mapBlockIndex;
        chainActive = oldMan.chainActive;
        pindexBestHeader = oldMan.pindexBestHeader;
        pcoinsTip.reset(oldMan.pcoinsTip.get());
        pblocktree.reset(oldMan.pblocktree.get());
    }


    /** Add a new block index entry for a given block recieved from the network */
    CBlockIndex* AddToBlockIndex(const CBlockHeader& block);

    /** Find the last common block between the parameter chain and a locator. */
    CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator);

    /** Check whether we are doing an initial block download (synchronizing from disk or network) */
    bool IsInitialBlockDownload();

    /** Initialize a new block tree database + block data on disk */
    bool InitBlockIndex(const CNetworkTemplate& chainparams);

    /** Create a new block index entry for a given block hash loaded from disk*/
    CBlockIndex* InsertBlockIndex(uint256 hash);

    /** Load the block tree and coins database from disk */
    bool LoadBlockIndex();

    /** Import blocks from an external file */
    bool LoadExternalBlockFile(const CNetworkTemplate& chainparams, FILE* fileIn, CDiskBlockPos *dbp = NULL);

    /** Unload database information */
    void UnloadBlockIndex();



};

#endif // CHAINMAN_H
