
#ifndef BITCOIN_BLOCK_STORAGE_H
#define BITCOIN_BLOCK_STORAGE_H

#include "chain/blockindex.h"
#include "consensus/params.h"
#include "fs.h"
#include "net/protocol.h"
#include "sync.h"

extern CCriticalSection cs_blockstorage;

/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);
/** Open a block file (blk?????.dat) */
FILE *OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE *OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Functions for disk access for blocks */
bool WriteBlockToDisk(const CBlock &block, CDiskBlockPos &pos, const CMessageHeader::MessageMagic &messageStart)
    EXCLUSIVE_LOCKS_REQUIRED(cs_blockstorage);
bool ReadBlockFromDisk(CBlock &block, const CDiskBlockPos &pos, const Consensus::Params &consensusParams)
    EXCLUSIVE_LOCKS_REQUIRED(cs_blockstorage);
bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex, const Consensus::Params &consensusParams)
    EXCLUSIVE_LOCKS_REQUIRED(cs_blockstorage);


#endif
