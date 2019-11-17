// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_STORAGE_H
#define BITCOIN_BLOCK_STORAGE_H

#include "chain/blockindex.h"
#include "consensus/params.h"
#include "fs.h"
#include "net/protocol.h"
#include "sync.h"
#include "undo.h"

/** Translation to a filesystem path */
fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix);
/** Open a block file (blk?????.dat) */
FILE *OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Open an undo file (rev?????.dat) */
FILE *OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);
/** Functions for disk access for blocks */
bool WriteBlockToDisk(const CBlock &block, CDiskBlockPos &pos, const CMessageHeader::MessageMagic &messageStart);

bool ReadBlockFromDisk(CBlock &block, const CDiskBlockPos &pos, const Consensus::Params &consensusParams);

bool ReadBlockFromDisk(CBlock &block, const CBlockIndex *pindex, const Consensus::Params &consensusParams);

bool UndoWriteToDisk(const CBlockUndo &blockundo,
    CDiskBlockPos &pos,
    const uint256 &hashBlock,
    const CMessageHeader::MessageMagic &messageStart);

bool UndoReadFromDisk(CBlockUndo &blockundo, const CDiskBlockPos &pos, const uint256 &hashBlock);

#endif
