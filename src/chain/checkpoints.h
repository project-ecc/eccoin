// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHECKPOINTS_H
#define BITCOIN_CHECKPOINTS_H

#include "uint256.h"

#include <map>

class CBlockIndex;

typedef std::map<int, uint256> MapCheckpoints;

/**
 * Block-chain checkpoints are compiled-in sanity checks.
 * They are updated every release or three.
 */
namespace Checkpoints
{
//! Return conservative estimate of total number of blocks, 0 if unknown
int GetTotalBlocksEstimate(const MapCheckpoints &checkpoints);

//! Returns last CBlockIndex* in mapBlockIndex that is a checkpoint
CBlockIndex *GetLastCheckpoint(const MapCheckpoints &checkpoints);

} // namespace Checkpoints

#endif // BITCOIN_CHECKPOINTS_H
