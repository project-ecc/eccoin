// This file is part of the Eccoin project
// Copyright (c) 2012-2013 The PPCoin developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PPCOIN_KERNEL_H
#define PPCOIN_KERNEL_H

#include "main.h"

// Compute the hash modifier for proof-of-stake
bool ComputeNextStakeModifier(const CBlockIndex *pindexPrev, const CTransaction &tx, uint256 &nStakeModifier);

// Check whether stake kernel meets hash target
// Sets hashProofOfStake on success return
bool CheckStakeKernelHash(int nHeight,
    const CBlock &blockFrom,
    unsigned int nTxPrevOffset,
    const CTransaction &txPrev,
    const COutPoint &prevout,
    unsigned int nTimeTx,
    uint256 &hashProofOfStake);

// Check kernel hash target and coinstake signature
// Sets hashProofOfStake on success return
bool CheckProofOfStake(int nHeight, const CTransaction &tx, uint256 &hashProofOfStake);
#endif // PPCOIN_KERNEL_H
