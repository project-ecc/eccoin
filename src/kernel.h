// Copyright (c) 2012-2013 The PPCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef PPCOIN_KERNEL_H
#define PPCOIN_KERNEL_H

#include <boost/assign/list_of.hpp>

#include "main.h"

static std::map<int, unsigned int> mapStakeModifierCheckpoints =
	boost::assign::map_list_of
        (     0, 0x0e00670bu )
        (  1000, 0xd97d4595u )
        ( 10000, 0x1cf3438cu )
        ( 50000, 0x8b989994u )
        ( 65000, 0xc10d7013u )
        ( 75000, 0xfa84c87cu )
        ( 77050, 0xf4162613u )
        ( 77500, 0x2af7615fu )
        ( 79000, 0x9b98a665u )
        ( 80000, 0x7d24c746u )
        ( 90000, 0x439f90b3u )
        (100000, 0x5ed74657u )
        (150000, 0x2fd6a457u )
        (185000, 0xa28ede88u )
        (197712, 0x4dbd9ac4u )
        ;

// MODIFIER_INTERVAL: time to elapse before new modifier is computed
static const unsigned int MODIFIER_INTERVAL = 6 * 60 * 60;
extern unsigned int nModifierInterval;
extern unsigned int nModifierIntervalSecond;


// MODIFIER_INTERVAL_RATIO:
// ratio of group interval length between the last group and the first group
static const int MODIFIER_INTERVAL_RATIO = 3;

// Compute the hash modifier for proof-of-stake
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64_t & nStakeModifier, bool& fGeneratedStakeModifier);

// Check whether stake kernel meets hash target
// Sets hashProofOfStake on success return
bool CheckStakeKernelHash(unsigned int nBits, const CBlock& blockFrom, unsigned int nTxPrevOffset, const CTransaction& txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake=false);

// Check kernel hash target and coinstake signature
// Sets hashProofOfStake on success return
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake);

// Check whether the coinstake timestamp meets protocol
bool CheckCoinStakeTimestamp(int64_t nTimeBlock, int64_t nTimeTx);

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex);

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, CBlockIndex *pindexNew);

#endif // PPCOIN_KERNEL_H
