// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.


#include "blockindex.h"

/** Turn the lowest '1' bit in the binary representation of a number into a '0'. */
int static inline InvertLowestOne(int n) { return n & (n - 1); }
/** Compute what height to jump back to with the CBlockIndex::pskip pointer. */
int static inline GetSkipHeight(int height)
{
    if (height < 2)
        return 0;

    // Determine which height to jump back to. Any number strictly lower than height is acceptable,
    // but the following expression seems to perform well in simulations (max 110 steps to go back
    // up to 2**18 blocks).
    return (height & 1) ? InvertLowestOne(InvertLowestOne(height - 1)) + 1 : InvertLowestOne(height);
}

CBlockIndex *CBlockIndex::GetAncestor(int height)
{
    if (height > nHeight || height < 0)
        return nullptr;

    CBlockIndex *pindexWalk = this;
    int heightWalk = nHeight;
    while (heightWalk > height)
    {
        int heightSkip = GetSkipHeight(heightWalk);
        int heightSkipPrev = GetSkipHeight(heightWalk - 1);
        if (pindexWalk->pskip != nullptr &&
            (heightSkip == height ||
                (heightSkip > height && !(heightSkipPrev < heightSkip - 2 && heightSkipPrev >= height))))
        {
            // Only follow pskip if pprev->pskip isn't better than pskip->pprev.
            pindexWalk = pindexWalk->pskip;
            heightWalk = heightSkip;
        }
        else
        {
            pindexWalk = pindexWalk->pprev;
            heightWalk--;
        }
    }
    return pindexWalk;
}

const CBlockIndex *CBlockIndex::GetAncestor(int height) const
{
    return const_cast<CBlockIndex *>(this)->GetAncestor(height);
}

void CBlockIndex::updateForPos(const CBlock &block)
{
    nFlags = 0;
    prevoutStake.SetNull();
    nStakeTime = 0;
    if (block.IsProofOfStake())
    {
        SetProofOfStake();
        prevoutStake = block.vtx[1]->vin[0].prevout;
        nStakeTime = block.vtx[1]->nTime;
    }
}

void CBlockIndex::BuildSkip()
{
    if (pprev)
        pskip = pprev->GetAncestor(GetSkipHeight(nHeight));
}

bool CBlockIndex::IsProofOfWork() const { return !(nFlags & BLOCK_PROOF_OF_STAKE); }
bool CBlockIndex::IsProofOfStake() const { return (nFlags & BLOCK_PROOF_OF_STAKE); }
void CBlockIndex::SetProofOfStake() { nFlags |= BLOCK_PROOF_OF_STAKE; }
unsigned int CBlockIndex::GetStakeEntropyBit() const { return ((nFlags & BLOCK_STAKE_ENTROPY) >> 1); }
bool CBlockIndex::SetStakeEntropyBit(unsigned int nEntropyBit)
{
    if (nEntropyBit > 1)
        return false;
    nFlags |= (nEntropyBit ? BLOCK_STAKE_ENTROPY : 0);
    return true;
}

void CBlockIndex::SetStakeModifier(uint256 nModifier) { nStakeModifier = nModifier; }
