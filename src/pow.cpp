// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "networks/netman.h"
#include "arith_uint256.h"
#include "chain/chain.h"
#include "uint256.h"
#include "util/util.h"
#include "main.h"

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    if(hash == params.hashGenesisBlock)
        return true;

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        return error("CheckProofOfWork(): nBits below minimum work");

    // Check proof of work matches claimed amount
    if (UintToArith256(hash) > bnTarget)
    {
        LogPrintf("%s > %s and it should not be \n",hash.ToString().c_str(), bnTarget.ToString().c_str());
        return error("CheckProofOfWork(): hash doesn't match nBits");
    }

    return true;
}

arith_uint256 GetBlockProof(const CBlockIndex& index)
{
    /// if this is true block is PoS and we need to calculate work a different way
    if(index.IsProofOfStake())
    {
        /// for proof of stake blocks, use the hash proof of stake instead of the blocks hash to add to the work as newer blocks actually do a lot of work to get a valid Proof of stake hash
        /// (by a lot i mean more than they previously had to do)
        arith_uint256 bnTarget = UintToArith256(index.hashProofOfStake);
        return (~bnTarget / (bnTarget + 1)) + 1;
    }
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(index.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a arith_uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

int64_t GetBlockProofEquivalentTime(const CBlockIndex& to, const CBlockIndex& from, const CBlockIndex& tip, const Consensus::Params& params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork) {
        r = to.nChainWork - from.nChainWork;
    } else {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    int64_t targetSpacing = params.nTargetSpacing;
    if(tip.GetMedianTimePast() > SERVICE_UPGRADE_HARDFORK)
    {
        targetSpacing = 150;
    }
    r = r * arith_uint256(targetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63) {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}
