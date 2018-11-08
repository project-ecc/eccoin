/*
 * This file is part of the ECC project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The ECC developers
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

#include "pow.h"

#include "arith_uint256.h"
#include "chain/chain.h"
#include "main.h"
#include "networks/netman.h"
#include "uint256.h"
#include "util/util.h"

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params &params)
{
    if (hash == params.hashGenesisBlock)
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
        return error("CheckProofOfWork(): hash doesn't match nBits");
    }

    return true;
}

arith_uint256 GetBlockProof(const CBlockIndex &index)
{
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

int64_t GetBlockProofEquivalentTime(const CBlockIndex &to,
    const CBlockIndex &from,
    const CBlockIndex &tip,
    const Consensus::Params &params)
{
    arith_uint256 r;
    int sign = 1;
    if (to.nChainWork > from.nChainWork)
    {
        r = to.nChainWork - from.nChainWork;
    }
    else
    {
        r = from.nChainWork - to.nChainWork;
        sign = -1;
    }
    int64_t targetSpacing = params.nTargetSpacing;
    if (tip.GetMedianTimePast() > SERVICE_UPGRADE_HARDFORK)
    {
        targetSpacing = 150;
    }
    r = r * arith_uint256(targetSpacing) / GetBlockProof(tip);
    if (r.bits() > 63)
    {
        return sign * std::numeric_limits<int64_t>::max();
    }
    return sign * r.GetLow64();
}
