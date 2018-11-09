/*
 * This file is part of the Eccoin project
 * Copyright (c) 2009-2010 Satoshi Nakamoto
 * Copyright (c) 2009-2016 The Bitcoin Core developers
 * Copyright (c) 2014-2018 The Eccoin developers
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

#include "checkpoints.h"

#include "chain.h"
#include "init.h"
#include "main.h"
#include "networks/networktemplate.h"
#include "uint256.h"

#include <boost/foreach.hpp>
#include <stdint.h>

namespace Checkpoints
{
/**
 * How many times slower we expect checking transactions after the last
 * checkpoint to be (from checking signatures, which is skipped up to the
 * last checkpoint). This number is a compromise, as it can't be accurate
 * for every system. When reindexing from a fast disk with a slow CPU, it
 * can be up to 20, while when downloading from a slow network with a
 * fast multicore CPU, it won't be much higher than 1.
 */
static const double SIGCHECK_VERIFICATION_FACTOR = 5.0;

//! Guess how far we are in the verification process at the given block index
double GuessVerificationProgress(const CCheckpointData &data, CBlockIndex *pindex, bool fSigchecks)
{
    if (pindex == NULL)
        return 0.0;

    //        int64_t nNow = time(NULL);

    //        double fSigcheckVerificationFactor = fSigchecks ? SIGCHECK_VERIFICATION_FACTOR : 1.0;
    //        double fWorkBefore = 0.0; // Amount of work done before pindex
    //        double fWorkAfter = 0.0;  // Amount of work left after pindex (estimated)
    // Work is defined as: 1.0 per transaction before the last checkpoint, and
    // fSigcheckVerificationFactor per transaction after.
    /*
            if (pindex->nChainTx <= data.nTransactionsLastCheckpoint) {
                double nCheapBefore = pindex->nChainTx;
                double nCheapAfter = data.nTransactionsLastCheckpoint - pindex->nChainTx;
                double nExpensiveAfter = (nNow - data.nTimeLastCheckpoint)/86400.0*data.fTransactionsPerDay;
                fWorkBefore = nCheapBefore;
                fWorkAfter = nCheapAfter + nExpensiveAfter*fSigcheckVerificationFactor;
            } else {
                double nCheapBefore = data.nTransactionsLastCheckpoint;
                double nExpensiveBefore = pindex->nChainTx - data.nTransactionsLastCheckpoint;
                double nExpensiveAfter = (nNow - pindex->GetBlockTime())/86400.0*data.fTransactionsPerDay;
                fWorkBefore = nCheapBefore + nExpensiveBefore*fSigcheckVerificationFactor;
                fWorkAfter = nExpensiveAfter*fSigcheckVerificationFactor;
            }
    */
    // return fWorkBefore / (fWorkBefore + fWorkAfter);
    return 0;
}

int GetTotalBlocksEstimate(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    if (checkpoints.empty())
        return 0;

    return checkpoints.rbegin()->first;
}

CBlockIndex *GetLastCheckpoint(const CCheckpointData &data)
{
    const MapCheckpoints &checkpoints = data.mapCheckpoints;

    BOOST_REVERSE_FOREACH (const MapCheckpoints::value_type &i, checkpoints)
    {
        const uint256 &hash = i.second;
        BlockMap::const_iterator t = pnetMan->getChainActive()->mapBlockIndex.find(hash);
        if (t != pnetMan->getChainActive()->mapBlockIndex.end())
            return t->second;
    }
    return NULL;
}

} // namespace Checkpoints
