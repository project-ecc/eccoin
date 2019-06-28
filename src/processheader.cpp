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

#include "processheader.h"
#include "init.h"
#include "main.h"
#include "timedata.h"
#include "util/util.h"


bool AcceptBlockHeader(const CBlockHeader &block,
    CValidationState &state,
    const CNetworkTemplate &chainparams,
    CBlockIndex **ppindex)
{
    AssertLockHeld(cs_main);
    AssertRecursiveWriteLockHeld(pnetMan->getChainActive()->cs_mapBlockIndex);
    // Check for duplicate
    uint256 hash = block.GetHash();
    CBlockIndex *pindex = pnetMan->getChainActive()->LookupBlockIndex(hash);
    if (hash != chainparams.GetConsensus().hashGenesisBlock)
    {
        if (pindex)
        {
            // Block header is already known.
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block is marked invalid", __func__), 0, "duplicate");
            return true;
        }

        if (!CheckBlockHeader(block, state))
            return false;

        // Get prev block index
        CBlockIndex *pindexPrev = pnetMan->getChainActive()->LookupBlockIndex(block.hashPrevBlock);
        if (!pindexPrev)
        {
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "bad-prevblk");
        }
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");

        assert(pindexPrev);
        if (fCheckpointsEnabled && !CheckIndexAgainstCheckpoint(pindexPrev, state, chainparams, hash))
            return error("%s: CheckIndexAgainstCheckpoint(): %s", __func__, state.GetRejectReason().c_str());

        if (!ContextualCheckBlockHeader(block, state, pindexPrev))
            return false;
    }
    if (pindex == nullptr)
    {
        pindex = pnetMan->getChainActive()->AddToBlockIndex(block);
    }

    if (ppindex)
    {
        *ppindex = pindex;
    }

    return true;
}


bool CheckBlockHeader(const CBlockHeader &block, CValidationState &state, bool fCheckPOW)
{
    // Check timestamp
    if (block.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(
            error("CheckBlockHeader(): block timestamp too far in the future"), REJECT_INVALID, "time-too-new");

    return true;
}


bool ContextualCheckBlockHeader(const CBlockHeader &block, CValidationState &state, CBlockIndex *const pindexPrev)
{
    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(error("%s: block's timestamp is too early", __func__), REJECT_INVALID, "time-too-old");

    return true;
}
