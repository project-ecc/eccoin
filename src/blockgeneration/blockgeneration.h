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

#include "chain/chain.h"
#include "consensus/params.h"
#include "wallet/wallet.h"

#include <boost/thread.hpp>

#ifndef ECCOIN_BLOCKGENERATION_H
#define ECCOIN_BLOCKGENERATION_H

static const bool DEFAULT_GENERATE = false;
static const bool DEFAULT_PRINTPRIORITY = false;

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

void IncrementExtraNonce(CBlock *pblock, CBlockIndex *pindexPrev, unsigned int &nExtraNonce);

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev);

std::unique_ptr<CBlockTemplate> CreateNewBlock(CWallet *pwallet, const CScript &scriptPubKeyIn, bool fProofOfStake);

void ThreadGeneration(void *parg, bool shutdownOnly = false, bool fProofOfStake = false);

extern boost::thread_group *minerThreads;
extern boost::thread_group *minterThreads;

#endif // ECCOIN_BLOCKGENERATION_H
