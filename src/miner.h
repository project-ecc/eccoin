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

#ifndef NOVACOIN_MINER_H
#define NOVACOIN_MINER_H

#include "main.h"
#include "wallet/wallet.h"

extern int64_t nLastCoinStakeSearchInterval;

static const bool DEFAULT_GENERATE = false;
static const bool DEFAULT_PRINTPRIORITY = false;


/** Base sha256 mining transform */
void SHA256Transform(void *pstate, void *pinput, const void *pinit);

void IncrementExtraNonce(CBlock *pblock, CBlockIndex *pindexPrev, unsigned int &nExtraNonce);
void FormatHashBuffers(CBlock *pblock, char *pmidstate, char *pdata, char *phash1);
bool CheckWork(const std::shared_ptr<const CBlock> pblock, CWallet &wallet, CReserveKey &reservekey);

int64_t UpdateTime(CBlockHeader *pblock, const Consensus::Params &consensusParams, const CBlockIndex *pindexPrev);

/** Check mined proof-of-stake block */
bool CheckStake(CBlock *pblock, CWallet &wallet);

void ThreadMiner(void *parg, bool shutdownOnly = false);

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

std::unique_ptr<CBlockTemplate> CreateNewBlock(CWallet *pwallet, bool fProofOfStake);

extern boost::thread_group *minerThreads;

#endif // NOVACOIN_MINER_H
