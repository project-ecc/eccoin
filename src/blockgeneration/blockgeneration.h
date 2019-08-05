// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chain/chain.h"
#include "consensus/params.h"
#include "wallet/wallet.h"

#ifndef ECCOIN_BLOCKGENERATION_H
#define ECCOIN_BLOCKGENERATION_H

static const bool DEFAULT_GENERATE = false;
static const bool DEFAULT_PRINTPRIORITY = false;
static const uint64_t DEFAULT_MIN_BLOCK_GEN_PEERS = 4;

extern std::atomic<bool> shutdown_miner_threads;
extern std::atomic<bool> shutdown_minter_threads;

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

extern thread_group *minerThreads;
extern thread_group *minterThreads;

#endif // ECCOIN_BLOCKGENERATION_H
