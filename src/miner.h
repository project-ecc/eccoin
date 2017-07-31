// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2013 The NovaCoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef NOVACOIN_MINER_H
#define NOVACOIN_MINER_H

#include "main.h"
#include "wallet/wallet.h"

extern int64_t nLastCoinStakeSearchInterval;

static const bool DEFAULT_GENERATE = false;
static const int DEFAULT_GENERATE_THREADS = 1;

static const bool DEFAULT_PRINTPRIORITY = false;


/** Check mined proof-of-stake block */
bool CheckStake(CBlock* pblock, CWallet& wallet);

/** Base sha256 mining transform */
void SHA256Transform(void* pstate, void* pinput, const void* pinit);

void ScryptMiner(CWallet *pwallet);

void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
void FormatHashBuffers(CBlock* pblock, char* pmidstate, char* pdata, char* phash1);
bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey);

void ThreadScryptMiner(void* parg);

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOps;
};

CBlockTemplate* CreateNewBlock(CWallet* pwallet, bool fProofOfStake=false);

#endif // NOVACOIN_MINER_H
