// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_MINER_H
#define ECCOIN_MINER_H

#include "blockgeneration.h"
#include "compare.h"
#include "main.h"
#include "wallet/wallet.h"

extern double dHashesPerSec;
extern int64_t nHPSTimerStart;

std::unique_ptr<CBlockTemplate> CreateNewPoWBlock(CWallet *pwallet, const CScript &scriptPubKeyIn);

void EccMiner(CWallet *pwallet);

#endif // ECCOIN_MINER_H
