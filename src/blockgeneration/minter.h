// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_MINTER_H
#define ECCOIN_MINTER_H

#include "blockgeneration.h"
#include "chain/chain.h"
#include "compare.h"
#include "wallet/wallet.h"

#include <memory>

std::unique_ptr<CBlockTemplate> CreateNewPoSBlock(CWallet *pwallet, const CScript &scriptPubKeyIn);

void EccMinter(CWallet *pwallet);

#endif // ECCOIN_MINTER_H
