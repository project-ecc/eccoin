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
