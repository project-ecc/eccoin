// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VERIFYDB_H
#define VERIFYDB_H

#include "coins.h"
#include "chain/chainparams.h"

/** RAII wrapper for VerifyDB: Verify consistency of the block and coin databases */
class CVerifyDB
{
public:
    CVerifyDB();
    ~CVerifyDB();
    bool VerifyDB(const CChainParams &chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth);
};

#endif // VERIFYDB_H
