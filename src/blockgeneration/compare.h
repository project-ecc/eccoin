// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_COMPARE_H
#define ECCOIN_COMPARE_H

#include "chain/tx.h"
#include "txmempool.h"
#include "util/util.h"

#include <set>

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction *ptx;
    std::set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction *ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        LogPrintf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n", ptx->GetHash().ToString().substr(0, 10).c_str(),
            dPriority, dFeePerKb);
        for (auto hash : setDependsOn)
            LogPrintf("   setDependsOn %s\n", hash.ToString().substr(0, 10).c_str());
    }
};

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction *> TxPriority;
class TxPriorityCompare
{
    bool byFee;

public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) {}
    bool operator()(const TxPriority &a, const TxPriority &b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

class ScoreCompare
{
public:
    ScoreCompare() {}
    bool operator()(const CTxMemPool::txiter a, const CTxMemPool::txiter b)
    {
        return CompareTxMemPoolEntryByScore()(*b, *a); // Convert to less than
    }
};

#endif // ECCOIN_COMPARE_H
