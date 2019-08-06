// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include "arith_uint256.h"
#include "block.h"
#include "blockindex.h"
#include "pow.h"
#include "tinyformat.h"
#include "uint256.h"

#include <atomic>
#include <vector>

/** An in-memory indexed chain of blocks. */
class CChain
{
private:
    std::vector<CBlockIndex *> vChain;

    std::atomic<CBlockIndex *> tip;

public:
    CChain() : tip(nullptr) {}
    ~CChain()
    {
        vChain.clear();
        tip = nullptr;
    }
    /** Returns the index entry for the genesis block of this chain, or NULL if none. */
    CBlockIndex *Genesis() const { return vChain.size() > 0 ? vChain[0] : nullptr; }
    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex *Tip() const { return tip; }
    CBlockIndex *AtHeight(int nHeight) const
    {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return nullptr;
        return vChain[nHeight];
    }

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex *operator[](int nHeight) const
    {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return nullptr;
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b)
    {
        return a.vChain.size() == b.vChain.size() && a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    void operator=(const CChain &a)
    {
        vChain = a.vChain;
        tip.store(a.tip.load());
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const { return (*this)[pindex->nHeight] == pindex; }
    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const
    {
        if (Contains(pindex))
            return (*this)[pindex->nHeight + 1];
        else
            return nullptr;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const { return tip.load() ? tip.load()->nHeight : -1; }
    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator GetLocator(const CBlockIndex *pindex = nullptr) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;
};

#endif // BITCOIN_CHAIN_H
