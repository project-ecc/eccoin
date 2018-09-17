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

#ifndef BITCOIN_CHAIN_H
#define BITCOIN_CHAIN_H

#include "arith_uint256.h"
#include "block.h"
#include "blockindex.h"
#include "pow.h"
#include "tinyformat.h"
#include "uint256.h"

#include <vector>

/** An in-memory indexed chain of blocks. */
class CChain
{
private:
    std::vector<CBlockIndex *> vChain;

public:
    ~CChain() { vChain.clear(); }
    /** Returns the index entry for the genesis block of this chain, or NULL if none. */
    CBlockIndex *Genesis() const { return vChain.size() > 0 ? vChain[0] : NULL; }
    /** Returns the index entry for the tip of this chain, or NULL if none. */
    CBlockIndex *Tip() const { return vChain.size() > 0 ? vChain[vChain.size() - 1] : NULL; }
    CBlockIndex *AtHeight(int nHeight) const
    {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return NULL;
        return vChain[nHeight];
    }

    /** Returns the index entry at a particular height in this chain, or NULL if no such height exists. */
    CBlockIndex *operator[](int nHeight) const
    {
        if (nHeight < 0 || nHeight >= (int)vChain.size())
            return NULL;
        return vChain[nHeight];
    }

    /** Compare two chains efficiently. */
    friend bool operator==(const CChain &a, const CChain &b)
    {
        return a.vChain.size() == b.vChain.size() && a.vChain[a.vChain.size() - 1] == b.vChain[b.vChain.size() - 1];
    }

    /** Efficiently check whether a block is present in this chain. */
    bool Contains(const CBlockIndex *pindex) const { return (*this)[pindex->nHeight] == pindex; }
    /** Find the successor of a block in this chain, or NULL if the given index is not found or is the tip. */
    CBlockIndex *Next(const CBlockIndex *pindex) const
    {
        if (Contains(pindex))
            return (*this)[pindex->nHeight + 1];
        else
            return NULL;
    }

    /** Return the maximal height in the chain. Is equal to chain.Tip() ? chain.Tip()->nHeight : -1. */
    int Height() const { return vChain.size() - 1; }
    /** Set/initialize a chain with a given tip. */
    void SetTip(CBlockIndex *pindex);

    /** Return a CBlockLocator that refers to a block in this chain (by default the tip). */
    CBlockLocator GetLocator(const CBlockIndex *pindex = NULL) const;

    /** Find the last common block between this chain and a block index entry. */
    const CBlockIndex *FindFork(const CBlockIndex *pindex) const;
};

#endif // BITCOIN_CHAIN_H
