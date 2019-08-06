// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OUTPOINT_H
#define OUTPOINT_H

#include "serialize.h"
#include "uint256.h"

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    uint32_t n;

    COutPoint() { SetNull(); }
    COutPoint(uint256 hashIn, uint32_t nIn)
    {
        hash = hashIn;
        n = nIn;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(hash);
        READWRITE(n);
    }

    void SetNull()
    {
        hash.SetNull();
        n = (uint32_t)-1;
    }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t)-1); }
    friend bool operator<(const COutPoint &a, const COutPoint &b)
    {
        return (a.hash < b.hash || (a.hash == b.hash && a.n < b.n));
    }

    friend bool operator==(const COutPoint &a, const COutPoint &b) { return (a.hash == b.hash && a.n == b.n); }
    friend bool operator!=(const COutPoint &a, const COutPoint &b) { return !(a == b); }
    std::string ToString() const;
};

#endif // OUTPOINT_H
