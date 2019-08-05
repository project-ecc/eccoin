// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2018 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TXOUT_H
#define TXOUT_H

#include "amount.h"
#include "script/script.h"

const unsigned int DEFAULT_DUST_THRESHOLD = 546;

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut() { SetNull(); }
    CTxOut(const CAmount &nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nValue);
        READWRITE(*(CScriptBase *)(&scriptPubKey));
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const { return (nValue == -1); }
    void SetEmpty()
    {
        nValue = 0;
        scriptPubKey.clear();
    }

    bool IsEmpty() const { return (nValue == 0 && scriptPubKey.empty()); }
    uint256 GetHash() const;

    CAmount GetDustThreshold() const
    {
        if (scriptPubKey.IsUnspendable())
            return (CAmount)0;

        return (CAmount)DEFAULT_DUST_THRESHOLD;
    }

    bool IsDust() const { return (nValue < GetDustThreshold()); }
    friend bool operator==(const CTxOut &a, const CTxOut &b)
    {
        return (a.nValue == b.nValue && a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut &a, const CTxOut &b) { return !(a == b); }
    std::string ToString() const;
};

#endif // TXOUT_H
