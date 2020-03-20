// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_KEYPOOLENTRY_H
#define ECCOIN_KEYPOOLENTRY_H

#include "pubkey.h"
#include "serialize.h"

/** A key pool entry */
class CKeyPoolEntry
{
public:
    int64_t nTime;
    CPubKey vchPubKey;

    CKeyPoolEntry();
    CKeyPoolEntry(const CPubKey &vchPubKeyIn);

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        int nVersion = s.GetVersion();
        if (!(s.GetType() & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(nTime);
        READWRITE(vchPubKey);
    }
};

#endif
