// This file is part of the Eccoin project
// Copyright (c) 2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_ROUTINGTAG_H
#define ECCOIN_ROUTINGTAG_H

#include "key.h"
#include "pubkey.h"

/// CRoutingTag is its own class instead of a pair holding isPrivate and a CKey
/// or something similar to allow the addition of more data in the future if
/// needed without needing to restructure a lot of the code around it.
class CRoutingTag
{
public:
    // memory and disk
    bool isPrivate;
    CPubKey vchPubKey;
    CPrivKey vchPrivKey;

    // memory only
    // this make the privkey redundant but makes calling ckey members a lot easier
    CKey key;

    CRoutingTag() : key() { isPrivate = true; }
    CRoutingTag(const CKey &_key) : key(_key)
    {
        isPrivate = true;
        vchPubKey = key.GetPubKey();
        vchPrivKey = key.GetPrivKey();
    }

    CRoutingTag(CKey &_key) : key(_key)
    {
        isPrivate = true;
        vchPubKey = key.GetPubKey();
        vchPrivKey = key.GetPrivKey();
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(isPrivate);
        READWRITE(vchPubKey);
        READWRITE(vchPrivKey);
    }

    void MakeNewKey(bool fCompressed)
    {
        key.MakeNewKey(fCompressed);
        vchPubKey = key.GetPubKey();
        vchPrivKey = key.GetPrivKey();
    }
};

#endif // ECCOIN_ROUTINGTAG_H
