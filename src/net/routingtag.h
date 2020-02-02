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

/// CRoutingTag does not extend CKey so that it may not be passed into a function that takes a ckey
class CRoutingTag
{
private:
    bool isPrivate;
    // tags are not compressed
    CPubKey vchPubKey;
    CPrivKey vchPrivKey;

public:
    CRoutingTag() { isPrivate = true; }
    CRoutingTag(bool _isPrivate, CPubKey _vchPubKey, CPrivKey _vchPrivKey)
    {
        isPrivate = _isPrivate;
        vchPubKey = _vchPubKey;
        vchPrivKey = _vchPrivKey;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(isPrivate);
        READWRITE(vchPubKey);
        READWRITE(vchPrivKey);
    }

    CPubKey GetPubKey() const;
    CPrivKey GetPrivKey() const;
    bool IsPrivate() const;
    void ConvertToPublicTag();
    void MakeNewKey();
    bool VerifyPubKey(const CPubKey &pubkey) const;
    bool CheckIfValid() const;
    bool Sign(const uint256 &hash, std::vector<unsigned char> &vchSig, uint32_t test_case = 0) const;
    bool SignCompact(const uint256 &hash, std::vector<unsigned char> &vchSig) const;
};

#endif // ECCOIN_ROUTINGTAG_H
