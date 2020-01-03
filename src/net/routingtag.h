// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_ROUTINGTAG_H
#define ECCOIN_ROUTINGTAG_H

#include "tagdb.h"

class CNetTagStore : public CCryptoKeyStore
{
public:
    bool fFileBacked;
    std::string strRoutingFile;
    std::set<int64_t> setKeyPool;
    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;
    CPubKey vchDefaultKey;
    CPubKey publicRoutingTag;

private:
    CRoutingTagDB *proutingdbEncryption;


public:
    CNetTagStore();
    CNetTagStore(const std::string &strRoutingFileIn);
    ~CNetTagStore();
    void SetNull();
    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    bool Load();
    CPubKey GetCurrentPublicTag();
    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey &key, const CPubKey &pubkey);
};

#endif // ECCOIN_ROUTINGTAG_H
