// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_TAGSTORE_H
#define ECCOIN_TAGSTORE_H

#include "routingtag.h"
#include "tagdb.h"

#include <atomic>
#include <set>

// CKeyID here is the hash of the tags pubkey
typedef std::map<CKeyID, CRoutingTag> TagMap;

typedef std::vector<unsigned char, secure_allocator<unsigned char> > CKeyingMaterial;

class CNetTagStore
{
public:
    mutable CCriticalSection cs_TagStore;

    /// mapTags holds either crypted or non crypted tags, depending on fUseCrypto
    TagMap mapTags;
    CKeyingMaterial vMasterKey;

    //! if fUseCrypto is true, mapKeys must be empty
    //! if fUseCrypto is false, vMasterKey must be empty
    std::atomic<bool> fUseCrypto;

    //! keeps track of whether Unlock has run a thorough check before
    std::atomic<bool> fDecryptionThoroughlyChecked;

    ////// net tag store
    bool fFileBacked;
    std::string strRoutingFile;
    std::set<int64_t> setKeyPool;
    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;
    CRoutingTag publicRoutingTag;

private:
    CRoutingTagDB *proutingdbEncryption;

protected:
    bool SetCrypted();

    //! will encrypt previously unencrypted keys
    bool EncryptKeys(CKeyingMaterial &vMasterKeyIn);

    bool Unlock(const CKeyingMaterial &vMasterKeyIn);

    bool AddCryptedTagToTagMap(const CRoutingTag &tag);

    bool AddTagToTagMap(const CRoutingTag &tag);

public:
    CNetTagStore();
    CNetTagStore(const std::string &strRoutingFileIn);
    ~CNetTagStore();
    void SetNull();

    bool IsCrypted() const;
    bool IsLocked() const;
    bool Lock();
    bool HaveTag(const CKeyID &address) const;
    bool GetTag(const CKeyID &address, CRoutingTag &tagOut) const;
    bool GetTagPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const;
    void GetTagIds(std::set<CKeyID> &setAddress) const;
    bool AddCryptedTag(const CRoutingTag &tag);
    bool Load();
    CPubKey GetCurrentPublicTagPubKey();
    bool LoadCryptedTag(const CRoutingTag &tag);
    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadTag(const CRoutingTag &tag);
};

#endif // ECCOIN_TAGSTORE_H
