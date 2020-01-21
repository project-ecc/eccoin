// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tagstore.h"
#include "crypter.h"

static bool EncryptSecret(const CKeyingMaterial &vMasterKey,
    const CKeyingMaterial &vchPlaintext,
    const uint256 &nIV,
    CCryptedPrivKey &vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_KEY_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_KEY_SIZE);
    if (!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt(*((const CKeyingMaterial *)&vchPlaintext), vchCiphertext);
}

static bool DecryptSecret(const CKeyingMaterial &vMasterKey,
    const CCryptedPrivKey &vchCiphertext,
    const uint256 &nIV,
    CKeyingMaterial &vchPlaintext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_KEY_SIZE);
    memcpy(&chIV[0], &nIV, WALLET_CRYPTO_KEY_SIZE);
    if (!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Decrypt(vchCiphertext, *((CKeyingMaterial *)&vchPlaintext));
}

static bool DecryptKey(const CKeyingMaterial &vMasterKey,
    const CCryptedPrivKey &vchCryptedSecret,
    const CPubKey &vchPubKey,
    CRoutingTag &tag)
{
    CKeyingMaterial vchSecret;
    if (!DecryptSecret(vMasterKey, vchCryptedSecret, vchPubKey.GetHash(), vchSecret))
        return false;

    if (vchSecret.size() != 32)
        return false;

    tag.key.Set(vchSecret.begin(), vchSecret.end(), vchPubKey.IsCompressed());
    tag.vchPubKey = vchPubKey;
    tag.vchPrivKey = vchSecret;
    return tag.key.VerifyPubKey(vchPubKey);
}

///////////////////////////////////////////////////

bool CNetTagStore::SetCrypted()
{
    LOCK(cs_TagStore);
    if (fUseCrypto)
        return true;
    if (!mapTags.empty())
        return false;
    fUseCrypto = true;
    return true;
}

//! will encrypt previously unencrypted keys
bool CNetTagStore::EncryptKeys(CKeyingMaterial &vMasterKeyIn)
{
    {
        LOCK(cs_TagStore);
        if (IsCrypted())
            return false;

        fUseCrypto = true;
        for (auto &mTag : mapTags)
        {
            const CRoutingTag &tag = mTag.second;
            CPubKey vchPubKey = tag.vchPubKey;
            CKeyingMaterial vchSecret(tag.vchPrivKey.begin(), tag.vchPrivKey.end());
            CCryptedPrivKey vchCryptedSecret;
            if (!EncryptSecret(vMasterKeyIn, vchSecret, vchPubKey.GetHash(), vchCryptedSecret))
                return false;
            CRoutingTag cryptedTag;
            cryptedTag.isPrivate = tag.isPrivate;
            cryptedTag.vchPubKey = tag.vchPubKey;
            cryptedTag.vchPrivKey = vchCryptedSecret;
            if (!AddCryptedTagToTagMap(cryptedTag))
                return false;
        }
        mapTags.clear();
    }
    return true;
}

bool CNetTagStore::Unlock(const CKeyingMaterial &vMasterKeyIn)
{
    {
        LOCK(cs_TagStore);
        if (!SetCrypted())
            return false;

        bool keyPass = false;
        bool keyFail = false;
        TagMap::const_iterator mi = mapTags.begin();
        for (; mi != mapTags.end(); ++mi)
        {
            const CPubKey &vchPubKey = (*mi).second.vchPubKey;
            const CCryptedPrivKey &vchCryptedSecret = (*mi).second.vchPrivKey;
            CRoutingTag tag;
            if (!DecryptKey(vMasterKeyIn, vchCryptedSecret, vchPubKey, tag))
            {
                keyFail = true;
                break;
            }
            keyPass = true;
            if (fDecryptionThoroughlyChecked)
                break;
        }
        if (keyPass && keyFail)
        {
            LogPrintf("The routing tag db is probably corrupted: Some keys decrypt but not all.\n");
            assert(false);
        }
        if (keyFail || !keyPass)
            return false;
        vMasterKey = vMasterKeyIn;
        fDecryptionThoroughlyChecked = true;
    }
    return true;
}

bool CNetTagStore::AddCryptedTagToTagMap(const CRoutingTag &tag)
{
    LOCK(cs_TagStore);
    if (!SetCrypted())
    {
        return false;
    }
    mapTags[tag.vchPubKey.GetID()] = tag;
    return true;
}

bool CNetTagStore::AddTagToTagMap(const CRoutingTag &tag)
{
    {
        LOCK(cs_TagStore);
        if (!IsCrypted())
        {
            mapTags[tag.vchPubKey.GetID()] = tag;
            return true;
        }

        if (IsLocked())
            return false;

        CCryptedPrivKey vchCryptedSecret;
        CKeyingMaterial vchSecret(tag.vchPrivKey.begin(), tag.vchPrivKey.end());
        if (!EncryptSecret(vMasterKey, vchSecret, tag.vchPubKey.GetHash(), vchCryptedSecret))
            return false;

        CRoutingTag cryptedTag;
        cryptedTag.isPrivate = tag.isPrivate;
        cryptedTag.vchPubKey = tag.vchPubKey;
        cryptedTag.vchPrivKey = vchCryptedSecret;
        if (!AddCryptedTagToTagMap(cryptedTag))
            return false;
    }
    return true;
}

CNetTagStore::CNetTagStore() : fUseCrypto(false), fDecryptionThoroughlyChecked(false) { SetNull(); }
CNetTagStore::CNetTagStore(const std::string &strRoutingFileIn) : fUseCrypto(false), fDecryptionThoroughlyChecked(false)
{
    SetNull();
    strRoutingFile = strRoutingFileIn;
    fFileBacked = true;
}

CNetTagStore::~CNetTagStore()
{
    delete proutingdbEncryption;
    proutingdbEncryption = nullptr;
}

void CNetTagStore::SetNull()
{
    fFileBacked = false;
    nMasterKeyMaxID = 0;
    proutingdbEncryption = nullptr;
}

bool CNetTagStore::IsCrypted() const { return fUseCrypto.load(); }
bool CNetTagStore::IsLocked() const
{
    if (!IsCrypted())
    {
        return false;
    }
    bool result;
    {
        LOCK(cs_TagStore);
        result = vMasterKey.empty();
    }
    return result;
}

bool CNetTagStore::Lock()
{
    if (!SetCrypted())
    {
        return false;
    }
    {
        LOCK(cs_TagStore);
        vMasterKey.clear();
    }
    return true;
}

bool CNetTagStore::HaveTag(const CKeyID &address) const
{
    LOCK(cs_TagStore);
    return mapTags.count(address) > 0;
}

bool CNetTagStore::GetTag(const CKeyID &address, CRoutingTag &tagOut) const
{
    LOCK(cs_TagStore);
    if (!IsCrypted())
    {
        TagMap::const_iterator mi = mapTags.find(address);
        if (mi != mapTags.end())
        {
            tagOut = mi->second;
            return true;
        }
    }
    else
    {
        TagMap::const_iterator mi = mapTags.find(address);
        if (mi != mapTags.end())
        {
            const CPubKey &vchPubKey = (*mi).second.vchPubKey;
            const CCryptedPrivKey &vchCryptedSecret = (*mi).second.vchPrivKey;
            return DecryptKey(vMasterKey, vchCryptedSecret, vchPubKey, tagOut);
        }
    }
    return false;
}
bool CNetTagStore::GetTagPubKey(const CKeyID &address, CPubKey &vchPubKeyOut) const
{
    LOCK(cs_TagStore);
    TagMap::const_iterator mi = mapTags.find(address);
    if (mi != mapTags.end())
    {
        vchPubKeyOut = (*mi).second.vchPubKey;
        return true;
    }
    return false;
}
void CNetTagStore::GetTagIds(std::set<CKeyID> &setAddress) const
{
    LOCK(cs_TagStore);
    setAddress.clear();
    TagMap::const_iterator mi = mapTags.begin();
    while (mi != mapTags.end())
    {
        setAddress.insert((*mi).first);
        mi++;
    }
}

bool CNetTagStore::AddCryptedTag(const CRoutingTag &tag)
{
    if (!AddCryptedTagToTagMap(tag))
        return false;
    if (!fFileBacked)
        return true;
    if (proutingdbEncryption)
        return proutingdbEncryption->WriteCryptedTag(tag);
    else
        return CRoutingTagDB(strRoutingFile).WriteCryptedTag(tag);
    return false;
}

bool CNetTagStore::Load()
{
    proutingdbEncryption = new CRoutingTagDB(strRoutingFile, "cr+");
    assert(proutingdbEncryption != nullptr);
    CKeyPoolEntry keypool;

    bool nLoadWalletRet = proutingdbEncryption->LoadTags(this);
    assert(nLoadWalletRet == true);

    if (setKeyPool.empty())
    {
        // TODO make this more than just 1 key
        while (setKeyPool.size() < (1 + 1))
        {
            int64_t nEnd = 1;
            if (!setKeyPool.empty())
            {
                nEnd = *(--setKeyPool.end()) + 1;
            }
            CRoutingTag tag;
            tag.MakeNewKey(false);
            CPubKey pubkey = tag.vchPubKey;
            assert(tag.key.VerifyPubKey(pubkey));
            if (!AddTagToTagMap(tag))
            {
                throw std::runtime_error("CWallet::GenerateNewKey(): AddKey failed");
            }
            if (!proutingdbEncryption->WritePool(nEnd, CKeyPoolEntry(pubkey)))
            {
                throw std::runtime_error("Connman::Start(): writing generated key failed");
            }
            setKeyPool.insert(nEnd);
            LogPrint("net", "keypool added key %d, size=%u\n", nEnd, setKeyPool.size());
        }
    }
    // Get the oldest key
    assert(setKeyPool.empty() == false);
    if (vchDefaultKey == CPubKey())
    {
        int64_t nIndex = -1;
        keypool.vchPubKey = CPubKey();
        nIndex = *(setKeyPool.begin());
        if (!proutingdbEncryption->ReadPool(nIndex, keypool))
        {
            throw std::runtime_error("ReserveKeyFromKeyPool(): read failed");
        }
        if (!HaveTag(keypool.vchPubKey.GetID()))
        {
            throw std::runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        }
        assert(keypool.vchPubKey.IsValid());
        LogPrint("net", "routing keypool reserve %d\n", nIndex);
        if (!proutingdbEncryption->WriteDefaultTag(keypool.vchPubKey))
        {
            assert(false);
        }
    }
    publicRoutingTag = vchDefaultKey;
    assert(vchDefaultKey != CPubKey());
    assert(publicRoutingTag != CPubKey());
    assert(publicRoutingTag == vchDefaultKey);
    return true;
}

CPubKey CNetTagStore::GetCurrentPublicTag() { return publicRoutingTag; }
bool CNetTagStore::LoadCryptedTag(const CRoutingTag &tag) { return AddCryptedTagToTagMap(tag); }
bool CNetTagStore::LoadTag(const CRoutingTag &tag) { return AddTagToTagMap(tag); }
