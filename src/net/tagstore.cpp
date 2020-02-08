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

static bool DecryptTag(const CKeyingMaterial &vMasterKey, const CRoutingTag &tagIn, CRoutingTag &tagOut)
{
    CKeyingMaterial vchSecret;
    if (!DecryptSecret(vMasterKey, tagIn.GetPrivKey(), tagIn.GetPubKey().GetHash(), vchSecret))
        return false;

    if (vchSecret.size() != 32)
        return false;

    tagOut = CRoutingTag(tagIn.IsPrivate(), tagIn.GetPubKey(), vchSecret);
    // TODO : we probably dont need to verify the pubkey here
    return tagOut.VerifyPubKey(tagIn.GetPubKey());
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
            CPubKey vchPubKey = tag.GetPubKey();
            const CPrivKey tagprivkey = tag.GetPrivKey();
            CKeyingMaterial vchSecret(tagprivkey.begin(), tagprivkey.end());
            CCryptedPrivKey vchCryptedSecret;
            if (!EncryptSecret(vMasterKeyIn, vchSecret, vchPubKey.GetHash(), vchCryptedSecret))
                return false;
            CRoutingTag cryptedTag(tag.IsPrivate(), tag.GetPubKey(), vchCryptedSecret);
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
            const CRoutingTag tagIn = (*mi).second;
            CRoutingTag tagOut;
            if (!DecryptTag(vMasterKeyIn, tagIn, tagOut))
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
    mapTags[tag.GetPubKey().GetID()] = tag;
    return true;
}

bool CNetTagStore::AddTagToTagMap(const CRoutingTag &tag)
{
    {
        LOCK(cs_TagStore);
        if (!IsCrypted())
        {
            mapTags[tag.GetPubKey().GetID()] = tag;
            return true;
        }

        if (IsLocked())
            return false;

        CCryptedPrivKey vchCryptedSecret;
        CPrivKey tagprivkey = tag.GetPrivKey();
        CKeyingMaterial vchSecret(tagprivkey.begin(), tagprivkey.end());
        if (!EncryptSecret(vMasterKey, vchSecret, tag.GetPubKey().GetHash(), vchCryptedSecret))
            return false;

        CRoutingTag cryptedTag(tag.IsPrivate(), tag.GetPubKey(), vchCryptedSecret);
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
            const CRoutingTag tagIn = (*mi).second;
            return DecryptTag(vMasterKey, tagIn, tagOut);
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
        vchPubKeyOut = (*mi).second.GetPubKey();
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
            tag.MakeNewKey();
            CPubKey pubkey = tag.GetPubKey();
            assert(tag.VerifyPubKey(pubkey));
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
    if (!proutingdbEncryption->ReadLastUsedPublicTag(publicRoutingTag))
    {
        // assign new public routing tag from pool
        int64_t nIndex = -1;
        nIndex = *(setKeyPool.begin());
        CKeyPoolEntry keypool;
        if (!proutingdbEncryption->ReadPool(nIndex, keypool))
            throw std::runtime_error("ReserveKeyFromKeyPool(): read failed");
        if (!HaveTag(keypool.vchPubKey.GetID()))
            throw std::runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        assert(keypool.vchPubKey.IsValid());
        assert(GetTag(keypool.vchPubKey.GetID(), publicRoutingTag));
        proutingdbEncryption->WriteLastUsedPublicTag(publicRoutingTag);
    }
    return true;
}

CPubKey CNetTagStore::GetCurrentPublicTagPubKey() { return publicRoutingTag.GetPubKey(); }
bool CNetTagStore::LoadCryptedTag(const CRoutingTag &tag) { return AddCryptedTagToTagMap(tag); }
bool CNetTagStore::LoadTag(const CRoutingTag &tag) { return AddTagToTagMap(tag); }
