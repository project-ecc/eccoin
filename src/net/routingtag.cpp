// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "routingtag.h"

CNetTagStore::CNetTagStore() { SetNull(); }
CNetTagStore::CNetTagStore(const std::string &strRoutingFileIn)
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

bool CNetTagStore::AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
        return false;
    if (!fFileBacked)
        return true;
    {
        if (proutingdbEncryption)
            return proutingdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
        else
            return CRoutingTagDB(strRoutingFile).WriteCryptedKey(vchPubKey, vchCryptedSecret);
    }
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
            CKey secret;
            secret.MakeNewKey(false);
            CPubKey pubkey = secret.GetPubKey();
            assert(secret.VerifyPubKey(pubkey));
            if (!AddKeyPubKey(secret, pubkey))
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
        if (!HaveKey(keypool.vchPubKey.GetID()))
        {
            throw std::runtime_error("ReserveKeyFromKeyPool(): unknown key in key pool");
        }
        assert(keypool.vchPubKey.IsValid());
        LogPrint("net", "routing keypool reserve %d\n", nIndex);
        if (!proutingdbEncryption->WriteDefaultKey(keypool.vchPubKey))
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
bool CNetTagStore::LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
{
    return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
}

//! Adds a key to the store, without saving it to disk (used by LoadWallet)
bool CNetTagStore::LoadKey(const CKey &key, const CPubKey &pubkey)
{
    return CCryptoKeyStore::AddKeyPubKey(key, pubkey);
}
