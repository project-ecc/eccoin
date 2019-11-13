// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_ROUTINGDB_H
#define ECCOIN_ROUTINGDB_H

#include "amount.h"
#include "key.h"
#include "keypoolentry.h"
#include "keystore.h"
#include "wallet/db.h"
#include "wallet/crypter.h"

#include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class CKeyPoolEntry;
class CMasterKey;
class uint160;
class uint256;
class CNetKeyStore;

/** Access to the routing database (routing.dat) */
class CRoutingDB : public CDB
{
public:
    CRoutingDB(const std::string &strFilename, const char *pszMode = "r+", bool fFlushOnCloseIn = true)
        : CDB(strFilename, pszMode, fFlushOnCloseIn)
    {
    }

    bool WriteKey(const CPubKey &vchPubKey, const CPrivKey &vchPrivKey);
    bool WriteCryptedKey(const CPubKey &vchPubKey,
        const std::vector<unsigned char> &vchCryptedSecret);
    bool WriteMasterKey(unsigned int nID, const CMasterKey &kMasterKey);
    bool WriteDefaultKey(const CPubKey &vchPubKey);

    bool ReadPool(int64_t nPool, CKeyPoolEntry &keypool);
    bool WritePool(int64_t nPool, const CKeyPoolEntry &keypool);
    bool ErasePool(int64_t nPool);

    bool LoadWallet(CNetKeyStore* pwallet);
    static bool Recover(CDBEnv &dbenv, const std::string &filename, bool fOnlyKeys);
    static bool Recover(CDBEnv &dbenv, const std::string &filename);

private:
    CRoutingDB(const CRoutingDB &);
    void operator=(const CRoutingDB &);
};

class CNetKeyStore : public CCryptoKeyStore
{
public:
    bool fFileBacked;
    std::string strRoutingFile;
    std::set<int64_t> setKeyPool;
    typedef std::map<unsigned int, CMasterKey> MasterKeyMap;
    MasterKeyMap mapMasterKeys;
    unsigned int nMasterKeyMaxID;
    CPubKey vchDefaultKey;
    CPubKey publicRoutingId;

private:
    CRoutingDB *proutingdbEncryption;



public:

    CNetKeyStore() { SetNull(); }
    CNetKeyStore(const std::string &strRoutingFileIn)
    {
        SetNull();
        strRoutingFile = strRoutingFileIn;
        fFileBacked = true;
    }

    ~CNetKeyStore()
    {
        delete proutingdbEncryption;
        proutingdbEncryption = nullptr;
    }

    void SetNull()
    {
        fFileBacked = false;
        nMasterKeyMaxID = 0;
        proutingdbEncryption = nullptr;
    }

    bool AddCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
    {
        if (!CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret))
            return false;
        if (!fFileBacked)
            return true;
        {
            if (proutingdbEncryption)
                return proutingdbEncryption->WriteCryptedKey(vchPubKey, vchCryptedSecret);
            else
                return CRoutingDB(strRoutingFile)
                    .WriteCryptedKey(vchPubKey, vchCryptedSecret);
        }
        return false;
    }

    bool Load()
    {
        proutingdbEncryption = new CRoutingDB(strRoutingFile, "cr+");
        assert(proutingdbEncryption != nullptr);
        CKeyPoolEntry keypool;

        bool nLoadWalletRet = proutingdbEncryption->LoadWallet(this);
        assert (nLoadWalletRet == true);

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
        publicRoutingId = vchDefaultKey;
        assert(vchDefaultKey != CPubKey());
        assert(publicRoutingId != CPubKey());
        assert(publicRoutingId == vchDefaultKey);
        return true;
    }

    CPubKey GetPublicRoutingId()
    {
        return publicRoutingId;
    }

    bool LoadCryptedKey(const CPubKey &vchPubKey, const std::vector<unsigned char> &vchCryptedSecret)
    {
        return CCryptoKeyStore::AddCryptedKey(vchPubKey, vchCryptedSecret);
    }

    //! Adds a key to the store, without saving it to disk (used by LoadWallet)
    bool LoadKey(const CKey &key, const CPubKey &pubkey) { return CCryptoKeyStore::AddKeyPubKey(key, pubkey); }
};

#endif // ECCOIN_ROUTINGDB_H
