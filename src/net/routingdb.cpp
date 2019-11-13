// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "routingdb.h"

#include "args.h"
#include "base58.h"
#include "keystore.h"
#include "net/protocol.h"
#include "serialize.h"
#include "sync.h"
#include "util/util.h"
#include "util/utiltime.h"

#include <boost/filesystem.hpp>
#include <boost/scoped_ptr.hpp>

extern std::atomic<bool> shutdown_threads;

//
// CRoutingDB
//

bool CRoutingDB::WriteKey(const CPubKey &vchPubKey, const CPrivKey &vchPrivKey)
{
    // hash pubkey/privkey to accelerate wallet load
    std::vector<unsigned char> vchKey;
    vchKey.reserve(vchPubKey.size() + vchPrivKey.size());
    vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
    vchKey.insert(vchKey.end(), vchPrivKey.begin(), vchPrivKey.end());

    return Write(std::make_pair(std::string("key"), vchPubKey),
        std::make_pair(vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool CRoutingDB::WriteCryptedKey(const CPubKey &vchPubKey,
    const std::vector<unsigned char> &vchCryptedSecret)
{
    const bool fEraseUnencryptedKey = true;
    if (!Write(std::make_pair(std::string("ckey"), vchPubKey), vchCryptedSecret, false))
        return false;
    if (fEraseUnencryptedKey)
    {
        Erase(std::make_pair(std::string("key"), vchPubKey));
    }
    return true;
}

bool CRoutingDB::WriteMasterKey(unsigned int nID, const CMasterKey &kMasterKey)
{
    return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool CRoutingDB::WriteDefaultKey(const CPubKey &vchPubKey)
{
    return Write(std::string("defaultkey"), vchPubKey);
}

bool CRoutingDB::ReadPool(int64_t nPool, CKeyPoolEntry &keypool)
{
    return Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CRoutingDB::WritePool(int64_t nPool, const CKeyPoolEntry &keypool)
{
    return Write(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CRoutingDB::ErasePool(int64_t nPool)
{
    return Erase(std::make_pair(std::string("pool"), nPool));
}

class CWalletScanState
{
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    bool fIsEncrypted;
    std::vector<uint256> vWalletUpgrade;

    CWalletScanState()
    {
        nKeys = 0;
        nCKeys = 0;
        fIsEncrypted = false;
    }
};

bool ReadKeyValue(CNetKeyStore *pwallet,
    CDataStream &ssKey,
    CDataStream &ssValue,
    CWalletScanState &wss,
    std::string &strType,
    std::string &strErr)
{
    try
    {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        if (strType == "key")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            CKey key;
            CPrivKey pkey;
            uint256 hash;

            if (strType == "key")
            {
                wss.nKeys++;
                ssValue >> pkey;
            }

            // Old wallets store keys as "key" [pubkey] => [privkey]
            // ... which was slow for wallets with lots of keys, because the public key is re-derived from the private
            // key
            // using EC operations as a checksum.
            // Newer wallets store keys as "key"[pubkey] => [privkey][hash(pubkey,privkey)], which is much faster while
            // remaining backwards-compatible.
            try
            {
                ssValue >> hash;
            }
            catch (...)
            {
            }

            bool fSkipCheck = false;

            if (!hash.IsNull())
            {
                // hash pubkey/privkey to accelerate wallet load
                std::vector<unsigned char> vchKey;
                vchKey.reserve(vchPubKey.size() + pkey.size());
                vchKey.insert(vchKey.end(), vchPubKey.begin(), vchPubKey.end());
                vchKey.insert(vchKey.end(), pkey.begin(), pkey.end());

                if (Hash(vchKey.begin(), vchKey.end()) != hash)
                {
                    strErr = "Error reading wallet database: CPubKey/CPrivKey corrupt";
                    return false;
                }

                fSkipCheck = true;
            }

            if (!key.Load(pkey, vchPubKey, fSkipCheck))
            {
                strErr = "Error reading wallet database: CPrivKey corrupt";
                return false;
            }
            if (!pwallet->LoadKey(key, vchPubKey))
            {
                strErr = "Error reading wallet database: LoadKey failed";
                return false;
            }
        }
        else if (strType == "mkey")
        {
            unsigned int nID;
            ssKey >> nID;
            CMasterKey kMasterKey;
            ssValue >> kMasterKey;
            if (pwallet->mapMasterKeys.count(nID) != 0)
            {
                strErr = strprintf("Error reading wallet database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == "ckey")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading wallet database: CPubKey corrupt";
                return false;
            }
            std::vector<unsigned char> vchPrivKey;
            ssValue >> vchPrivKey;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedKey(vchPubKey, vchPrivKey))
            {
                strErr = "Error reading wallet database: LoadCryptedKey failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "defaultkey")
        {
            ssValue >> pwallet->vchDefaultKey;
        }
        else if (strType == "pool")
        {
            int64_t nIndex;
            ssKey >> nIndex;
            CKeyPoolEntry keypool;
            ssValue >> keypool;
            pwallet->setKeyPool.insert(nIndex);
        }
    }
    catch (...)
    {
        return false;
    }
    return true;
}

static bool IsKeyType(std::string strType)
{
    return (strType == "key" || strType == "mkey" || strType == "ckey");
}

bool CRoutingDB::LoadWallet(CNetKeyStore *pwallet)
{
    pwallet->vchDefaultKey = CPubKey();
    CWalletScanState wss;
    try
    {
        // Get cursor
        Dbc *pcursor = GetCursor();
        if (!pcursor)
        {
            LogPrintf("Error getting wallet database cursor\n");
            return false;
        }

        while (true)
        {
            // Read next record
            CDataStream ssKey(SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(SER_DISK, CLIENT_VERSION);
            int ret = ReadAtCursor(pcursor, ssKey, ssValue);
            if (ret == DB_NOTFOUND)
                break;
            else if (ret != 0)
            {
                LogPrintf("Error reading next record from routing key database\n");
                return false;
            }

            // Try to be tolerant of single corrupt records:
            std::string strType, strErr;
            if (!ReadKeyValue(pwallet, ssKey, ssValue, wss, strType, strErr))
            {
                // losing keys is considered a catastrophic error, anything else
                // we assume the user can live with:
                if (IsKeyType(strType))
                {
                    return false;
                }
            }
            if (!strErr.empty())
            {
                LogPrintf("%s\n", strErr);
            }
        }
        pcursor->close();
    }
    catch (const boost::thread_interrupted &)
    {
        throw;
    }
    catch (...)
    {
        return false;
    }
    LogPrintf("Keys: %u plaintext, %u encrypted, %u total\n", wss.nKeys, wss.nCKeys,
        wss.nKeys + wss.nCKeys);
    return true;
}

//
// Try to (very carefully!) recover wallet.dat if there is a problem.
//
bool CRoutingDB::Recover(CDBEnv &dbenv, const std::string &filename, bool fOnlyKeys)
{
    // Recovery procedure:
    // move wallet.dat to wallet.timestamp.bak
    // Call Salvage with fAggressive=true to
    // get as much data as possible.
    // Rewrite salvaged data to wallet.dat
    // Set -rescan so any missing transactions will be
    // found.
    int64_t now = GetTime();
    std::string newFilename = strprintf("routing.%d.bak", now);

    int result = dbenv.dbenv->dbrename(NULL, filename.c_str(), NULL, newFilename.c_str(), DB_AUTO_COMMIT);
    if (result == 0)
        LogPrintf("Renamed %s to %s\n", filename, newFilename);
    else
    {
        LogPrintf("Failed to rename %s to %s\n", filename, newFilename);
        return false;
    }

    std::vector<CDBEnv::KeyValPair> salvagedData;
    bool fSuccess = dbenv.Salvage(newFilename, true, salvagedData);
    if (salvagedData.empty())
    {
        LogPrintf("Salvage(aggressive) found no records in %s.\n", newFilename);
        return false;
    }
    LogPrintf("Salvage(aggressive) found %u records\n", salvagedData.size());

    boost::scoped_ptr<Db> pdbCopy(new Db(dbenv.dbenv, 0));
    int ret = pdbCopy->open(NULL, // Txn pointer
        filename.c_str(), // Filename
        "main", // Logical db name
        DB_BTREE, // Database type
        DB_CREATE, // Flags
        0);
    if (ret > 0)
    {
        LogPrintf("Cannot create database file %s\n", filename);
        return false;
    }
    CNetKeyStore dummyWallet;
    CWalletScanState wss;

    DbTxn *ptxn = dbenv.TxnBegin();
    for (auto &row : salvagedData)
    {
        if (fOnlyKeys)
        {
            CDataStream ssKey(row.first, SER_DISK, CLIENT_VERSION);
            CDataStream ssValue(row.second, SER_DISK, CLIENT_VERSION);
            std::string strType, strErr;
            bool fReadOK;
            {
                // Required in LoadKeyMetadata():
                fReadOK = ReadKeyValue(&dummyWallet, ssKey, ssValue, wss, strType, strErr);
            }
            if (!IsKeyType(strType))
                continue;
            if (!fReadOK)
            {
                LogPrintf("WARNING: CWalletDB::Recover skipping %s: %s\n", strType, strErr);
                continue;
            }
        }
        Dbt datKey(&row.first[0], row.first.size());
        Dbt datValue(&row.second[0], row.second.size());
        int ret2 = pdbCopy->put(ptxn, &datKey, &datValue, DB_NOOVERWRITE);
        if (ret2 > 0)
            fSuccess = false;
    }
    ptxn->commit(0);
    pdbCopy->close(0);

    return fSuccess;
}

bool CRoutingDB::Recover(CDBEnv &dbenv, const std::string &filename)
{
    return CRoutingDB::Recover(dbenv, filename, false);
}
