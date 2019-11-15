// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "tagdb.h"

#include "args.h"
#include "base58.h"
#include "keystore.h"
#include "net/protocol.h"
#include "serialize.h"
#include "sync.h"
#include "tagstore.h"
#include "util/util.h"
#include "util/utiltime.h"

#include <boost/filesystem.hpp>
#include <boost/scoped_ptr.hpp>

class CTagDBState
{
public:
    unsigned int nKeys;
    unsigned int nCKeys;
    bool fIsEncrypted;

    CTagDBState()
    {
        nKeys = 0;
        nCKeys = 0;
        fIsEncrypted = false;
    }
};

bool CRoutingTagDB::WriteTag(const CRoutingTag &tag)
{
    // hash pubkey/privkey to accelerate wallet load
    // std::vector<unsigned char> vchKey;
    // vchKey.reserve(tag.vchPubKey.size() + tag.vchPrivKey.size());
    // vchKey.insert(tag.vchKey.end(), tag.vchPubKey.begin(), tag.vchPubKey.end());
    // vchKey.insert(tag.vchKey.end(), tag.vchPrivKey.begin(), tag.vchPrivKey.end());

    return Write(std::make_pair(std::string("tag"), tag.GetPubKey()), tag, false);
    // std::make_pair(tag.vchPrivKey, Hash(vchKey.begin(), vchKey.end())), false);
}

bool CRoutingTagDB::WriteCryptedTag(const CRoutingTag &tag)
{
    if (!Write(std::make_pair(std::string("ctag"), tag.GetPubKey()), tag, false))
    {
        return false;
    }
    Erase(std::make_pair(std::string("tag"), tag.GetPubKey()));
    return true;
}

bool CRoutingTagDB::WriteMasterTag(unsigned int nID, const CMasterKey &kMasterKey)
{
    return Write(std::make_pair(std::string("mkey"), nID), kMasterKey, true);
}

bool CRoutingTagDB::WriteLastUsedPublicTag(CRoutingTag &publicRoutingTag)
{
    publicRoutingTag.ConvertToPublicTag();
    return Write(std::string("lastpublictag"), publicRoutingTag);
}

bool CRoutingTagDB::ReadLastUsedPublicTag(CRoutingTag &publicRoutingTag)
{
    return Read(std::string("lastpublictag"), publicRoutingTag);
}

bool CRoutingTagDB::ReadPool(int64_t nPool, CKeyPoolEntry &keypool)
{
    return Read(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CRoutingTagDB::WritePool(int64_t nPool, const CKeyPoolEntry &keypool)
{
    return Write(std::make_pair(std::string("pool"), nPool), keypool);
}

bool CRoutingTagDB::ErasePool(int64_t nPool) { return Erase(std::make_pair(std::string("pool"), nPool)); }
bool ReadKeyValue(CNetTagStore *pwallet,
    CDataStream &ssKey,
    CDataStream &ssValue,
    CTagDBState &wss,
    std::string &strType,
    std::string &strErr)
{
    try
    {
        // Unserialize
        // Taking advantage of the fact that pair serialization
        // is just the two items serialized one after the other
        ssKey >> strType;
        if (strType == "tag")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading tag database: A Tag CPubKey is corrupt";
                return false;
            }
            CRoutingTag tag;
            uint256 hash;

            if (strType == "tag")
            {
                wss.nKeys++;
                ssValue >> tag;
            }

            /*
                if (!key.Load(pkey, vchPubKey, false))
                {
                    strErr = "Error reading wallet database: CPrivKey corrupt";
                    return false;
                }
            */
            if (!pwallet->LoadTag(tag))
            {
                strErr = "Error reading tag database: LoadTag failed";
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
                strErr = strprintf("Error reading tag database: duplicate CMasterKey id %u", nID);
                return false;
            }
            pwallet->mapMasterKeys[nID] = kMasterKey;
            if (pwallet->nMasterKeyMaxID < nID)
                pwallet->nMasterKeyMaxID = nID;
        }
        else if (strType == "ctag")
        {
            CPubKey vchPubKey;
            ssKey >> vchPubKey;
            if (!vchPubKey.IsValid())
            {
                strErr = "Error reading tag database: a crypted tag's CPubKey is corrupt";
                return false;
            }
            CRoutingTag tag;
            ssValue >> tag;
            wss.nCKeys++;

            if (!pwallet->LoadCryptedTag(tag))
            {
                strErr = "Error reading tag database: LoadCryptedTag failed";
                return false;
            }
            wss.fIsEncrypted = true;
        }
        else if (strType == "lastpublictag")
        {
            ssValue >> pwallet->publicRoutingTag;
            if (!pwallet->LoadTag(pwallet->publicRoutingTag))
            {
                strErr = "Error reading tag database: lastpublictag LoadTag failed";
                return false;
            }
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

static bool IsKeyType(std::string strType) { return (strType == "key" || strType == "mkey" || strType == "ckey"); }
bool CRoutingTagDB::LoadTags(CNetTagStore *pwallet)
{
    pwallet->publicRoutingTag = CRoutingTag();
    CTagDBState wss;
    try
    {
        // Get cursor
        Dbc *pcursor = GetCursor();
        if (!pcursor)
        {
            LogPrintf("Error getting tag database cursor\n");
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
                LogPrintf("Error reading next record from tag database\n");
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
    LogPrintf("Tags: %u plaintext, %u encrypted, %u total\n", wss.nKeys, wss.nCKeys, wss.nKeys + wss.nCKeys);
    return true;
}

//
// Try to (very carefully!) recover wallet.dat if there is a problem.
//
bool CRoutingTagDB::Recover(CDBEnv &dbenv, const std::string &filename, bool fOnlyKeys)
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
    CNetTagStore dummyWallet;
    CTagDBState wss;

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
                LogPrintf("WARNING:[Tags] CWalletDB::Recover skipping %s: %s\n", strType, strErr);
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

bool CRoutingTagDB::Recover(CDBEnv &dbenv, const std::string &filename)
{
    return CRoutingTagDB::Recover(dbenv, filename, false);
}
