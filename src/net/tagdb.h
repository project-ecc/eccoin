// This file is part of the Eccoin project
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2014-2019 The Eccoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ECCOIN_TAGDB_H
#define ECCOIN_TAGDB_H

#include "crypter.h"
#include "key.h"
#include "keypoolentry.h"
#include "keystore.h"
#include "routingtag.h"
#include "wallet/cryptokeystore.h"
#include "wallet/db.h"

// #include <list>
#include <stdint.h>
#include <string>
#include <utility>
#include <vector>

class CNetTagStore;

/** Access to the routing database (routing.dat) */
class CRoutingTagDB : public CDB
{
public:
    CRoutingTagDB(const std::string &strFilename, const char *pszMode = "r+", bool fFlushOnCloseIn = true)
        : CDB(strFilename, pszMode, fFlushOnCloseIn)
    {
    }

    bool WriteTag(const CRoutingTag &tag);
    bool WriteCryptedTag(const CRoutingTag &tag);
    bool WriteMasterTag(unsigned int nID, const CMasterKey &kMasterKey);

    bool WriteLastUsedPublicTag(CRoutingTag &publicRoutingTag);
    bool ReadLastUsedPublicTag(CRoutingTag &publicRoutingTag);

    bool ReadPool(int64_t nPool, CKeyPoolEntry &keypool);
    bool WritePool(int64_t nPool, const CKeyPoolEntry &keypool);
    bool ErasePool(int64_t nPool);

    bool LoadTags(CNetTagStore *pwallet);
    static bool Recover(CDBEnv &dbenv, const std::string &filename, bool fOnlyKeys);
    static bool Recover(CDBEnv &dbenv, const std::string &filename);

private:
    CRoutingTagDB(const CRoutingTagDB &);
    void operator=(const CRoutingTagDB &);
};

#endif // ECCOIN_TAGDB_H
