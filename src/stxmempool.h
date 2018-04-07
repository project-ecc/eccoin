// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef STXMEMPOOL_H
#define STXMEMPOOL_H

#include "dbwrapper.h"
#include "uint256.h"
#include "tx/servicetx.h"

#include <map>
#include <string>
#include <utility>
#include <vector>

//! -stxcache default (MiB)
static const int64_t nDefaultStxCache = 512;

/** Access to a service transaction storage database since they arent stored in blocks
* Use leveldb since we already implement it for txindex and blockindexes.
* no need to find a new db when leveldb already works
*/
class CStxDB : public CDBWrapper
{
public:
    CStxDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
private:
    CStxDB(const CStxDB&);
    void operator=(const CStxDB&);
public:

    bool WriteEntry(uint256 hash, CServiceTransaction stx);
    bool ReadEntry(uint256 hash, CServiceTransaction& stx);
    bool EraseEntry(uint256 hash);
};

class CStxMemPool
{
private:
    CStxDB* stxdb = nullptr;
public:
    CStxMemPool()
    {
        stxdb = new CStxDB(nDefaultStxCache, false, false);
    }

    bool exists(uint256 hash) const;
    bool lookup(uint256 hash, CServiceTransaction& result) const;
    bool add(uint256 hash, CServiceTransaction& stx) const;
};

extern std::unique_ptr<CStxMemPool> g_stxmempool;

#endif // STXMEMPOOL_H
