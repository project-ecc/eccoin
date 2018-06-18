/*
 * This file is part of the ECC project
 * Copyright (c) 2018 Greg Griffith
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef STXMEMPOOL_H
#define STXMEMPOOL_H

#include "dbwrapper.h"
#include "uint256.h"
#include "services/servicetx.h"

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
    std::unique_ptr<CStxDB> stxdb;
public:
    CStxMemPool()
    {
        stxdb.reset(new CStxDB(nDefaultStxCache, false, false));
    }
    ~CStxMemPool()
    {
        stxdb.reset();
        stxdb = nullptr;
    }

    bool exists(uint256 hash) const;
    bool lookup(uint256 hash, CServiceTransaction& result) const;
    bool add(uint256 hash, CServiceTransaction& stx) const;
};

extern std::unique_ptr<CStxMemPool> g_stxmempool;

#endif // STXMEMPOOL_H
