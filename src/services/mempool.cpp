/*
 * This file is part of the Eccoin project
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

#include "services/mempool.h"

#include "util/util.h"

std::unique_ptr<CStxMemPool> g_stxmempool = nullptr;

CStxDB::CStxDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "services/mempool", nCacheSize, fMemory, fWipe)
{

}

bool CStxDB::WriteEntry(uint256 hash, CServiceTransaction stx)
{
    return Write(hash, stx);
}
bool CStxDB::ReadEntry(uint256 hash, CServiceTransaction& stx)
{
    return Read(hash, stx);
}
bool CStxDB::EraseEntry(uint256 hash)
{
    return Erase(hash);
}


bool CStxMemPool::exists(uint256 hash) const
{
    return stxdb->Exists(hash);
}

bool CStxMemPool::lookup(uint256 hash, CServiceTransaction& result) const
{
    return stxdb->ReadEntry(hash, result);
}

bool CStxMemPool::add(uint256 hash, CServiceTransaction& stx) const
{
    return stxdb->Write(hash, stx);
}
