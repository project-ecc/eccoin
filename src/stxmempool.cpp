// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "stxmempool.h"

#include "util/util.h"

std::unique_ptr<CStxMemPool> g_stxmempool = nullptr;

CStxDB::CStxDB(size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "services" / "mempool", nCacheSize, fMemory, fWipe)
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
