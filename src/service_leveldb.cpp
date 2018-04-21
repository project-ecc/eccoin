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

#include "service_leveldb.h"

#include "util/util.h"

CServiceDB::CServiceDB(std::string name, size_t nCacheSize, bool fMemory, bool fWipe) : CDBWrapper(GetDataDir() / "services" / + name.c_str(), nCacheSize, fMemory, fWipe)
{

}

bool CServiceDB::WriteFlag(const char &SERVICE_FLAG, const std::string &name, bool fValue)
{
    return Write(std::make_pair(SERVICE_FLAG, name), fValue ? '1' : '0');
}

bool CServiceDB::ReadFlag(const char &SERVICE_FLAG, const std::string &name, bool &fValue)
{
    char ch;
    if (!Read(std::make_pair(SERVICE_FLAG, name), ch))
        return false;
    fValue = ch == '1';
    return true;
}

bool CServiceDB::EraseFlag(const char &SERVICE_FLAG, const std::string &name)
{
    CDBBatch batch(*this);
    batch.Erase(std::make_pair(SERVICE_FLAG,name));
    return WriteBatch(batch);
}

