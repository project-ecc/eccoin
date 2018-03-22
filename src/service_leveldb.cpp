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

