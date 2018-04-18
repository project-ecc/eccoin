// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ans.h"

#include <utility>

std::unique_ptr<CServiceDB> g_ans = nullptr;
CAnsZone* pansMain = nullptr;


static const char A_REC     = 'A';
static const char PTR_REC   = 'P';

bool CAnsZone::existsRecord(CAnsKey key)
{
    return g_ans->ExistsEntry(key);
}

bool CAnsZone::existsRecord(AnsRecordTypes recordType, std::string key)
{
    CAnsKey anskey(recordType, key);
    return existsRecord(anskey);
}

bool CAnsZone::addRecord(AnsRecordTypes recordType, std::string key, CAnsRecord& value)
{
    switch(recordType)
    {
        case A_RECORD:
        {
            CAnsKey Akey(A_REC, key);
            CAnsRecordSet recSet;
            // get existing record set if there is one, if not recSet will remain unchanged
            g_ans->ReadEntry(Akey, recSet);
            // add the record to to record set. since its a set if a record with that key already exists, nothing will be changed
            recSet.addRecord(value.getVertificationCode(), value);
            //write the new/updated record set to the DB
            if(g_ans->WriteEntry(Akey, recSet))
            {
                return true;
            }
            break;
        }
        case PTR_RECORD:
        {
            // PTR records are unique since an address can only have so we store the record directly
            CAnsKey PTRkey(PTR_REC, key);
            if(g_ans->WriteEntry(PTRkey, value))
            {
                return true;
            }
            break;
        }
        default:
            return false;
    }
    return false;
}


bool CAnsZone::getRecord(std::string key, CAnsRecordSet &value)
{
    CAnsKey Akey(A_REC,key);
    return g_ans->ReadEntry(Akey, value);
}

bool CAnsZone::getRecord(std::string key, CAnsRecord &value)
{
    value.setNull();
    CAnsKey PTRkey(PTR_REC,key);
    return g_ans->ReadEntry(PTRkey, value);
}

bool CAnsZone::addTimeToRecord(CServiceTransaction stx, std::string& addr, uint64_t newExpireTime)
{
    CAnsRecord value(stx, addr);
    std::string name = value.getName();
    std::string address = value.getAddress();
    CAnsKey Akey(A_REC, name);
    if(!g_ans->ReadEntry(Akey, value))
    {
        return false;
    }
    value.setExpireTime(newExpireTime);
    g_ans->WriteEntry(Akey, value);

    CAnsKey PTRkey(PTR_REC, address);
    if(!g_ans->ReadEntry(PTRkey, value))
    {
        return false;
    }
    value.setExpireTime(newExpireTime);
    g_ans->WriteEntry(PTRkey, value);
    return true;
}


