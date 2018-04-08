// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ans.h"

#include <utility>

std::unique_ptr<CServiceDB> g_ans = nullptr;
CAnsZone* pansMain = nullptr;


static const char A_REC     = 'A';
static const char PTR_REC   = 'P';

bool CAnsZone::addRecord(AnsRecordTypes recordType, std::string key, CAnsRecord& value)
{
    switch(recordType)
    {
        case A_RECORD:
        {
            CAnsKey Akey(A_REC,key);
            g_ans->WriteEntry(Akey, value);
            break;
        }
        case PTR_RECORD:
        {
            CAnsKey PTRkey(PTR_REC,key);
            g_ans->WriteEntry(PTRkey, value);
            break;
        }
        default:
            return false;
    }
    return true;
}

CAnsRecord CAnsZone::getRecord(AnsRecordTypes recordType, std::string key)
{
    CAnsRecord value;
    value.setNull();
    switch(recordType)
    {
        case A_RECORD:
        {
            CAnsKey Akey(A_REC,key);
            g_ans->ReadEntry(Akey, value);
            break;
        }
        case PTR_RECORD:
        {
            CAnsKey PTRkey(PTR_REC,key);
            g_ans->ReadEntry(PTRkey, value);
            break;
        }
        default:
            break;
    }
    return value;
}
