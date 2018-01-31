// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ans.h"

#include <utility>

CAnsZone* pansMain = nullptr;

bool CAnsZone::addRecord(AnsRecordTypes recordType, std::string key, CAnsRecord value)
{
    switch(recordType)
    {
        case A_RECORD:
            A.insert(std::make_pair(key, value));
            break;
        case CNAME_RECORD:
            CNAME.insert(std::make_pair(key, value));
            break;
        case PTR_RECORD:
            PTR.insert(std::make_pair(key, value));
            break;
        default:
            return false;
    }
    return true;
}

CAnsRecord CAnsZone::getRecord(AnsRecordTypes recordType, std::string key)
{
    switch(recordType)
    {
        case A_RECORD:
        {
            auto Aresult = A.find(key);
            if(Aresult != A.end())
            {
                return Aresult->second;
            }
            break;
        }
        case CNAME_RECORD:
        {
            auto CNAMEresult = CNAME.find(key);
            if(CNAMEresult != CNAME.end())
            {
                return CNAMEresult->second;
            }
            break;
        }
        case PTR_RECORD:
        {
            auto PTRresult = PTR.find(key);
            if(PTRresult != PTR.end())
            {
                return PTRresult->second;
            }
            break;
        }
        default:
            break;
    }
    return CAnsRecord();
}

recordSet CAnsZone::getRecordSet(AnsRecordTypes recordType)
{
    switch(recordType)
    {
        case A_RECORD:
        {
            return A;
        }
        case CNAME_RECORD:
        {
            return CNAME;
        }
        case PTR_RECORD:
        {
            return PTR;
        }
        default:
            break;
    }
    return recordSet();
}

uint64_t CAnsZone::getRecordSetSize(AnsRecordTypes recordType)
{
    // we use a declared uint64_t here and return that instead of returning
    // .size() because .size() is of type size_t
    uint64_t recordSetSize;
    switch(recordType)
    {
        case A_RECORD:
        {
            recordSetSize = A.size();
            break;
        }
        case CNAME_RECORD:
        {
            recordSetSize = CNAME.size();
            break;
        }
        case PTR_RECORD:
        {
            recordSetSize = PTR.size();
            break;
        }
        default:
            return 0;
    }
    return recordSetSize;
}

void CAnsZone::clearRecordSet(AnsRecordTypes recordType)
{
    switch(recordType)
    {
        case A_RECORD:
            A.clear();
            break;
        case CNAME_RECORD:
            CNAME.clear();
            break;
        case PTR_RECORD:
            PTR.clear();
            break;
        default:
            break;
    }
}


