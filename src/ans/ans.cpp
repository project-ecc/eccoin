#include "ans.h"

#include <utility>

bool CAnsZone::addRecord(AnsRecordTypes recordType, std::string key, CAnsRecord value)
{
    switch(recordType)
    {
        case Arec:
            A.insert(std::make_pair(key, value));
            break;
        case CNAMErec:
            CNAME.insert(std::make_pair(key, value));
            break;
        case PTRrec:
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
        case Arec:
        {
            auto Aresult = A.find(key);
            if(Aresult != A.end())
            {
                return Aresult->second;
            }
            break;
        }
        case CNAMErec:
        {
            auto CNAMEresult = CNAME.find(key);
            if(CNAMEresult != CNAME.end())
            {
                return CNAMEresult->second;
            }
            break;
        }
        case PTRrec:
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

uint64_t CAnsZone::getRecordSetSize(AnsRecordTypes recordType)
{
    // we use a declared uint64_t here and return that instead of returning
    // .size() because .size() is of type size_t
    uint64_t recordSetSize;
    switch(recordType)
    {
        case Arec:
        {
            recordSetSize = A.size();
            break;
        }
        case CNAMErec:
        {
            recordSetSize = CNAME.size();
            break;
        }
        case PTRrec:
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
        case Arec:
            A.clear();
            break;
        case CNAMErec:
            CNAME.clear();
            break;
        case PTRrec:
            PTR.clear();
            break;
        default:
            break;
    }
}


