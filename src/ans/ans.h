#ifndef ANS_H
#define ANS_H

#include "ansrecord.h"

#include <string>
#include <unordered_map>

typedef std::unordered_map<std::string, CAnsRecord> recordSet;

class CAnsZone
{
private:
    recordSet A;
    recordSet CNAME;
    recordSet PTR;
public:
    bool addRecord(AnsRecordTypes recordType, std::string key, CAnsRecord value);
    CAnsRecord getRecord(AnsRecordTypes recordType, std::string key);
    uint64_t getRecordSetSize(AnsRecordTypes recordType);
    void clearRecordSet(AnsRecordTypes recordType);
};

#endif // ANS_H
