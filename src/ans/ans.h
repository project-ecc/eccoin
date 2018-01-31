// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
    recordSet getRecordSet(AnsRecordTypes recordType);
    uint64_t getRecordSetSize(AnsRecordTypes recordType);
    void clearRecordSet(AnsRecordTypes recordType);
};

extern CAnsZone* pansMain;


#endif // ANS_H
