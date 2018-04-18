// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ANS_H
#define ANS_H

#include "ansrecord.h"

#include "service_leveldb.h"

#include <string>
#include <unordered_map>
#include <memory>

enum Opcode_ANS{
    OP_REGISTER,
    OP_RENEW,
};

extern std::unique_ptr<CServiceDB> g_ans;

class CAnsZone
{
public:
    bool existsRecord(CAnsKey key);
    bool existsRecord(AnsRecordTypes recordType, std::string key);
    bool addRecord(AnsRecordTypes recordType, std::string key, CAnsRecord &value);
    bool getRecord(std::string key, CAnsRecordSet &value);
    bool getRecord(std::string key, CAnsRecord &value);
    bool addTimeToRecord(CServiceTransaction stx, std::string& addr, uint64_t newExpireTime);
};

extern CAnsZone* pansMain;
#endif // ANS_H
