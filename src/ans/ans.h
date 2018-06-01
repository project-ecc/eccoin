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
    bool addTimeToRecord(CServiceTransaction stx, std::string& addr, uint64_t additionalTime);
};

extern CAnsZone* pansMain;
#endif // ANS_H
