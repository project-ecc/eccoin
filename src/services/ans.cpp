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
    if(recordType == A_RECORD)
    {
        CAnsKey anskey(A_REC, key);
        return existsRecord(anskey);
    }
    else if(recordType == PTR_RECORD)
    {
        CAnsKey anskey(PTR_REC, key);
        return existsRecord(anskey);
    }
    return false;
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
            if(!recSet.addRecord(value.getVertificationCode(), value))
            {
                break;
            }
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

bool CAnsZone::addTimeToRecord(CServiceTransaction stx, std::string& addr, uint64_t additionalTime)
{
    CAnsRecord value(stx, addr);
    std::string name = value.getName();
    std::string address = value.getAddress();
    CAnsKey Akey(A_REC, name);
    if(!g_ans->ReadEntry(Akey, value))
    {
        return false;
    }
    value.addExpireTime(additionalTime);
    g_ans->WriteEntry(Akey, value);

    CAnsKey PTRkey(PTR_REC, address);
    if(!g_ans->ReadEntry(PTRkey, value))
    {
        return false;
    }
    value.addExpireTime(additionalTime);
    g_ans->WriteEntry(PTRkey, value);
    return true;
}


