// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "ans.h"

#include <utility>

std::unique_ptr<CServiceDB> g_ans = nullptr;
CAnsZone* pansMain = nullptr;


static const char A_REC     = 'A';
static const char CNAME_REC = 'C';
static const char PTR_REC   = 'P';

bool CAnsZone::addRecord(AnsRecordTypes recordType, std::string key, CAnsRecord value)
{
    switch(recordType)
    {
        case A_RECORD:
            g_ans->WriteEntry(A_REC, key, value);
            break;
        case CNAME_RECORD:
            g_ans->WriteEntry(CNAME_REC, key, value);
            break;
        case PTR_RECORD:
            g_ans->WriteEntry(PTR_REC, key, value);
            break;
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
            g_ans->ReadEntry(A_REC, key, value);
            break;
        }
        case CNAME_RECORD:
        {
            g_ans->ReadEntry(CNAME_REC, key, value);
            break;
        }
        case PTR_RECORD:
        {
            g_ans->ReadEntry(PTR_REC, key, value);
            break;
        }
        default:
            break;
    }
    return value;
}

const uint64_t oneMonth = 2592000; // 30 days in seconds

// TODO : NEEDS ACTUAL TIME CALC METHOD
uint64_t CalcValidTime(uint64_t nTime, uint256 paymentHash)
{
    return nTime + oneMonth;
}
