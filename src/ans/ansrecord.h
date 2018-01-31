// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ANSRECORD_H
#define ANSRECORD_H

#include <string>
#include "uint256.h"

enum AnsRecordTypes{
    A_RECORD, // name to address
    CNAME_RECORD, // name to name
    PTR_RECORD, // address to name

    UNKNOWN_RECORD,
};

class CAnsRecord
{
private:
    std::string value;
    uint64_t expireTime;
    uint256 paymentHash;
    uint256 serviceHash;
public:
    CAnsRecord()
    {
        setNull();
    }

    CAnsRecord(std::string _value, uint64_t _expTime, uint256 _paymentHash, uint256 _serviceHash)
    {
        this->value = _value;
        this->expireTime = _expTime;
        this->paymentHash = _paymentHash;
        this->serviceHash = _serviceHash;
    }

    friend bool operator==(const CAnsRecord& a, const CAnsRecord& b)
    {
        return a.value == b.value &&
               a.expireTime == b.expireTime &&
               a.paymentHash == b.paymentHash &&
               a.serviceHash == b.serviceHash;
    }

    void setNull();

    void setValue(std::string strValue);
    std::string getValue();

    void setExpireTime(uint64_t ntime);
    uint64_t getExpireTime();

    void setPaymentHash(uint256 hash);
    uint256 getPaymentHash();

    void setServiceHash(uint256 hash);
    uint256 getServiceHash();
};

#endif // ANSRECORD_H
