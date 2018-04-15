// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ANSRECORD_H
#define ANSRECORD_H

#include <string>
#include "uint256.h"
#include "serialize.h"
#include "tx/servicetx.h"

enum AnsRecordTypes{
    A_RECORD, // name to address
    PTR_RECORD, // address to name

    UNKNOWN_RECORD, // ???
};

class CAnsRecord
{
private:
    std::string name;
    std::string address;
    uint64_t expireTime;
    uint256 paymentHash;
    uint256 serviceHash;
    std::string verificationCode;

    uint64_t CalcValidTime(uint64_t nTime, uint256 paymentHash);

public:
    CAnsRecord()
    {
        setNull();
    }

    CAnsRecord(const CServiceTransaction stx, std::string addr, std::string code = "")
    {
        std::string name(stx.vdata.begin(), stx.vdata.end());
        this->name = name;
        this->address = addr;
        this->expireTime = CalcValidTime(stx.nTime, stx.paymentReferenceHash);
        this->paymentHash = stx.paymentReferenceHash;
        this->serviceHash = stx.GetHash();
        this->verificationCode = code;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(name);
        READWRITE(address);
        READWRITE(expireTime);
        READWRITE(paymentHash);
        READWRITE(serviceHash);
        READWRITE(verificationCode);
    }


    friend bool operator==(const CAnsRecord& a, const CAnsRecord& b)
    {
        return a.name == b.name &&
               a.address == b.address &&
               a.expireTime == b.expireTime &&
               a.paymentHash == b.paymentHash &&
               a.serviceHash == b.serviceHash &&
               a.verificationCode == b.verificationCode;
    }

    friend bool operator!=(const CAnsRecord& a, const CAnsRecord& b)
    {
        return a.name != b.name ||
               a.address == b.address ||
               a.expireTime != b.expireTime ||
               a.paymentHash != b.paymentHash ||
               a.serviceHash != b.serviceHash ||
               a.verificationCode != b.verificationCode;
    }

    void setNull();

    void setName(std::string strName);
    std::string getName();

    void setAddress(std::string strAddress);
    std::string getAddress();

    void setExpireTime(uint64_t nTime);
    uint64_t getExpireTime();

    void setPaymentHash(uint256 hash);
    uint256 getPaymentHash();

    void setServiceHash(uint256 hash);
    uint256 getServiceHash();

    std::string getVertificationCode();
    bool isValidCode(std::string code);

};

class CAnsKey
{
private:
    const char record;
    const std::string name;
public:
    CAnsKey(const char& _record, std::string& _name) : record(_record), name(_name) {}

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(record);
        READWRITE(name);
    }
};

#endif // ANSRECORD_H
