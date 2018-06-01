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
    void addExpireTime(uint64_t nTime);
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
    CAnsKey(const char& _record, std::string& _name) : record(_record), name(_name)
    {

    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(record);
        READWRITE(name);
    }
};

class CAnsRecordSet
{
private:
    std::map<std::string, CAnsRecord> recordSet;
public:
    CAnsRecordSet()
    {
        recordSet.clear();
    }

    CAnsRecordSet(std::map<std::string, CAnsRecord> _recordSet)
    {
        recordSet = _recordSet;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(recordSet);
    }

    bool addRecord(std::string code, CAnsRecord rec)
    {
        if(code == "")
        {
            return false;
        }
        auto ret = recordSet.insert(std::make_pair(code,rec));
        return ret.second;
    }

    bool getRecord(std::string code, CAnsRecord& rec)
    {
        auto ret = recordSet.find(code);
        if(ret != recordSet.end())
        {
            rec = (*ret).second;
            return true;
        }
        return false;
    }

    std::map<std::string, CAnsRecord> getRecords()
    {
        return recordSet;
    }

    bool removeRecord(std::string code)
    {
        auto ret = recordSet.find(code);
        if(ret != recordSet.end())
        {
            recordSet.erase(ret);
            return true;
        }
        return false;
    }
};

#endif // ANSRECORD_H
