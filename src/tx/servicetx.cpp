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

#include "servicetx.h"
#include "crypto/hash.h"
#include "streams.h"
#include "timedata.h"
#include "tinyformat.h"

struct serializeServiceTx
{
    int32_t nVersion;
    uint16_t nServiceId;
    unsigned int nTime;
    uint16_t nOpCode;
    uint32_t nExpireTime;
    std::vector<unsigned char> vdata;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*const_cast<int32_t*>(&this->nVersion));
        nVersion = this->nVersion;
        READWRITE(*const_cast<uint16_t*>(&this->nServiceId));
        READWRITE(*const_cast<uint32_t*>(&this->nTime));
        READWRITE(*const_cast<uint16_t*>(&this->nOpCode));
        READWRITE(*const_cast<uint32_t*>(&nExpireTime));
        READWRITE(*const_cast<std::vector<unsigned char>*>(&vdata));
    }
};

uint256 CServiceTransaction::GetHash() const
{
    serializeServiceTx txtohash;
    txtohash.nVersion = this->nVersion;
    txtohash.nServiceId = this->nServiceId;
    txtohash.nTime = this->nTime;
    txtohash.nOpCode = this->nOpCode;
    txtohash.nExpireTime = this->nExpireTime;
    txtohash.vdata = this->vdata;
    return SerializeHash(txtohash);
}

void CServiceTransaction::UpdateHash() const
{
    serializeServiceTx txtohash;
    txtohash.nVersion = this->nVersion;
    txtohash.nServiceId = this->nServiceId;
    txtohash.nTime = this->nTime;
    txtohash.nOpCode = this->nOpCode;
    txtohash.nExpireTime = this->nExpireTime;
    txtohash.vdata = this->vdata;
    *const_cast<uint256*>(&hash) = SerializeHash(txtohash);
}

CServiceTransaction::CServiceTransaction() : nVersion(CServiceTransaction::CURRENT_VERSION), nServiceId(0), nTime(GetAdjustedTime()),
        nOpCode(0), nExpireTime(0), vdata(), paymentReferenceHash() { //, securityHash() {
    paymentReferenceHash.SetNull();
//    securityHash.SetNull();
}

CServiceTransaction::CServiceTransaction(const CServiceTransaction &tx) : nVersion(tx.nVersion), nServiceId(tx.nServiceId), nTime(tx.nTime),
        nOpCode(tx.nOpCode), nExpireTime(tx.nExpireTime), vdata(tx.vdata), paymentReferenceHash(tx.paymentReferenceHash) { //, securityHash(tx.securityHash) {
    UpdateHash();
}

CServiceTransaction& CServiceTransaction::operator=(const CServiceTransaction &tx) {
    *const_cast<int32_t*>(&nVersion) = tx.nVersion;
    *const_cast<uint16_t*>(&nServiceId) = tx.nServiceId;
    *const_cast<uint32_t*>(&nTime) = tx.nTime;
    *const_cast<uint16_t*>(&nOpCode) = tx.nOpCode;
    *const_cast<unsigned int*>(&nExpireTime) = tx.nExpireTime;
    *const_cast<std::vector<unsigned char>*>(&vdata) = tx.vdata;
    *const_cast<uint256*>(&paymentReferenceHash) = tx.paymentReferenceHash;
//    *const_cast<uint256*>(&securityHash) = tx.securityHash;
    *const_cast<uint256*>(&hash) = tx.hash;
    return *this;
}

std::string CServiceTransaction::ToString() const
{
    std::string str;
    std::string datastr(vdata.begin(), vdata.end());
    str += strprintf("CServiceTransaction(hash=%s, ver=%d, nServiceId=%u, nTime=%u, nOpCode=%u, nExpireTime=%u, vdata=%s, paymentReferenceHash=%s)\n",
        GetHash().ToString().substr(0,10),
        nVersion,
        nServiceId,
        nTime,
        nOpCode,
        nExpireTime,
        datastr.c_str(),
        paymentReferenceHash.GetHex().c_str());
    return str;
}

/*
void CServiceTransaction::setSecurityHash()
{
    CDataStream ss(SER_GETHASH, 0);
    ss << this->paymentReferenceHash;
    ss << this->GetHash();
    securityHash = Hash(ss.begin(), ss.end());
}
*/
