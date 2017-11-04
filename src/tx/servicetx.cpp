#include "servicetx.h"
#include "crypto/hash.h"
#include "timedata.h"



uint256 CServiceTransaction::GetHash() const
{
    return SerializeHash(*this);
}

void CServiceTransaction::UpdateHash() const
{
    *const_cast<uint256*>(&hash) = SerializeHash(*this);
}

CServiceTransaction::CServiceTransaction() : nVersion(CServiceTransaction::CURRENT_VERSION), nServiceId(0), nTime(GetAdjustedTime()), nOpCode(0), nLockTime(0), vdata(), paymentReferenceHash() {
    paymentReferenceHash.SetNull();
}

CServiceTransaction::CServiceTransaction(const CServiceTransaction &tx) : nVersion(tx.nVersion), nServiceId(tx.nServiceId), nTime(tx.nTime), nOpCode(tx.nOpCode), nLockTime(tx.nLockTime), vdata(tx.vdata), paymentReferenceHash(tx.paymentReferenceHash) {
    UpdateHash();
}

CServiceTransaction& CServiceTransaction::operator=(const CServiceTransaction &tx) {
    *const_cast<int32_t*>(&nVersion) = tx.nVersion;
    *const_cast<uint16_t*>(&nServiceId) = tx.nServiceId;
    *const_cast<uint32_t*>(&nTime) = tx.nTime;
    *const_cast<uint16_t*>(&nOpCode) = tx.nOpCode;
    *const_cast<unsigned int*>(&nLockTime) = tx.nLockTime;
    *const_cast<std::vector<unsigned char>*>(&vdata) = tx.vdata;
    *const_cast<uint256*>(&paymentReferenceHash) = tx.paymentReferenceHash;
    *const_cast<uint256*>(&hash) = tx.hash;
    return *this;
}

std::string CServiceTransaction::ToString() const
{
    return "";
}
