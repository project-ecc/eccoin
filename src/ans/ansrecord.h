#ifndef ANSRECORD_H
#define ANSRECORD_H

#include <string>
#include "uint256.h"

enum AnsRecordTypes{
    Arec, // name to address
    CNAMErec, // name to name
    PTRrec, // address to name
};

class CAnsRecord
{
private:
    std::string value;
    uint64_t expireTime;
    uint256 paymentHash;
    uint256 serviceHash;
public:
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
