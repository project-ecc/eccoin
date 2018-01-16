#include "ansrecord.h"

void CAnsRecord::setValue(std::string strValue)
{
    value = strValue;
}

std::string CAnsRecord::getValue()
{
    return value;
}

void CAnsRecord::setExpireTime(uint64_t ntime)
{
    expireTime = ntime;
}

uint64_t CAnsRecord::getExpireTime()
{
    return expireTime;
}

void CAnsRecord::setPaymentHash(uint256 hash)
{
    paymentHash = hash;
}

uint256 CAnsRecord::getPaymentHash()
{
    return paymentHash;
}

void CAnsRecord::setServiceHash(uint256 hash)
{
    serviceHash = hash;
}

uint256 CAnsRecord::getServiceHash()
{
    return serviceHash;
}
