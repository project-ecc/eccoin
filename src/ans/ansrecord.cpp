// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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
