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


#include "ansrecord.h"
#include "tx/tx.h"
#include "base58.h"
#include "script/script.h"

void CAnsRecord::setNull()
{
    name.clear();
    address.clear();
    expireTime = 0;
    paymentHash.SetNull();
    serviceHash.SetNull();
    verificationCode.clear();
}

void CAnsRecord::setName(std::string strName)
{
    name = strName;
}

std::string CAnsRecord::getName()
{
    return name;
}

void CAnsRecord::setAddress(std::string strAddress)
{
    address = strAddress;
}

std::string CAnsRecord::getAddress()
{
    return address;
}

void CAnsRecord::setExpireTime(uint64_t nTime)
{
    expireTime = nTime;
}

void CAnsRecord::addExpireTime(uint64_t nTime)
{
    expireTime = expireTime + nTime;
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

std::string CAnsRecord::getVertificationCode()
{
    return verificationCode;
}

bool CAnsRecord::isValidCode(std::string code)
{
    return code == this->verificationCode;
}

const uint64_t oneMonth = 2592000; // 30 days in seconds
// TODO : NEEDS ACTUAL TIME CALC METHOD
uint64_t CAnsRecord::CalcValidTime(uint64_t nTime, uint256 paymentHash)
{
    return nTime + oneMonth;
}
