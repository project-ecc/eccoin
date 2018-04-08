// Copyright (c) 2018 Greg Griffith and the ECC developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

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

bool CAnsRecord::getAddrFromPtx(std::string& addr)
{
    addr = "";
    CTransaction ptx;
    uint256 blockHashOfTx;
    if (!GetTransaction(this->paymentHash, ptx, pnetMan->getActivePaymentNetwork()->GetConsensus(), blockHashOfTx))
    {
        return false;
    }
    std::vector<std::vector<unsigned char> > vSolutionsOut;
    txnouttype whichTypeOut;
    CKeyID addressOutID;
    CBitcoinAddress addrOut;
    CScript scriptPubKeyOut = ptx.vout[0].scriptPubKey;
    if (!Solver(scriptPubKeyOut, whichTypeOut, vSolutionsOut))
    {
        return false;
    }

    if (whichTypeOut == TX_PUBKEY)
    {
        CPubKey pubKey(vSolutionsOut[0]);
        if (!pubKey.IsValid())
        {
            return false;
        }
        addressOutID = pubKey.GetID();
    }
    else if (whichTypeOut == TX_PUBKEYHASH)
    {
        addressOutID = CKeyID(uint160(vSolutionsOut[0]));
    }
    else
    {
        return false;
    }
    addrOut = CBitcoinAddress(addressOutID);
    addr = addrOut.ToString();
    return true;
}

const uint64_t oneMonth = 2592000; // 30 days in seconds
// TODO : NEEDS ACTUAL TIME CALC METHOD
uint64_t CAnsRecord::CalcValidTime(uint64_t nTime, uint256 paymentHash)
{
    return nTime + oneMonth;
}
