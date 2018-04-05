#include <stdint.h>
#include <univalue.h>
#include <cctype>

#include "ans/ans.h"
#include "base58.h"
#include "main.h"
#include "rpcserver.h"
#include "tx/servicetx.h"
#include "util/utilmoneystr.h"
#include "wallet/wallet.h"

bool EnsureWalletIsAvailable(bool avoidException);

AnsRecordTypes resolveRecordType(std::string strRecordType)
{
    AnsRecordTypes recordtype;
    if(strRecordType == "A" || strRecordType == "a")
    {
        recordtype = AnsRecordTypes::A_RECORD;
    }
    else if(strRecordType == "CNAME" || strRecordType == "cname")
    {
        recordtype = AnsRecordTypes::CNAME_RECORD;
    }
    else if(strRecordType == "PTR" || strRecordType == "ptr")
    {
        recordtype = AnsRecordTypes::PTR_RECORD;
    }
    else
    {
        recordtype = AnsRecordTypes::UNKNOWN_RECORD;
    }
    return recordtype;
}

/// TODO : Revisit this for possibility later. right now it doesnt seem like this is doable with a db dynamic for all services
/*
UniValue getansrecordset(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getansrecordset \"recordType\"\n"
            "\nReturn the records in the requested record set.\n"
            "\nArguments:\n"
            "1. \"record type\"     (string, required) The record set to fetch. recordTypes are A, CNAME, PTR\n"
            "\nResult:\n"
            "{\n                  (json array of name-address pairs)\n"
            "  \"name, address\"  (string) a bitcoin address associated with the given account\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getansrecordset", "\"A\"")
            + HelpExampleRpc("getansrecordset", "\"CNAME\"")
        );
    std::string strRecordType = params[0].get_str();
    AnsRecordTypes recordtype = resolveRecordType(strRecordType);
    UniValue ret(UniValue::VOBJ);
    if(recordtype == AnsRecordTypes::UNKNOWN_RECORD)
    {
        ret.push_back(Pair("ERROR", "invalid record type requested. Valid record types are: A, CNAME, PTR"));
        return ret;
    }
    recordSet records = g_ans->getRecordSet(recordtype);
    if(records.size() == 0)
    {
        ret.push_back(Pair("ERROR", "the record set requested contains no records"));
        return ret;
    }
    for ( recordSet::iterator iter = records.begin(); iter != records.end(); ++iter )
    {
        ret.push_back(Pair(iter->first, iter->second.getValue()));
    }
    return ret;
}
*/

/// TODO : consider passing by reference for getRecord instead of returning a value
CAnsRecord getRecordUnknownType(std::string strRecordName)
{
    CAnsRecord record;
    if(strRecordName.size() <= 25)
    {
        record = pansMain->getRecord(AnsRecordTypes::A_RECORD, strRecordName);
        if(record != CAnsRecord())
        {
           return record;
        }
        record.setNull();
        record = pansMain->getRecord(AnsRecordTypes::CNAME_RECORD, strRecordName);
        if(record != CAnsRecord())
        {
           return record;
        }
    }
    else
    {
        record = pansMain->getRecord(AnsRecordTypes::PTR_RECORD, strRecordName);
        if(record != CAnsRecord())
        {
           return record;
        }
    }
    record.setNull();
    return record;
}

UniValue getansrecord(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getansrecord \"record name\" \"record type\" \n"
            "\nReturn the full record with the record name.\n"
            "\nArguments:\n"
            "1. \"record name\"     (string, required) The fetch the record with the provided record name\n"
            "2. \"record type\"     (string, optional) Search only this recordset for the provided record name\n"
            "\nResult:\n"
            "{\n                  (json array of name-address pairs)\n"
            "  \"name, address\"  (string) a bitcoin address associated with the given account\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getansrecordset", "\"A\"")
            + HelpExampleRpc("getansrecordset", "\"CNAME\"")
        );
    std::string strRecordName = params[0].get_str();
    AnsRecordTypes recordtype = AnsRecordTypes::UNKNOWN_RECORD;
    CAnsRecord record = CAnsRecord();
    UniValue ret(UniValue::VOBJ);
    if(params.size() == 2)
    {
        recordtype = resolveRecordType(params[1].get_str());
        record = pansMain->getRecord(recordtype, strRecordName);
    }
    else
    {
        record = getRecordUnknownType(strRecordName);
    }
    if(record == CAnsRecord())
    {
        ret.push_back(Pair("ERROR", "there is no record with that record name"));
        return ret;
    }
    ret.push_back(Pair("Key"        , strRecordName                    ));
    ret.push_back(Pair("Value"      , record.getValue()                ));
    ret.push_back(Pair("ExpireTime" , record.getExpireTime()           ));
    ret.push_back(Pair("paymentHash", record.getPaymentHash().GetHex() ));
    ret.push_back(Pair("ServiceHash", record.getServiceHash().GetHex() ));
    return ret;
}



static void SendMoney(const CTxDestination &address, CAmount nValue, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet)
{
    CAmount curBalance = pwalletMain->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // TODO : make an actual fee calculation for services, just use 1 ECC for now for testing purposes
    CAmount nFeeRequired = ((1 * COIN) / 100);
    std::string strError;
    CRecipient recipient = {scriptPubKey, nValue, false};
    if (!pwalletMain->CreateTransactionForService(recipient, wtxNew, reservekey, nFeeRequired, nFeeRet, strError))
    {
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
        {
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        }
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
}

static void CreateANStransaction(CServiceTransaction& stxnew, CWalletTx& wtxnew, std::string& strUsername, CAmount& nFeeRet)
{
    stxnew.nVersion = CServiceTransaction::CURRENT_VERSION;
    stxnew.nServiceId = 0; // 0 is for ANS because pure payment addresses use odd number tx versions
    stxnew.nTime = GetTime();
    stxnew.nOpCode = 0;

    /// TODO : Make a real time calculation, this should suffice for testing though.
    uint32_t lockTime = (60 * 60 * 24 *30); // 30 days
    lockTime = lockTime * (nFeeRet / 1); // allow payment for multiple months at a time
    stxnew.nLockTime = lockTime;
    /// TODO : SOME CALCULATION TO GET VERIFICATION CODE base on time and pub key of addr being used

    stxnew.vdata = std::vector<unsigned char>(strUsername.begin(), strUsername.end()); // should just be the username

    // add service transaction hash to payment hash so it can be rehashed later
    wtxnew.tx->serviceReferenceHash = stxnew.GetHash();
}

UniValue getansaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 2)
    {
        throw std::runtime_error(
            "getansaddress \"bitcoinaddress\" \"username\" \n"
            "\nAssign a username to an owned address.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address to have a username set to.\n"
            "2. \"username\"  (string, required) The username to be set.\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id and additional info.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" \"alice\"")
            + HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", \"bob\"")
        );
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string strAddress = params[0].get_str();
    CBitcoinAddress address(strAddress);
    if (!address.IsValid())
    {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    }
    if(!pwalletMain->AddressIsMine(address.Get()))
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + address.ToString() + " is not known");
    }

    // Amount
    std::string strUsername;
    strUsername = params[1].get_str();

    if(strUsername.length() > 25)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Username exceeds maxiumum length of 25");
    }

    // check for banned letters/numbers
    /** All alphanumeric characters except for "0", "I", "O", and "l" */

    if(strUsername.find("0") != std::string::npos)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Username contains invalid charactar. All alphanumeric characters EXCEPT for zero, capital i, capital o, and lowercase L are allowed");
    }
    if(strUsername.find("I") != std::string::npos)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Username contains invalid charactar. All alphanumeric characters EXCEPT for zero, capital i, capital o, and lowercase L are allowed");
    }
    if(strUsername.find("O") != std::string::npos)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Username contains invalid charactar. All alphanumeric characters EXCEPT for zero, capital i, capital o, and lowercase L are allowed");
    }
    if(strUsername.find("l") != std::string::npos)
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Username contains invalid charactar. All alphanumeric characters EXCEPT for zero, capital i, capital o, and lowercase L are allowed");
    }

    std::string::size_type i = 0;
    while(i<strUsername.length())
    {
        /// ANS names can only have ascii values in them
        if(isalnum(strUsername[i]) == false)
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Username contains invalid charactar. All alphanumeric characters EXCEPT for zero, capital i, capital o, and lowercase L are allowed");
        }
        i++;
    }
    EnsureWalletIsUnlocked();

    // check to make sure we dont already have an A record for that name
    AnsRecordTypes recordtype = AnsRecordTypes::A_RECORD;
    if(pansMain->getRecord(recordtype, strUsername) != CAnsRecord())
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Username already exists for an address");
    }


    CWalletTx wtx;
    CServiceTransaction stx;
    // TODO : have user enter coin amount to pay for ans address, right now it is set to the default 1 month and cant be changed
    CAmount nAmount = (1 * COIN);
    CAmount nFeeRet = 0;
    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    SendMoney(address.Get(), nAmount, wtx, reservekey, nFeeRet);
    CreateANStransaction(stx, wtx, strUsername, nFeeRet);
    // update the payment hash to include the service transactions hash as a member of its hash
    wtx.tx->UpdateHash();
    // paymentReferenceHash of service transaction must be set AFTER rehashing the payment hash as the rehash of the payment hash will include the hash of the service transaction
    stx.paymentReferenceHash = wtx.tx->GetHash();
    LogPrintf("payment transaction made was: %s \n", wtx.tx->ToString().c_str());
    LogPrintf("service transaction made was: %s \n", stx.ToString().c_str());
    
    CValidationState state;
    if (!pwalletMain->CommitTransaction(wtx, reservekey, g_connman.get(), state))
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
    }
    if (!pwalletMain->CommitTransactionForService(stx, strUsername, g_connman.get()))
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The service transaction was rejected! This might happen for a variety of reasons.");
    }
    
    std::string responseMessage = "The user name " + strUsername + " has been assigned to the address " + strAddress + ""
        " with PaymentHash = " + wtx.tx->GetHash().GetHex() + " and  ServiceHash = " + stx.GetHash().GetHex();

    return responseMessage;
}
