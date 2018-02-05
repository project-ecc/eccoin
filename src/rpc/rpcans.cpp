#include <stdint.h>
#include <univalue.h>
#include <cctype>

#include "ans/ans.h"
#include "base58.h"
#include "rpcserver.h"
#include "tx/servicetx.h"
#include "wallet/wallet.h"

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
    recordSet records = pansMain->getRecordSet(recordtype);
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
        if(strRecordName.size() <= 25)
        {
            recordSet Arecords = pansMain->getRecordSet(AnsRecordTypes::A_RECORD);
            recordSet::iterator Aiter = Arecords.find(strRecordName);
            if(Aiter != Arecords.end())
            {
                record = Aiter->second;
            }
            else
            {
                recordSet CNAMErecords = pansMain->getRecordSet(AnsRecordTypes::CNAME_RECORD);
                recordSet::iterator CNAMEiter = CNAMErecords.find(strRecordName);
                if(CNAMEiter != CNAMErecords.end())
                {
                    record = CNAMEiter->second;
                }
            }
        }
        else
        {
            recordSet records = pansMain->getRecordSet(AnsRecordTypes::PTR_RECORD);
            for ( recordSet::iterator iter = records.begin(); iter != records.end(); ++iter )
            {
                ret.push_back(Pair(iter->first, iter->second.getValue()));
            }
        }
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



static void SendMoney(const CTxDestination &address, CAmount nValue, bool fSubtractFeeFromAmount, CWalletTx& wtxNew)
{
    CAmount curBalance = pwalletMain->GetBalance();

    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, nValue, fSubtractFeeFromAmount};
    vecSend.push_back(recipient);
    if (!pwalletMain->CreateTransaction(vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError)) {
        if (!fSubtractFeeFromAmount && nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds!", FormatMoney(nFeeRequired));
        throw JSONRPCError(RPC_WALLET_ERROR, strError);
    }
    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The transaction was rejected! This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
}

static void CreateANStransaction(CServiceTransaction& stxnew, CAmount feePaid, std::string& strUsername)
{
    stxnew.nVersion = CServiceTransaction::CURRENT_VERSION;
    stxnew.nServiceId = 0; // 0 is for ANS because pure payment addresses use odd number tx versions
    stxnew.nTime = GetTime();
    stxnew.nOpCode = 0; // for all ANS tx's this fields is 0;
    stxnew.nLockTime = feepaidTotal; // TODO : some fee calculation here
    /// TODO : SOME CALCULATION TO GET VERIFICATION CODE base on time and pub key of addr being used

    stxnew.vdata = strUsername; // should just be the username


}

UniValue getansaddress(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() < 2 || params.size() > 5)
        throw std::runtime_error(
            "sendtoaddress \"bitcoinaddress\" \"username\" \n"
            "\nSend an amount to a given address.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"bitcoinaddress\"  (string, required) The bitcoin address to send to.\n"
            "2. \"amount\"      (numeric or string, required) The amount in " + CURRENCY_UNIT + " to send. eg 0.1\n"
            "3. \"comment\"     (string, optional) A comment used to store what the transaction is for. \n"
            "                             This is not part of the transaction, just kept in your wallet.\n"
            "4. \"comment-to\"  (string, optional) A comment to store the name of the person or organization \n"
            "                             to which you're sending the transaction. This is not part of the \n"
            "                             transaction, just kept in your wallet.\n"
            "5. subtractfeefromamount  (boolean, optional, default=false) The fee will be deducted from the amount being sent.\n"
            "                             The recipient will receive less bitcoins than you enter in the amount field.\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"donation\" \"seans outpost\"")
            + HelpExampleCli("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\" 0.1 \"\" \"\" true")
            + HelpExampleRpc("sendtoaddress", "\"1M72Sfpbz1BPpXFHz9m3CdqATR44Jvaydd\", 0.1, \"donation\", \"seans outpost\"")
        );

    LOCK2(cs_main, pwalletMain->cs_wallet);

    std::string strAddress = params[0].get_str();
    CBitcoinAddress address(strAddress);
    if (!address.IsValid())
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid Bitcoin address");
    if(!pwalletMain->AddressIsMine(address.Get()))
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "Private key for address " + address.ToString() + " is not known");
    }

    // Amount
    std::string strUsername = params[1].get_str();

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
        if(isalnum(strUsername[i]) == false)
        {
            throw JSONRPCError(RPC_INVALID_PARAMS, "Username contains invalid charactar. All alphanumeric characters EXCEPT for zero, capital i, capital o, and lowercase L are allowed");
        }
        i++;
    }
    EnsureWalletIsUnlocked();
    CWalletTx wtx;
    CServiceTransaction stx;
    CAmount nFeeRequired = SendMoney(address.Get(), nAmount, fSubtractFeeFromAmount, wtx);
    CreateANStransaction(stx, nFeeRequired, strUsername);

    std::string responseMessage = "The user name " + strUsername + " has been assigned to the address " + strAddress + ""
        " with PaymentHash = " + wtx.GetHash().GetHex() + " and  ServiceHash = " + stx.GetHash().GetHex();

    return responseMessage;
}
