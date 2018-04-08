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

/*************************************
 *
 * ANS Internal RPC Logic
 *
 */

AnsRecordTypes resolveRecordType(std::string strRecordType)
{
    AnsRecordTypes recordtype;
    if(strRecordType == "A" || strRecordType == "a")
    {
        recordtype = AnsRecordTypes::A_RECORD;
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

bool getRecordUnknownType(std::string strRecordName, CAnsRecord& record)
{
    record.setNull();
    if(strRecordName.size() <= 25)
    {
        if(pansMain->getRecord(AnsRecordTypes::A_RECORD, strRecordName, record))
        {
           return true;
        }
    }
    else
    {
        if(pansMain->getRecord(AnsRecordTypes::PTR_RECORD, strRecordName, record))
        {
           return true;
        }
    }
    return false;
}

static CAmount CalcAnsFeeFromMonths(uint8_t months)
{
    return (months * 50) * COIN;
}

static void CreatePayment(const CTxDestination &address, CAmount nFeeRequired, CWalletTx& wtxNew, CReserveKey& reservekey, CAmount& nFeeRet)
{
    CAmount curBalance = pwalletMain->GetBalance();
    CAmount nValue = 1 * COIN;
    // Check amount
    if (nValue <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid amount");

    if (nValue > curBalance)
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds");

    // Parse ecc address
    CScript scriptPubKey = GetScriptForDestination(address);
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

static void CreateANStransaction(CServiceTransaction& stxnew, CWalletTx& wtxnew, std::string& strUsername, uint8_t nMonths, Opcode_ANS opcode)
{
    stxnew.nVersion = CServiceTransaction::CURRENT_VERSION;
    stxnew.nServiceId = 0; // 0 is for ANS because pure payment addresses use odd number tx versions
    stxnew.nTime = GetTime();
    stxnew.nOpCode = opcode;
    stxnew.nExpireTime = nMonths * (60*60*24*30); // months * 30 days
    stxnew.vdata = std::vector<unsigned char>(strUsername.begin(), strUsername.end()); // should just be the username
    // add service transaction hash to payment hash so it can be rehashed later
    wtxnew.tx->serviceReferenceHash = stxnew.GetHash();
}

/*************************************
 *
 * ANS Commands
 *
 */


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
            "  \"name, address\"  (string) a ecc address associated with the given account\n"
            "  ,...\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("getansrecord"," \"name\" \"A\"")
            + HelpExampleRpc("getansrecord"," \"EQT4WawJ6BN2JuaTfViuztHFeiqj2KCvTf\" \"PTR\"")
        );
    std::string strRecordName = params[0].get_str();
    AnsRecordTypes recordtype = AnsRecordTypes::UNKNOWN_RECORD;
    CAnsRecord record = CAnsRecord();
    UniValue ret(UniValue::VOBJ);
    if(params.size() == 2)
    {
        recordtype = resolveRecordType(params[1].get_str());
        pansMain->getRecord(recordtype, strRecordName, record);
    }
    else
    {
        getRecordUnknownType(strRecordName, record);
    }
    if(record == CAnsRecord())
    {
        ret.push_back(Pair("ERROR", "there is no record with that record name"));
        return ret;
    }
    ret.push_back(Pair("Key for this record" , strRecordName                    ));
    ret.push_back(Pair("Name"                , record.getName()                 ));
    ret.push_back(Pair("Address"             , record.getAddress()              ));
    ret.push_back(Pair("ExpireTime"          , record.getExpireTime()           ));
    ret.push_back(Pair("paymentHash"         , record.getPaymentHash().GetHex() ));
    ret.push_back(Pair("ServiceHash"         , record.getServiceHash().GetHex() ));
    return ret;
}

UniValue registerans(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 2)
    {
        throw std::runtime_error(
            "getansaddress \"eccaddress\" \"username\" \n"
            "\nAssign a username to an owned address.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"eccaddress\"  (string, required) The ecc address to have a username set to.\n"
            "2. \"username\"    (string, required) The username to be set.\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id and additional info.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"EQT4WawJ6BN2JuaTfViuztHFeiqj2KCvTf\" \"alice\"")
            + HelpExampleRpc("sendtoaddress", "\"EQT4WawJ6BN2JuaTfViuztHFeiqj2KCvTf\" \"bob\"")
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
    CAnsRecord record;
    if(pansMain->getRecord(recordtype, strUsername, record))
    {
        throw JSONRPCError(RPC_INVALID_PARAMS, "Username already exists for an address");
    }
    uint8_t nMonths = 1;

    CWalletTx wtx;
    CServiceTransaction stx;
    // TODO : have user enter coin amount to pay for ans address, right now it is set to the default 1 month and cant be changed
    CAmount nAmount = CalcAnsFeeFromMonths(nMonths);
    CAmount nFeeRet = 0;
    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CreatePayment(address.Get(), nAmount, wtx, reservekey, nFeeRet);
    CreateANStransaction(stx, wtx, strUsername, nFeeRet, Opcode_ANS::OP_REGISTER);
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


UniValue renewans(const UniValue& params, bool fHelp)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 2)
    {
        throw std::runtime_error(
            "renewans \"eccaddress\" \"username\" \n"
            "\nAdd more time to an ans username.\n"
            + HelpRequiringPassphrase() +
            "\nArguments:\n"
            "1. \"eccaddress\"  (string, required) The ecc address the username is set to.\n"
            "2. \"username\"    (string, required) The username that is set.\n"
            "\nResult:\n"
            "\"transactionid\"  (string) The transaction id and additional info.\n"
            "\nExamples:\n"
            + HelpExampleCli("sendtoaddress", "\"EQT4WawJ6BN2JuaTfViuztHFeiqj2KCvTf\" \"alice\"")
            + HelpExampleRpc("sendtoaddress", "\"EQT4WawJ6BN2JuaTfViuztHFeiqj2KCvTf\" \"bob\"")
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
    CAnsRecord record;
    if(!pansMain->getRecord(A_RECORD, strUsername, record))
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: There is no record for that username");
    }
    if(address.ToString() != record.getAddress())
    {
        throw JSONRPCError(RPC_WALLET_ERROR, "Error: The entered address does not match the address for that record");
    }
    uint8_t nMonths = 1;

    CWalletTx wtx;
    CServiceTransaction stx;
    // TODO : have user enter coin amount to pay for ans address, right now it is set to the default 1 month and cant be changed
    CAmount nAmount = CalcAnsFeeFromMonths(nMonths);
    CAmount nFeeRet = 0;
    // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CreatePayment(address.Get(), nAmount, wtx, reservekey, nFeeRet);
    CreateANStransaction(stx, wtx, strUsername, nMonths, Opcode_ANS::OP_RENEW);
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
